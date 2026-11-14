//go:build windows

package smbhost

// 账号权限（LSA account rights）的读写。
//
// 为什么必须有这一层：
// Windows 客户端版（专业版/家庭版）的默认安全策略里，
// 「拒绝从网络访问这台计算机」这一项包含 Guest。只要这条还在，
// 来宾账户不管共享权限、NTFS 权限怎么配，都连不上——
// 客户端看到的是 NT_STATUS_LOGON_TYPE_NOT_GRANTED：
// 不是"权限不够"，而是"这种登录方式压根不给你"。
//
// 这条策略既不在共享权限里，也不在 NTFS 里，所以按常规思路配一整天也不会好。
// 另外 Guest 账户没有密码，而「账户: 使用空密码的本地账户只允许进行控制台登录」
// 默认开启，也会把网络登录挡掉（表现为 STATUS_ACCOUNT_RESTRICTION）。
// 两者都必须在开启免密时一起处理，并在关闭时还原。

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	// POLICY_ALL_ACCESS：改账号权限需要足够大的句柄
	policyAllAccess = 0x00F0FFF
	// POLICY_LOOKUP_NAMES：某些系统上 ALL_ACCESS 会被拒，退一步用这个
	policyLookupNames = 0x00000800

	seDenyNetworkLogonRight = "SeDenyNetworkLogonRight"

	statusSuccess            = 0
	statusObjectNameNotFound = 0xC0000034 // 该账户没有任何账号权限
)

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *lsaUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

var (
	advapi32Lsa = syscall.NewLazyDLL("advapi32.dll")

	procLsaOpenPolicy          = advapi32Lsa.NewProc("LsaOpenPolicy")
	procLsaClose               = advapi32Lsa.NewProc("LsaClose")
	procLsaFreeMemory          = advapi32Lsa.NewProc("LsaFreeMemory")
	procLsaNtStatusToWinError  = advapi32Lsa.NewProc("LsaNtStatusToWinError")
	procLsaEnumerateAcctRights = advapi32Lsa.NewProc("LsaEnumerateAccountRights")
	procLsaRemoveAcctRights    = advapi32Lsa.NewProc("LsaRemoveAccountRights")
	procLsaAddAcctRights       = advapi32Lsa.NewProc("LsaAddAccountRights")
	procLookupAccountNameW     = advapi32Lsa.NewProc("LookupAccountNameW")
)

func ntErr(status uintptr) error {
	w, _, _ := procLsaNtStatusToWinError.Call(status)
	return fmt.Errorf("NTSTATUS 0x%08x（Win32 %d）", uint32(status), uint32(w))
}

func lsaOpen() (uintptr, error) {
	var attrs lsaObjectAttributes
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	for _, access := range []uint32{policyAllAccess, policyLookupNames} {
		var h uintptr
		r, _, _ := procLsaOpenPolicy.Call(0,
			uintptr(unsafe.Pointer(&attrs)), uintptr(access), uintptr(unsafe.Pointer(&h)))
		if uint32(r) == statusSuccess {
			return h, nil
		}
	}
	return 0, fmt.Errorf("打开本地安全策略失败，需要管理员权限")
}

// withAccountSID 取账户 SID 并保证它在回调期间不被 GC 移动。
func withAccountSID(account string, fn func(sid unsafe.Pointer) error) error {
	namePtr, err := syscall.UTF16PtrFromString(account)
	if err != nil {
		return err
	}
	var cbSid, cchDomain uint32
	procLookupAccountNameW.Call(0, uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(unsafe.Pointer(&cbSid)), 0, uintptr(unsafe.Pointer(&cchDomain)), 0)
	if cbSid == 0 {
		return fmt.Errorf("系统里找不到账户 %s", account)
	}
	sid := make([]byte, cbSid)
	domain := make([]uint16, cchDomain+1)
	var use uint32
	r, _, e := procLookupAccountNameW.Call(0, uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&sid[0])), uintptr(unsafe.Pointer(&cbSid)),
		uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&cchDomain)),
		uintptr(unsafe.Pointer(&use)))
	if r == 0 {
		return fmt.Errorf("查询账户 %s 的 SID 失败: %v", account, e)
	}
	err = fn(unsafe.Pointer(&sid[0]))
	runtime.KeepAlive(sid)
	return err
}

func lsaStr(s *lsaUnicodeString) string {
	if s == nil || s.Buffer == nil || s.Length == 0 {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice(s.Buffer, int(s.Length)/2))
}

func enumerateRights(policy uintptr, sid unsafe.Pointer) ([]string, error) {
	var buf *lsaUnicodeString
	var count uint32
	r, _, _ := procLsaEnumerateAcctRights.Call(policy, uintptr(sid),
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&count)))
	if uint32(r) == statusObjectNameNotFound {
		return nil, nil
	}
	if uint32(r) != statusSuccess {
		return nil, fmt.Errorf("枚举账号权限失败: %w", ntErr(r))
	}
	defer procLsaFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	if count == 0 || buf == nil {
		return nil, nil
	}
	arr := unsafe.Slice(buf, count)
	out := make([]string, 0, count)
	for i := range arr {
		out = append(out, lsaStr(&arr[i]))
	}
	return out, nil
}

func toLsaArray(rights []string) ([]lsaUnicodeString, [][]uint16) {
	strs := make([]lsaUnicodeString, 0, len(rights))
	bufs := make([][]uint16, 0, len(rights))
	for _, r := range rights {
		p, err := syscall.UTF16FromString(r)
		if err != nil {
			continue
		}
		bufs = append(bufs, p)
		strs = append(strs, lsaUnicodeString{
			Length:        uint16((len(p) - 1) * 2),
			MaximumLength: uint16(len(p) * 2),
			Buffer:        &bufs[len(bufs)-1][0],
		})
	}
	return strs, bufs
}

func removeRights(policy uintptr, sid unsafe.Pointer, rights []string) error {
	strs, bufs := toLsaArray(rights)
	if len(strs) == 0 {
		return nil
	}
	r, _, _ := procLsaRemoveAcctRights.Call(policy, uintptr(sid), 0,
		uintptr(unsafe.Pointer(&strs[0])), uintptr(len(strs)))
	runtime.KeepAlive(bufs)
	runtime.KeepAlive(strs)
	if uint32(r) != statusSuccess {
		return fmt.Errorf("移除账号权限失败: %w", ntErr(r))
	}
	return nil
}

// addRights 注意：LsaAddAccountRights 的原型比 LsaRemoveAccountRights 少一个
// AllRights 参数（BOOL, PLSA_UNICODE_STRING, ULONG）。多传一个参数会让后面的
// 参数整体错位，LSA 返回 0xC003000C（RPC 存根数据错误），而且不报"参数个数不对"。
func addRights(policy uintptr, sid unsafe.Pointer, rights []string) error {
	strs, bufs := toLsaArray(rights)
	if len(strs) == 0 {
		return nil
	}
	r, _, _ := procLsaAddAcctRights.Call(policy, uintptr(sid),
		uintptr(unsafe.Pointer(&strs[0])), uintptr(len(strs)))
	runtime.KeepAlive(bufs)
	runtime.KeepAlive(strs)
	if uint32(r) != statusSuccess {
		return fmt.Errorf("添加账号权限失败: %w", ntErr(r))
	}
	return nil
}

func hasRight(rights []string, want string) bool {
	for _, r := range rights {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// GuestDeniedNetworkLogon 报告 Guest 是否在「拒绝从网络访问这台计算机」名单里。
func GuestDeniedNetworkLogon() (bool, error) {
	policy, err := lsaOpen()
	if err != nil {
		return false, err
	}
	defer procLsaClose.Call(policy)
	var denied bool
	err = withAccountSID("Guest", func(sid unsafe.Pointer) error {
		rights, err := enumerateRights(policy, sid)
		if err != nil {
			return err
		}
		denied = hasRight(rights, seDenyNetworkLogonRight)
		return nil
	})
	return denied, err
}

// AllowGuestNetworkLogon 把 Guest 从「拒绝从网络访问」里摘掉。
// 返回改动前的状态：true 表示原本在名单里，关闭免密时要加回去。
func AllowGuestNetworkLogon() (bool, error) {
	policy, err := lsaOpen()
	if err != nil {
		return false, err
	}
	defer procLsaClose.Call(policy)
	var denied bool
	err = withAccountSID("Guest", func(sid unsafe.Pointer) error {
		rights, err := enumerateRights(policy, sid)
		if err != nil {
			return err
		}
		denied = hasRight(rights, seDenyNetworkLogonRight)
		if !denied {
			return nil
		}
		if err := removeRights(policy, sid, []string{seDenyNetworkLogonRight}); err != nil {
			return err
		}
		// 复核：LSA 的调用参数错位时不会报错，只会"看起来成功"，
		// 所以改完必须再读一次确认真的是想要的状态。
		after, err := enumerateRights(policy, sid)
		if err != nil {
			return err
		}
		if hasRight(after, seDenyNetworkLogonRight) {
			return fmt.Errorf("已请求移除，但 Guest 仍在「拒绝从网络访问」名单里")
		}
		return nil
	})
	return denied, err
}

// RestoreGuestNetworkLogon 按备份把「拒绝从网络访问」加回 Guest。
func RestoreGuestNetworkLogon(denied bool) error {
	if !denied {
		return nil
	}
	policy, err := lsaOpen()
	if err != nil {
		return err
	}
	defer procLsaClose.Call(policy)
	return withAccountSID("Guest", func(sid unsafe.Pointer) error {
		rights, err := enumerateRights(policy, sid)
		if err != nil {
			return err
		}
		if hasRight(rights, seDenyNetworkLogonRight) {
			return nil
		}
		if err := addRights(policy, sid, []string{seDenyNetworkLogonRight}); err != nil {
			return err
		}
		after, err := enumerateRights(policy, sid)
		if err != nil {
			return err
		}
		if !hasRight(after, seDenyNetworkLogonRight) {
			return fmt.Errorf("已请求恢复，但 Guest 仍未回到「拒绝从网络访问」名单")
		}
		return nil
	})
}
