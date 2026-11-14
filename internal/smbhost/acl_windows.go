//go:build windows

package smbhost

// 用 Win32 安全 API 直接改「目录本身的 DACL」，而不是调 icacls。
//
// 为什么要绕开 icacls：icacls /grant 带 (OI)(CI) 时会就地把继承 ACE
// 传播到整棵子树。共享根只要稍微大一点（几十万文件很常见），
// 这一步就要跑几分钟，前端表现为「点开关后界面长时间没反应」，
// 更糟的是进程被强杀时权限只改了一半。
//
// 实际情况是根本不需要传播：Windows 的访问检查会把父目录的
// 可继承 ACE 动态合并进子对象的有效权限，只要根目录的 DACL 里有
// 这一条就够。所以这里只读写根对象的安全描述符，毫秒级返回。

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	seFileObject            = 1   // SE_FILE_OBJECT
	daclSecurityInformation = 0x4 // DACL_SECURITY_INFORMATION
	containerInheritAce     = 0x2 // CONTAINER_INHERIT_ACE
	objectInheritAce        = 0x1 // OBJECT_INHERIT_ACE
	accessAllowedAceType    = 0
	setAccess               = 2 // SET_ACCESS
	revokeAccess            = 4 // REVOKE_ACCESS
	trusteeIsSid            = 0 // TRUSTEE_IS_SID
	trusteeIsWellKnownGroup = 5 // TRUSTEE_IS_WELL_KNOWN_GROUP
	fileGenericRead         = 0x120089
	fileGenericWrite        = 0x120116
	fileGenericExecute      = 0x1200A0
	fileDelete              = 0x00010000
	fileReadControl         = 0x00020000
	fileSynchronize         = 0x00100000
)

var (
	advapi32Acl              = syscall.NewLazyDLL("advapi32.dll")
	procGetNamedSecurityInfo = advapi32Acl.NewProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfo = advapi32Acl.NewProc("SetNamedSecurityInfoW")
	procSetEntriesInAcl      = advapi32Acl.NewProc("SetEntriesInAclW")
	kernel32Acl              = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree            = kernel32Acl.NewProc("LocalFree")
)

// trusteeW 对应 Win32 的 TRUSTEE_W。字段顺序与对齐必须和 C 一致：
// 64 位下三个 DWORD 之后有 4 字节填充，ptstrName 落在偏移 24。
type trusteeW struct {
	pMultipleTrustee         *uint16
	multipleTrusteeOperation uint32
	trusteeForm              uint32
	trusteeType              uint32
	ptstrName                uintptr
}

// explicitAccessW 对应 EXPLICIT_ACCESS_W。
type explicitAccessW struct {
	grfAccessPermissions uint32
	grfAccessMode        uint32
	grfInheritance       uint32
	_                    uint32 // 对齐填充
	trustee              trusteeW
}

// everyoneMask 把「读写」/「只读」翻译成具体访问位。
// 不用 GENERIC_READ 这类通用位，是因为通用位会写进 DACL 原样保存，
// 之后用 icacls 看会出现看不懂的 0x1f01ff 之类。
func everyoneMask(writable bool) uint32 {
	read := uint32(fileGenericRead | fileGenericExecute | fileReadControl | fileSynchronize)
	if !writable {
		return read
	}
	return read | fileGenericWrite | fileDelete
}

// setEveryoneACE 在 root 的 DACL 上添加或删除 Everyone 的可继承 ACE。
// mode 取 setAccess 或 revokeAccess；revoke 只删匹配 Everyone 的 ACE，
// 其它 ACE 原样保留。
func setEveryoneACE(root string, writable bool, mode uint32) error {
	if root == "" {
		return fmt.Errorf("共享根为空")
	}
	p, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return fmt.Errorf("路径无法转换: %w", err)
	}

	var oldSd unsafe.Pointer
	var oldDacl unsafe.Pointer
	ret, _, _ := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(p)), seFileObject, daclSecurityInformation,
		0, 0,
		uintptr(unsafe.Pointer(&oldDacl)),
		0,
		uintptr(unsafe.Pointer(&oldSd)),
	)
	if ret != 0 {
		return fmt.Errorf("读取目录安全描述符失败（错误码 %d）", ret)
	}
	defer procLocalFree.Call(uintptr(oldSd))

	sid, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return fmt.Errorf("构造 Everyone SID 失败: %w", err)
	}

	ea := explicitAccessW{
		grfAccessPermissions: everyoneMask(writable),
		grfAccessMode:        mode,
		grfInheritance:       containerInheritAce | objectInheritAce,
	}
	ea.trustee.trusteeForm = trusteeIsSid
	ea.trustee.trusteeType = trusteeIsWellKnownGroup
	ea.trustee.ptstrName = uintptr(unsafe.Pointer(sid))

	var newAcl unsafe.Pointer
	ret, _, _ = procSetEntriesInAcl.Call(
		1,
		uintptr(unsafe.Pointer(&ea)),
		uintptr(oldDacl),
		uintptr(unsafe.Pointer(&newAcl)),
	)
	if ret != 0 {
		return fmt.Errorf("构造新 ACL 失败（错误码 %d）", ret)
	}
	defer procLocalFree.Call(uintptr(newAcl))

	ret, _, _ = procSetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(p)), seFileObject, daclSecurityInformation,
		0, 0,
		uintptr(newAcl),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("写入目录权限失败（错误码 %d）", ret)
	}
	return nil
}

// grantEveryoneFast 幂等授予 Everyone 可继承权限。
func grantEveryoneFast(root string, writable bool) error {
	return setEveryoneACE(root, writable, setAccess)
}

// revokeEveryoneFast 撤销本程序加上的 Everyone ACE。
func revokeEveryoneFast(root string) error {
	return setEveryoneACE(root, true, revokeAccess)
}
