//go:build windows

package smbhost

// 免密（来宾/匿名）共享。
//
// 为什么不是"改一行共享权限"就行：SMB 的登录先于共享权限。
// 客户端不带凭据来连，Windows 要先决定"这次网络登录映射成谁"，
// 这个决定由下面三个开关共同控制：
//
//	1) 内置 Guest 账户是否启用      —— 没有主体可映射，后面都白搭
//	2) HKLM\...\Control\Lsa\ForceGuest —— 1 = 来宾模式（所有本地账户的网络登录
//	   一律映射为 Guest），0 = 经典模式（必须用真实账户口令）
//	3) NTFS 上 Everyone 是否有读权限 —— 共享权限放行了、文件系统拦下也一样拒
//
// ForceGuest 是整机全局的，所以"免密"和"本机账户登录"在同一台机器上无法并存：
// 打开免密后，任何用户名/口令组合都会被接受并映射为 Guest。
// 这一点在诊断里必须说清楚，不能让用户以为"两种方式都开着"。

import (
	"fmt"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const (
	lsaKey      = `SYSTEM\CurrentControlSet\Control\Lsa`
	workstation = `SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`

	ufAccountDisable = 0x0002
	errUserNotFound  = 2222
	everyoneSID      = "*S-1-1-0"
)

var (
	netapi32             = syscall.NewLazyDLL("netapi32.dll")
	procNetUserGetInfo   = netapi32.NewProc("NetUserGetInfo")
	procNetApiBufferFree = netapi32.NewProc("NetApiBufferFree")
)

// State 是免密相关开关的现状，供诊断与状态展示使用。
type State struct {
	GuestExists bool `json:"guest_exists"`
	GuestActive bool `json:"guest_active"`
	// ForceGuest: 1 来宾模式，0 经典模式，-1 键不存在（等价于 0）
	ForceGuest int `json:"force_guest"`
	// ClientGuest 本机作为客户端访问别人的免密共享时是否放行（AllowInsecureGuestAuth）
	ClientGuest bool `json:"client_guest"`
	// GuestDeniedNetwork Guest 是否被「拒绝从网络访问这台计算机」挡住（客户端版默认挡住）
	GuestDeniedNetwork bool `json:"guest_denied_network"`
	// NetLogonKnown 上面那项是否真的读到了。非管理员读 LSA 会被拒，
	// 这时不能报"OK"，否则诊断会假绿。
	NetLogonKnown bool `json:"net_logon_known"`
	// BlankPwdNetwork 空密码账户是否允许网络登录（LimitBlankPasswordUse=0 表示允许）
	BlankPwdNetwork bool `json:"blank_pwd_network"`
}

// Backup 记录改动前的样子，退出时按它还原。
// 不做"一律改成 0"，是因为用户机器上原本可能就是 1。
type Backup struct {
	GuestActive bool `json:"guest_active"`
	ForceGuest  int  `json:"force_guest"`
	// EveryoneHadAccess 改动前 Everyone 是否已有访问权；没有才在还原时撤销
	EveryoneHadAccess bool `json:"everyone_had_access"`
	// GuestDenyNetwork 改动前 Guest 是否在「拒绝从网络访问」名单里
	GuestDenyNetwork bool `json:"guest_deny_network"`
	// LimitBlankPassword 改动前的 LimitBlankPasswordUse；-1 表示键不存在
	LimitBlankPassword int `json:"limit_blank_password"`
	// Engine 记录这份备份是哪条路线写的：go = 自研服务端（没有系统改动），
	// 空 = 老版本的 native 备份（改过 Guest/ForceGuest，必须还原）。
	// 有了它，升级后残留的旧备份也能被正确识别并还原。
	Engine string `json:"engine,omitempty"`
}

// ReadState 读现状。不需要管理员权限。
// 自研服务端（engine: go）下"免密"是进程内的认证策略，与 Guest 账户、
// ForceGuest、LSA 权限统统无关，所以这里如实报服务端自己的状态，
// 不去读那些和当前路线无关的注册表项。
func ReadState() State {
	if !systemGuestActive() {
		client := false
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, workstation, registry.QUERY_VALUE); err == nil {
			if v, _, err := k.GetIntegerValue("AllowInsecureGuestAuth"); err == nil {
				client = v == 1
			}
			k.Close()
		}
		mu.Lock()
		active := running != nil
		mu.Unlock()
		return State{
			GuestExists:     true,
			GuestActive:     active,
			ForceGuest:      1,
			ClientGuest:     client,
			NetLogonKnown:   true,
			BlankPwdNetwork: true,
		}
	}
	st := State{ForceGuest: -1}
	if flags, err := guestFlags(); err == nil {
		st.GuestExists = true
		st.GuestActive = flags&ufAccountDisable == 0
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, lsaKey, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("ForceGuest"); err == nil {
			st.ForceGuest = int(v)
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, workstation, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("AllowInsecureGuestAuth"); err == nil {
			st.ClientGuest = v == 1
		}
		k.Close()
	}
	st.BlankPwdNetwork = readDword(lsaKey, "LimitBlankPasswordUse", 1) == 0
	if denied, err := GuestDeniedNetworkLogon(); err == nil {
		st.NetLogonKnown = true
		st.GuestDeniedNetwork = denied
	}
	return st
}

// readDword 读一个 DWORD 值，不存在或读不到时返回 def。
func readDword(key, name string, def int) int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return def
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return def
	}
	return int(v)
}

// guestFlags 用 NetUserGetInfo 读账户标志位。
// 不用 `net user Guest` 解析输出，是因为它是本地化文本（中文系统上是"账户启用"），
// 换个语言就解析错了。
func guestFlags() (uint32, error) {
	var buf unsafe.Pointer
	name, _ := syscall.UTF16PtrFromString("Guest")
	r, _, _ := procNetUserGetInfo.Call(0,
		uintptr(unsafe.Pointer(name)), 1, uintptr(unsafe.Pointer(&buf)))
	if r != 0 {
		if uint32(r) == errUserNotFound {
			return 0, fmt.Errorf("系统里没有 Guest 账户")
		}
		return 0, fmt.Errorf("读取 Guest 账户失败，错误码 %d", r)
	}
	defer procNetApiBufferFree.Call(uintptr(buf))
	// USER_INFO_1.usri1_flags 在 x64 上的偏移：4 个指针/整型对齐后落在 40
	const flagsOffset = 40
	return *(*uint32)(unsafe.Add(buf, flagsOffset)), nil
}

// EnsureGuestLogon 幂等地保证「登录类型」那两道门是开的。
// 进程被强杀后重启时备份文件还在、不会重跑 Enable，
// 但 Guest 的网络登录权与空密码策略必须重新确认一遍，否则重启后又连不上。
func EnsureGuestLogon() error {
	if !systemGuestActive() {
		return nil // 免密在进程内完成，没有"网络登录权限"这回事
	}
	if _, err := AllowGuestNetworkLogon(); err != nil {
		return fmt.Errorf("解除 Guest 网络登录限制失败: %w", err)
	}
	if err := setDword(lsaKey, "LimitBlankPasswordUse", 0); err != nil {
		return fmt.Errorf("允许空密码账户从网络登录失败: %w", err)
	}
	return nil
}

// EnsureRootAccess 幂等地保证「当前共享根」上 Everyone 有权限。
//
// 这条以前藏在 Enable 里，只在第一次开免密时跑一次，于是留下一个坑：
// 免密已经开着的情况下更换共享目录，新根上谁也没给它授权，
// Guest 能登录成功（LastLogon 会更新）、列目录却全是 NT_STATUS_ACCESS_DENIED，
// 用户看到的就是"用 guest 登录不能访问"。
// 换根、重启复用备份、改可写开关都必须重新确认这一条。
func EnsureRootAccess(root string, writable bool) error {
	if !systemGuestActive() {
		return nil // 自研服务端自己管权限，不看 NTFS
	}
	if root == "" {
		return nil
	}
	// 不做"已经有 Everyone 就跳过"的短路。给目录加可继承 ACE 时，
	// Windows 要把它逐个传播到子对象，几十万文件的目录能跑几分钟；
	// 中途进程被杀，根目录的 ACE 已经写上了、子对象却没收全。
	// 这时靠 everyoneHasAccess 判断会得出"已经好了"，实际一半文件仍拒绝访问。
	// SET_ACCESS 本身是幂等的（同 SID 同权限只会替换那一条），重复跑只会
	// 把没传播完的部分补齐，所以这里每次都走一遍。
	return grantEveryone(root, writable)
}

// RevokeRootAccess 撤销某个目录上的 Everyone 授权（换根 / 关闭免密时清理）。
// 只看引擎会误判：调用它的时候（关闭流程末尾）引擎往往已经切走了，
// 但权限还留在那儿，所以这里不校验 systemGuestActive，只认目录本身。
func RevokeRootAccess(root string) error {
	if root == "" {
		return nil
	}
	return revokeEveryoneFast(root)
}

// Enable 打开免密：启用 Guest、切到来宾模式、给 Everyone 读权限。
// 返回改动前的状态，供 Restore 使用。
func Enable(root string, writable bool) (Backup, error) {
	// 自研服务端：免密只是"认证不过就按 Guest 放行 + 按需要放开写"，
	// 一个系统开关都不用动，也就不需要备份任何整机状态。
	if !systemGuestActive() {
		if err := goEnableGuest(root, writable); err != nil {
			return Backup{}, err
		}
		return Backup{GuestActive: true, ForceGuest: 1, Engine: "go"}, nil
	}
	before := ReadState()
	bk := Backup{
		GuestActive: before.GuestActive,
		ForceGuest:  before.ForceGuest,
	}
	if !before.GuestExists {
		return bk, fmt.Errorf("系统里没有 Guest 账户，无法开启免密（部分精简系统会移除它）")
	}

	if !before.GuestActive {
		if out, err := run("net", "user", "Guest", "/active:yes"); err != nil {
			return bk, fmt.Errorf("启用 Guest 账户失败（需要管理员权限）: %s", tail(out, err))
		}
	}
	if err := setForceGuest(1); err != nil {
		rollbackAccount(before)
		return bk, fmt.Errorf("切换来宾模式失败（需要管理员权限）: %w", err)
	}

	hadAccess, err := everyoneHasAccess(root)
	if err != nil {
		rollbackPolicy(before)
		return bk, err
	}
	bk.EveryoneHadAccess = hadAccess
	// 这里不做同步授权。给目录加可继承 ACE 会让 Windows 把这条 ACE
	// 传播到整棵子树，五十万文件的目录要跑好几分钟，开关键就卡住了。
	// 授权由 app.ensureGuestACL 在后台完成；这里只记录"改动前有没有"，
	// 供还原时判断该不该撤销。

	// 第 4 道门：登录类型。
	// 客户端版默认把 Guest 放进「拒绝从网络访问这台计算机」，
	// 不摘掉它，前面三道门全开也连不上（NT_STATUS_LOGON_TYPE_NOT_GRANTED）。
	denied, err := AllowGuestNetworkLogon()
	bk.GuestDenyNetwork = denied
	if err != nil {
		RestoreGuestNetworkLogon(denied)
		rollbackPolicy(before)
		return bk, fmt.Errorf("解除 Guest 网络登录限制失败（需要管理员权限）: %w", err)
	}

	// 第 5 道门：空密码。
	// Guest 账户没有密码，而「使用空密码的本地账户只允许进行控制台登录」默认开启，
	// 会把网络登录直接挡掉。不改这一条，客户端会收到 STATUS_ACCOUNT_RESTRICTION。
	bk.LimitBlankPassword = readDword(lsaKey, "LimitBlankPasswordUse", -1)
	if err := setDword(lsaKey, "LimitBlankPasswordUse", 0); err != nil {
		RestoreGuestNetworkLogon(denied)
		rollbackPolicy(before)
		return bk, fmt.Errorf("允许空密码账户从网络登录失败（需要管理员权限）: %w", err)
	}
	return bk, nil
}

// rollbackPolicy 撤掉本次已经动过的账户与策略。
// 半开状态最坑：Guest 启用了但没进来宾模式，用户会以为"已经免密了"却还是被要口令。
func rollbackPolicy(before State) {
	if before.ForceGuest < 0 {
		deleteForceGuest()
	} else {
		setForceGuest(before.ForceGuest)
	}
	rollbackAccount(before)
}

func rollbackAccount(before State) {
	if !before.GuestActive {
		run("net", "user", "Guest", "/active:no")
	}
}

// Restore 把免密相关的系统状态还原到备份时的样子。
// 共享本身由 RemoveShare 负责，这里只管账户、策略与 NTFS 授权。
func Restore(root string, bk Backup) error {
	// 按备份自带的来源判断，而不是按当前引擎：升级后可能留着上一版
	// native 写的备份（里面改过 Guest/ForceGuest），那些必须照旧还原。
	if bk.Engine == "go" {
		return goRestoreGuest(root)
	}
	var errs []string
	if bk.ForceGuest < 0 {
		if err := deleteForceGuest(); err != nil {
			errs = append(errs, "恢复来宾模式策略: "+err.Error())
		}
	} else if err := setForceGuest(bk.ForceGuest); err != nil {
		errs = append(errs, "恢复来宾模式策略: "+err.Error())
	}
	if !bk.GuestActive {
		if out, err := run("net", "user", "Guest", "/active:no"); err != nil {
			errs = append(errs, "停用 Guest 账户: "+tail(out, err))
		}
	}
	// 注意：这里不撤销 Everyone 授权。撤销同样要把改动传播到整棵子树，
	// 大目录上要跑几分钟，放在这里会把「关闭开关 / 退出程序」一并拖住。
	// 由 app.restoreGuest 在后台调 RevokeRootAccess 完成，
	// 判断依据是 bk.EveryoneHadAccess。
	// 还原登录类型限制：把 Guest 放回「拒绝从网络访问」。
	if err := RestoreGuestNetworkLogon(bk.GuestDenyNetwork); err != nil {
		errs = append(errs, "恢复 Guest 网络登录限制: "+err.Error())
	}
	// 还原空密码策略：原本没有这个键就删掉，别凭空造一个 0 出来。
	if bk.LimitBlankPassword >= 0 {
		if err := setDword(lsaKey, "LimitBlankPasswordUse", bk.LimitBlankPassword); err != nil {
			errs = append(errs, "恢复空密码策略: "+err.Error())
		}
	} else {
		if err := deleteValue(lsaKey, "LimitBlankPasswordUse"); err != nil {
			errs = append(errs, "恢复空密码策略: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "；"))
	}
	return nil
}

// SetClientGuest 控制本机作为"客户端"访问免密共享时是否放行。
// 与服务器侧无关：即使服务端配置正确，Windows 10 1709+ 的客户端也会
// 默认拒绝"未经身份验证的来宾访问"，报"组织的安全策略阻止..."。
func SetClientGuest(enable bool) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, workstation, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("写注册表失败（需要管理员权限）: %w", err)
	}
	defer k.Close()
	v := uint32(0)
	if enable {
		v = 1
	}
	return k.SetDWordValue("AllowInsecureGuestAuth", v)
}

func setForceGuest(v int) error {
	return setDword(lsaKey, "ForceGuest", v)
}

// setDword 写一个 DWORD 到 HKLM。
func setDword(key, name string, v int) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, uint32(v))
}

func deleteValue(key, name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

func deleteForceGuest() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, lsaKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue("ForceGuest"); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

// everyoneHasAccess 判断 Everyone 是否已经能读这个目录。
// icacls 输出里的账户名在本机语言下可能是 "Everyone" 或 SID，两种都认。
func everyoneHasAccess(root string) (bool, error) {
	out, err := run("icacls", root)
	if err != nil {
		return false, fmt.Errorf("读取目录权限失败: %v %s", err, strings.TrimSpace(out))
	}
	return strings.Contains(out, "Everyone") || strings.Contains(strings.ToUpper(out), "S-1-1-0"), nil
}

func grantEveryone(root string, writable bool) error {
	// 走 Win32 安全 API 而不是 icacls：见 acl_windows.go 里的说明，
	// icacls 会就地把继承 ACE 传播到整棵子树，几十万文件能卡上几分钟。
	if err := grantEveryoneFast(root, writable); err != nil {
		return fmt.Errorf("授予 Everyone 权限失败: %w", err)
	}
	return nil
}

// tail 把子进程输出拼进错误信息。
// 中文 Windows 上 net/icacls 输出的是 GBK，直接塞进界面就是一串乱码，
// 所以不是合法 UTF-8 时只保留退出状态，让我们自己的中文说明来承担信息量。
func tail(out string, err error) string {
	s := strings.TrimSpace(out)
	if s == "" || !utf8.ValidString(s) {
		return fmt.Sprintf("%v", err)
	}
	return fmt.Sprintf("%v %s", err, s)
}
