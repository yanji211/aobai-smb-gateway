//go:build windows

package main

// Windows 下的 smb check：必须逐项说清楚六道门，因为哪一道没到位，
// 客户端看到的都是同一句"打不开共享"。

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"fsgw/internal/config"
	"fsgw/internal/smbhost"
)

// pick 让自检输出里"该项预期的样子"和"当前的样子"各占一半。
func pick(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func smbClientGuest(enable bool) int {
	if err := smbhost.SetClientGuest(enable); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if enable {
		fmt.Println("已允许本机访问免密（来宾）共享：AllowInsecureGuestAuth=1")
	} else {
		fmt.Println("已恢复默认：本机不再接受未经身份验证的来宾共享")
	}
	return 0
}

func smbReport(cfg *config.Config) int {
	// 引擎不同，要检查的"门"完全不同：
	//   go      → 445 是不是我们自己在听、账号表里有没有人、共享根在不在；
	//   native  → Guest/ForceGuest/LSA 那一整套整机开关（下面这段）。
	if smbhost.Engine() != "native" {
		return smbGoReport(cfg)
	}
	st := smbhost.ReadState()
	mark := func(ok bool) string {
		if ok {
			return "[ OK ]"
		}
		return "[ 缺 ]"
	}
	fmt.Println("SMB 免密登录检查")
	fmt.Printf("  %s Guest 账户      %s\n", mark(st.GuestExists && st.GuestActive), describeGuest(st))
	fmt.Printf("  %s 来宾模式        %s\n", mark(st.ForceGuest == 1), describeForceGuest(st.ForceGuest))
	fmt.Printf("  %s 共享是否存在    %s\n", mark(smbhost.Exists(cfg.Shares[0].Name)), `\\`+cfg.Shares[0].Name)
	fmt.Printf("  %s 网络登录权限    %s\n", mark(st.NetLogonKnown && !st.GuestDeniedNetwork), describeDenyNetwork(st))
	fmt.Printf("  %s 空密码网络登录  %s\n", mark(st.BlankPwdNetwork), describeBlankPwd(st.BlankPwdNetwork))
	fmt.Printf("  %s 本机作为客户端  %s\n", mark(st.ClientGuest), describeClientGuest(st.ClientGuest))
	fmt.Println()
	fmt.Printf("  配置: smb.auth=%s  guest_writable=%v\n", cfg.SMB.Auth, cfg.SMB.GuestWritable)
	if cfg.SMB.Auth == "guest" || cfg.SMB.Auth == "both" {
		fmt.Println("  说明: 免密模式是整机设置——开启期间本机所有账户的网络登录都会映射为 Guest，")
		fmt.Println("        网关关闭时会自动还原。需要管理员权限运行 fsgw run 才会生效。")
	} else {
		fmt.Println("  说明: 当前是账户口令模式（smb.auth=account），访问时需输入本机用户名和密码。")
	}
	return 0
}

// smbGoReport 自研服务端（engine: go / auto）的自检。
// 这里没有 Guest 账户、ForceGuest、LSA 权限那套东西要查——认证在进程内做，
// 真正会挡住 Win11 的只有三件事：445 有没有在听、账号表配没配、共享根通不通。
func smbGoReport(cfg *config.Config) int {
	mark := func(ok bool) string {
		if ok {
			return "[ OK ]"
		}
		return "[ 缺 ]"
	}
	name := cfg.Shares[0].Name

	// 445 只在回环能看到不算数：绑的是 0.0.0.0，这里就看本机能不能连上。
	// 但"能连上"不等于"是我们在提供服务"——系统自带的 LanmanServer 也听 445，
	// 所以还要用 smbhost.Exists 确认占用者是谁，否则自检会假绿。
	portOpen := false
	if c, err := net.DialTimeout("tcp", "127.0.0.1:445", 800*time.Millisecond); err == nil {
		c.Close()
		portOpen = true
	}
	ours := smbhost.Exists(name)
	// 共享根是否可读，直接决定客户端列目录会不会报错。
	rootOK := false
	if fi, err := os.Stat(cfg.Shares[0].Root); err == nil && fi.IsDir() {
		rootOK = true
	}
	// 账号表：有账号 = Win11 24H2 能走签名会话；纯空表 = 只靠来宾。
	hasAccounts := strings.TrimSpace(cfg.SMB.Account) != "" || strings.TrimSpace(cfg.SMB.NTHash) != "" ||
		strings.TrimSpace(cfg.SMB.Password) != ""
	if clients, err := config.LoadClients(cfg.Path); err == nil {
		for _, c := range clients {
			if strings.TrimSpace(c.Name) != "" && strings.TrimSpace(c.NTHash) != "" {
				hasAccounts = true
			}
		}
	}

	fmt.Println("SMB 自检（引擎：进程内 Go SMB2/3 服务端）")
	fmt.Printf("  %s 引擎            %s（与 Linux 同一套代码）\n", mark(true), smbhost.Engine())
	fmt.Printf("  %s 445 监听        %s\n", mark(ours), describePort445(portOpen, ours))
	fmt.Printf("  %s 共享是否存在    %s\n", mark(ours), `\\本机\`+name)
	fmt.Printf("  %s 共享根可读      %s\n", mark(rootOK), cfg.Shares[0].Root)
	fmt.Printf("  %s 账号口令        %s\n", mark(hasAccounts),
		pick(hasAccounts, "已配置（Win11 24H2 可正常签名登录）", "未配置：只能来宾登录，Win11 24H2 会被强制签名挡住"))
	fmt.Println()
	fmt.Printf("  配置: smb.engine=%s  smb.auth=%s  guest_writable=%v\n",
		pick(cfg.SMB.Engine == "", "auto（默认）", cfg.SMB.Engine), cfg.SMB.Auth, cfg.SMB.GuestWritable)
	fmt.Println("  说明: 自研服务端运行期间 445 由本进程持有，系统自带的 Server 服务会被临时改为手动并停止，")
	fmt.Println("        本机原有的 net share 共享在此期间不可用；关闭网关或切回 engine=native 时自动还原。")
	return 0
}

// describePort445 说清 445 现在到底是谁在听。
// 这里最容易骗人的一点：没启动网关时 445 也通（系统自带共享服务在听），
// 所以只报"通/不通"会把"网关没开"误判成"已经就绪"。
func describePort445(portOpen, ours bool) string {
	switch {
	case ours:
		return "自研服务端在对外提供"
	case portOpen:
		return "被系统 Server 服务占用，自研服务端未启动（开关不是 LAN/ALL，或未提权）"
	}
	return "无人监听（开关不是 LAN/ALL，或服务未启动）"
}

func describeGuest(st smbhost.State) string {
	switch {
	case !st.GuestExists:
		return "系统里没有该账户"
	case st.GuestActive:
		return "已启用"
	}
	return "未启用"
}

func describeForceGuest(v int) string {
	switch v {
	case 1:
		return "ForceGuest=1，客户端免密直接进"
	case -1:
		return "ForceGuest 未设置（等同经典模式，要口令）"
	}
	return fmt.Sprintf("ForceGuest=%d（经典模式，要口令）", v)
}

func describeClientGuest(ok bool) string {
	if ok {
		return "允许访问别人的免密共享"
	}
	return "默认拒绝来访者（AllowInsecureGuestAuth=0）"
}

// describeDenyNetwork 「拒绝从网络访问这台计算机」里有没有 Guest。
// 客户端版默认有，这是免密失败最常见的原因，而且报错看着像"权限不足"。
func describeDenyNetwork(st smbhost.State) string {
	switch {
	case !st.NetLogonKnown:
		return "读不到（非管理员无法读取 LSA 权限，请在提权窗口里运行）"
	case st.GuestDeniedNetwork:
		return "Guest 被「拒绝从网络访问」挡住（这是客户端版默认策略）"
	}
	return "Guest 可远程登录"
}

func describeBlankPwd(ok bool) string {
	if ok {
		return "允许空密码账户从网络登录"
	}
	return "禁止空密码账户网络登录（Guest 没有密码，会被挡）"
}
