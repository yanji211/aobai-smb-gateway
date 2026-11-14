//go:build linux

package main

// Linux 下的 smb check：SMB 服务端是进程内的纯 Go 实现，没有 samba 那套
// 配置文件与系统账户，所以检查项只有「445 通不通 / 匿名能不能列 / 共享根读不读得到」。
// 刻意不打印 ForceGuest 之类，免得照抄 Windows 的诊断反而误导。

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"fsgw/internal/config"
)

func smbClientGuest(enable bool) int {
	// Linux 客户端不存在 AllowInsecureGuestAuth 这类策略。
	fmt.Println("Linux 作为客户端不需要额外开关：")
	fmt.Println("  mount -t cifs //<主机>/<共享> /mnt/x -o username=Guest,password=")
	fmt.Println("  或 smbclient //<主机>/<共享> -N -m SMB3")
	return 0
}

func smbReport(cfg *config.Config) int {
	mark := func(ok bool) string {
		if ok {
			return "[ OK ]"
		}
		return "[ 缺 ]"
	}
	if len(cfg.Shares) == 0 {
		fmt.Println("配置里没有共享")
		return 1
	}
	share := cfg.Shares[0].Name
	root := cfg.Shares[0].Root

	portOpen := false
	if c, err := net.DialTimeout("tcp", "127.0.0.1:445", time.Second); err == nil {
		portOpen = true
		c.Close()
	}

	rootOK := true
	rootNote := root
	if fi, err := os.Stat(root); err != nil {
		rootOK, rootNote = false, err.Error()
	} else if !fi.IsDir() {
		rootOK, rootNote = false, "不是目录"
	} else {
		rootNote = fmt.Sprintf("%s（%d 项）", root, dirCount(root))
	}

	fmt.Println("SMB 共享检查（Linux / 纯 Go SMB2-3 服务端）")
	fmt.Printf("  %s 445 监听          %s\n", mark(portOpen), pick(portOpen, "Go 服务端在跑", "未监听（开关不是 LAN/ALL，或服务未启动）"))
	fmt.Printf("  %s 共享根            %s\n", mark(rootOK), rootNote)
	fmt.Printf("  %s 共享名            %s\n", mark(share != ""), "\\\\<本机>\\"+share)

	anon := -1 // -1 未测，0 失败，1 成功
	anonNote := "客户端没装 smbclient，跳过实测"
	if portOpen {
		if _, err := exec.LookPath("smbclient"); err == nil {
			// 直接连共享列目录，而不是 smbclient -L。
			// -L 走的是 IPC$ 上的 srvsvc 命名管道 RPC（NetShareEnum），
			// 纯 Go 服务端不实现 RPC，-L 只会回一个空列表——用它判定
			// "匿名能不能访问"会把正常服务误报成不可用。
			out, err := exec.Command("smbclient", "//127.0.0.1/"+share, "-N", "-m", "SMB3", "-c", "ls").CombinedOutput()
			text := string(out)
			switch {
			case err == nil && !strings.Contains(text, "NT_STATUS"):
				anon, anonNote = 1, fmt.Sprintf("匿名列举成功，%s 可读到 %d 项", share, countListed(text))
			case strings.Contains(text, "NT_STATUS_LOGON_FAILURE"), strings.Contains(text, "NT_STATUS_ACCESS_DENIED"):
				anon, anonNote = 0, "匿名被拒："+firstLine(text)
			case strings.Contains(text, "Connection refused"), strings.Contains(text, "NT_STATUS_CONNECTION"):
				anon, anonNote = 0, "连不上 445"
			default:
				anon, anonNote = 0, firstLine(text)
			}
		}
	}
	fmt.Printf("  %s 匿名可访问        %s\n", mark(anon != 0), anonNote)

	// Win11 24H2+ 只认"能签名的会话"，来宾会话没有密钥、签不了名，
	// 所以账号表里必须有能通过口令认证的客户端。这一项检查它。
	acct := cfg.SMB.Account
	clients, _ := config.LoadClients(cfg.Path)
	names := make([]string, 0, len(clients)+1)
	if acct != "" {
		names = append(names, acct)
	}
	for _, c := range clients {
		names = append(names, c.Name)
	}

	acctState := 1
	var acctNote string
	switch {
	case len(names) == 0:
		acctState = 0
		acctNote = "还没有任何客户端账号：Win11 24H2+ 会报「策略阻止未经验证的来宾访问」；" +
			"到控制台的「SMB 客户端」里添加，或在 config.yaml 里配 password / nt_hash"
	case cfg.SMB.Password != "":
		// 有明文就实测一次，这是唯一能证明"口令真的对"的办法。
		if _, err := exec.LookPath("smbclient"); err == nil {
			out, err := exec.Command("smbclient", "//127.0.0.1/"+share,
				"-U", acct+"%"+cfg.SMB.Password, "-m", "SMB3", "-c", "ls").CombinedOutput()
			text := string(out)
			if err == nil && !strings.Contains(text, "NT_STATUS") {
				acctNote = fmt.Sprintf("共 %d 个账号（%s）；%s 实测登录成功，可读到 %d 项",
					len(names), strings.Join(names, ","), acct, countListed(text))
			} else {
				acctState = 0
				acctNote = "账号 " + acct + " 登录被拒：" + firstLine(text)
			}
		} else {
			acctNote = fmt.Sprintf("共 %d 个账号（%s）；客户端没装 smbclient，跳过实测",
				len(names), strings.Join(names, ","))
		}
	default:
		// 只有哈希：本机没有明文，没法自己验，只能如实说明。
		acctNote = fmt.Sprintf("共 %d 个账号（%s），只存 NT 哈希（%s）；用对应口令在 Windows 上登录即可",
			len(names), strings.Join(names, ","), config.ClientsPath(cfg.Path))
	}
	fmt.Printf("  %s 账号登录          %s\n", mark(acctState != 0), acctNote)

	fmt.Println()
	fmt.Printf("  配置: smb.auth=%s  账号=%q  guest_writable=%v  shares[0].writable=%v\n",
		cfg.SMB.Auth, acct, cfg.SMB.GuestWritable, cfg.Shares[0].Writable)
	fmt.Println("  说明: SMB 服务端是进程内的 Go 实现，不依赖 samba，也不读写 /etc/samba。")
	fmt.Println("        免密策略：走完整 NTLM 握手，匿名访问按来宾放行（老客户端/电视照旧）。")
	fmt.Println("        配了账号则对该账号校验 NTLMv2 口令，会话带密钥参与签名——")
	fmt.Println("        Windows 11 24H2 起强制签名，没有这条就只能被它自己的策略挡住。")
	fmt.Println("        共享只读与否由 guest_writable 决定；关闭开关后 445 立即停止监听。")
	return 0
}

func dirCount(p string) int {
	entries, err := os.ReadDir(p)
	if err != nil {
		return 0
	}
	return len(entries)
}

// countListed 数一遍 smbclient ls 的输出里有多少条目。
// 每行形如 "  2020-05-22-23-img     D        0  Sat May 23 08:21:49 2020"，
// 属性列是单个 D / A，两边有空格；结尾那行 "xxxx blocks of size" 不含这些。
func countListed(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " D ") || strings.Contains(line, " A ") {
			n++
		}
	}
	return n
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func pick(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}
