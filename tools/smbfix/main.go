//go:build windows

// 家庭共享盘一键修复（Win11 SMB 客户端）
//
// 背景：fsgw 这台 Linux 上的纯 Go SMB 服务端同时放行"账号"和"来宾"两种登录，
// 但 Win11 24H2 起客户端默认强制 SMB 签名，来宾会话没有会话密钥、签不了名，
// 于是只会报"你组织的安全策略阻止了未经身份验证的来宾访问"。
// 所以正确姿势不是放开来宾，而是让每台机器都用登记过的账号认证。
//
// 这个程序做四件事：修客户端策略 → 清掉坏的旧凭据/旧映射 → 用账号存凭据并映射盘 → 读写验收。
//
// 用法：
//
//	共享盘一键修复.exe                     正常双击（会弹 UAC 提权）
//	共享盘一键修复.exe -diag               只体检不修
//	共享盘一键修复.exe -ip 192.0.2.11 -share share -user admin -pass changeme -drive Z
//	共享盘一键修复.exe -noelevate          不提权（调试用，注册表那一步会跳过）
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	defIP    = "192.0.2.11"
	defShare = "share"
	defUser  = "admin"
	defPass  = "changeme"

	totalSteps = 9
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleCP    = kernel32.NewProc("SetConsoleCP")
	procSetConsoleOutCP = kernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleTitle = kernel32.NewProc("SetConsoleTitleW")
	shell32             = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW   = shell32.NewProc("ShellExecuteW")

	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	procRegCreateKeyExW  = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueExW   = advapi32.NewProc("RegSetValueExW")
	procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")

	logFile *os.File
	logPath string
)

// 注册表相关常量
const (
	hkeyLocalMachine = 0x80000002
	keyRead          = 0x20019
	keySetValue      = 0x0002
	keyWow64_64      = 0x0100
	regDword         = 4

	regPathLwParams = `SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`
	regPathLwPolicy = `SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation`
	regPathLsa      = `SYSTEM\CurrentControlSet\Control\Lsa`
)

func main() {
	initConsole()
	initLog()
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()

	ip := argVal("ip", defIP)
	share := argVal("share", defShare)
	user := argVal("user", defUser)
	pass := argVal("pass", defPass)
	drivePref := strings.ToUpper(argVal("drive", ""))
	diagOnly := hasFlag("diag")
	noElevate := hasFlag("noelevate")

	banner(ip, share, user, diagOnly)

	admin := isAdmin()
	if !admin && !noElevate {
		emit("  需要管理员权限来修客户端的 SMB 策略，正在申请提权（请在弹窗里点『是』）...")
		if err := elevate(); err != nil {
			emit("%s", "  [FAIL] 提权失败或被取消："+err.Error())
			emit("         请右键这个 exe → 以管理员身份运行。")
			pause()
			os.Exit(1)
		}
		os.Exit(0) // 提权后的新窗口接手，当前窗口可以关了
	}
	if !admin {
		warn("当前不是管理员权限，注册表类修复会跳过（只适合自检）")
	}
	if diagOnly {
		emit("  [体检模式] 只检查不修改")
	}

	// ---------- 1. 网络可达性 ----------
	step(1, "检查到 %s 的连通性", ip)
	if !tcpAlive(ip, 445, 4*time.Second) {
		bad("TCP 445 连不上，共享服务不可达")
		emitLocalNets(ip)
		emit("")
		emit("  常见原因：① 这台机器和服务器不在同一网段/同一 Wi-Fi；")
		emit("            ② 路由器开了 AP 隔离（无线客户端之间互访被禁）；")
		emit("            ③ 服务器上 fsgw 没在跑（在 110 上执行 systemctl status fsgw）。")
		finish(false)
		return
	}
	ok("445 端口可用（延迟 %s）", tcpRTT(ip, 445))
	if diagOnly {
		diagReport(ip, share, admin)
		emit("")
		emit("  ===== 体检结束（本次没有做任何修改）=====")
		pause()
		return
	}

	// ---------- 2. 网络位置 ----------
	step(2, "把当前网络位置设为『专用网络』")
	if cat := networkCategory(); cat == "Private" {
		ok("已经是专用网络，跳过")
	} else if !admin {
		warn("当前网络位置是 %s，需要管理员权限才能改", cat)
	} else {
		if code, out := run("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-NetConnectionProfile | Where-Object {$_.IPv4Connectivity -ne 'Disconnected'} | Set-NetConnectionProfile -NetworkCategory Private"); code == 0 {
			ok("已设为专用网络（资源管理器『网络』里能看到这台机器）")
		} else {
			warn("设置失败，不影响访问，可忽略（%s）", firstLine(out))
		}
	}

	// ---------- 3. SMB 客户端策略 ----------
	step(3, "修正 SMB 客户端策略")
	if !admin {
		warn("非管理员，跳过注册表修复")
	} else {
		// 允许来宾登录：给老设备/低版本系统留后路，Win11 本身走账号，不依赖它
		if v, found := regGetDword(regPathLwParams, "AllowInsecureGuestAuth"); found && v == 1 {
			ok("AllowInsecureGuestAuth 已经是 1")
		} else if err := regSetDword(regPathLwParams, "AllowInsecureGuestAuth", 1); err == nil {
			ok("AllowInsecureGuestAuth 已置 1（允许来宾兜底）")
		} else {
			bad("写入 AllowInsecureGuestAuth 失败：%v", err)
		}
		// 组策略层的同名键优先级更高，有就一起改
		if v, found := regGetDword(regPathLwPolicy, "AllowInsecureGuestAuth"); found && v != 1 {
			if err := regSetDword(regPathLwPolicy, "AllowInsecureGuestAuth", 1); err == nil {
				ok("组策略层 AllowInsecureGuestAuth 已置 1")
			}
		}
		// NTLMv2：服务端只存 NT 哈希，客户端必须用 NTLMv2 才能验过
		if v, found := regGetDword(regPathLsa, "LmCompatibilityLevel"); !found || v < 3 {
			if err := regSetDword(regPathLsa, "LmCompatibilityLevel", 3); err == nil {
				ok("LmCompatibilityLevel 已置 3（强制 NTLMv2）")
			}
		} else {
			ok("LmCompatibilityLevel = %d，无需调整", v)
		}
		// 出站 NTLM 被完全禁用的话，账号认证是不可能的，必须解掉
		if v, found := regGetDword(regPathLsa, "RestrictSendingNTLMTraffic"); found && v == 2 {
			if err := regSetDword(regPathLsa, "RestrictSendingNTLMTraffic", 0); err == nil {
				warn("检测到出站 NTLM 被封禁（=2），已放开为 0")
			}
		}
		if v, found := regGetDword(regPathLsa, "DisableDomainCreds"); found && v == 1 {
			warn("系统禁止为网络认证保存凭据（DisableDomainCreds=1），本工具已改为显式传账号，不受影响")
		}
	}

	// ---------- 4. 客户端服务 ----------
	step(4, "确认『Workstation』服务在运行")
	if serviceRunning("LanmanWorkstation") {
		ok("LanmanWorkstation 正在运行")
	} else if admin {
		run("sc", "start", "LanmanWorkstation")
		time.Sleep(500 * time.Millisecond)
		if serviceRunning("LanmanWorkstation") {
			ok("已启动 LanmanWorkstation")
		} else {
			bad("LanmanWorkstation 启动失败，SMB 客户端不可用")
		}
	} else {
		warn("非管理员，无法启动服务")
	}

	// ---------- 5. 清理旧连接与旧凭据 ----------
	step(5, "清理指向这台服务器的旧映射与旧凭据")
	removed := clearMappings(ip)
	if len(removed) == 0 {
		ok("没有残留映射")
	} else {
		ok("已断开 %d 处旧映射：%s", len(removed), strings.Join(removed, "、"))
	}
	// 旧凭据留着会顶掉新的，必须先删（-1219 多重连接冲突也多半是这个）
	for _, target := range []string{ip} {
		run("cmdkey", "/delete:"+target)
	}
	ok("已清除 %s 的历史凭据", ip)

	// ---------- 6. 写入账号凭据 ----------
	step(6, "登记账号凭据（%s）", user)
	if code, out := run("cmdkey", "/add:"+ip, "/user:"+user, "/pass:"+pass); code != 0 {
		bad("cmdkey 写入失败：%s", explain(code, out))
		finish(false)
		return
	}
	if !hasCredential(ip) {
		warn("凭据可能没写进去，稍后靠显式传参兜底")
	} else {
		ok("凭据已存入本机 Credential Manager（重启后仍然有效）")
	}

	// ---------- 7. 映射盘符 ----------
	step(7, "映射网络驱动器")
	drive, err := mapDrive(ip, share, user, pass, drivePref)
	if err != nil {
		bad("%s", err.Error())
		emit("")
		emit("  若提示『用户名或密码不正确』，说明服务器换了口令，请找管理员在 110 上执行：")
		emit("    fsgw smb nt-hash <新口令>   → 填入 /etc/fsgw/config.yaml 的 smb.nt_hash，再 systemctl restart fsgw")
		finish(false)
		return
	}
	ok("%s: → \\\\%s\\%s", drive, ip, share)

	// ---------- 8. 读写验收 ----------
	step(8, "验收：列目录 + 写一个测试文件")
	root := drive + ":\\"
	// 注意：这里不能用 os.ReadDir —— 它内部用"目录专用"方式打开句柄，
	// 而这个纯 Go SMB 服务端不支持 GetFileInformationByHandleEx(FileIdBothDirectoryInfo)，
	// 会回 STATUS_INVALID_PARAMETER，Windows 侧表现为 "The parameter is incorrect"。
	// 先 os.Open 再 Readdirnames 走的是另一条路径，实测正常。
	names, err := readDirNames(root)
	if err != nil {
		bad("列目录失败：%v", err)
		finish(false)
		return
	}
	preview := make([]string, 0, 6)
	for i, n := range names {
		if i >= 6 {
			break
		}
		preview = append(preview, n)
	}
	ok("目录共 %d 项：%s ...", len(names), strings.Join(preview, " / "))

	testName := ".fsgw_write_test_" + strconv.Itoa(os.Getpid()) + ".tmp"
	testPath := filepath.Join(root, testName)
	payload := "fsgw write test " + time.Now().Format("2006-01-02 15:04:05")
	if err := os.WriteFile(testPath, []byte(payload), 0o644); err != nil {
		warn("写入被拒（共享当前是只读）：%v", err)
		emit("             只读不影响使用；要允许往里存文件，需在 110 的 /etc/fsgw/config.yaml 把 writable 改 true。")
	} else {
		if b, rerr := os.ReadFile(testPath); rerr == nil && string(b) == payload {
			ok("写入并读回校验一致（可写）")
		} else {
			warn("能写但回读不一致：%v", rerr)
		}
		if derr := os.Remove(testPath); derr != nil {
			warn("测试文件删不掉：%v（请手工删 %s）", derr, testPath)
		}
	}

	// ---------- 9. 收尾 ----------
	step(9, "打开共享文件夹")
	if hasFlag("noopen") {
		ok("已跳过自动打开（-noopen）")
	} else {
		run("explorer.exe", root)
		ok("已在资源管理器打开 %s（若没弹出来，手动进这个路径即可）", root)
	}

	finish(true)
}

// ---------------------------------------------------------------- 步骤实现

// clearMappings 断开所有指向该服务器的连接，返回被清掉的对象
func clearMappings(ip string) []string {
	var removed []string
	code, out := run("net", "use")
	if code != 0 && out == "" {
		return removed
	}
	needle := `\\` + ip
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || !strings.Contains(line, needle) {
			continue
		}
		// 行形如：OK           Z:        \\192.0.2.11\share    Microsoft Windows Network
		// 第一个字段是状态词（本地化），不能当盘符，得往后找 "X:" 或 UNC。
		target := ""
		for _, f := range strings.Fields(line) {
			if len(f) == 2 && f[1] == ':' {
				c := f[0]
				if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
					target = strings.ToUpper(f)
					break
				}
			}
			if strings.HasPrefix(f, needle) {
				target = f
				break
			}
		}
		if target == "" {
			continue
		}
		if c, _ := run("net", "use", target, "/delete", "/y"); c == 0 {
			removed = append(removed, target)
		}
	}
	// IPC$ 之类的隐藏连接单独再扫一遍
	if c, _ := run("net", "use", `\\`+ip+`\IPC$`, "/delete", "/y"); c == 0 {
		removed = append(removed, "IPC$")
	}
	return removed
}

// mapDrive 依次尝试盘符，成功后返回盘符字母
func mapDrive(ip, share, user, pass, pref string) (string, error) {
	unc := `\\` + ip + `\` + share
	// 优先用指定盘符，被占用就顺延；没指定就从 Z 往下找空位
	var candidates []string
	seen := map[string]bool{}
	if pref != "" {
		candidates = append(candidates, pref)
		seen[pref] = true
	}
	for c := 'Z'; c >= 'K'; c-- {
		s := string(c)
		if !seen[s] {
			candidates = append(candidates, s)
			seen[s] = true
		}
	}

	var lastCode int
	var lastOut string
	skipped := 0
	for _, letter := range candidates {
		if letterInUse(letter) {
			skipped++
			continue
		}
		// 先带显式账号，最可靠
		code, out := run("net", "use", letter+":", unc, pass, "/user:"+user, "/persistent:yes")
		if code == 0 {
			return letter, nil
		}
		lastCode, lastOut = code, out
		// 退一步：只用已存的凭据（有些系统不接受命令行传口令）
		if code2, out2 := run("net", "use", letter+":", unc, "/persistent:yes"); code2 == 0 {
			return letter, nil
		} else {
			_ = out2
		}
		if code == 2250 { // 盘符被占用，换下一个
			continue
		}
		// 其它错误基本不是盘符问题，没必要再试别的字母
		if code == 53 || code == 67 || code == 1326 || code == 5 {
			break
		}
	}
	if lastCode == 0 {
		lastCode = 2250
		if skipped > 0 {
			return "", fmt.Errorf("映射失败：从 %s 往下的盘符全被占用了，先断开几个不用的网络盘再试", candidates[0])
		}
	}
	// net use 的原始输出是 GBK，直接打到控制台会乱码，只落到日志里备查
	if logFile != nil && lastOut != "" {
		logFile.WriteString("net use raw: " + lastOut + "\r\n")
	}
	return "", fmt.Errorf("映射失败（错误 %d：%s）", lastCode, explainCode(lastCode))
}

// readDirNames 列出目录下的名字。
// 不用 os.ReadDir：它打开目录句柄用的方式在这个纯 Go SMB 服务端上会被拒
// （STATUS_INVALID_PARAMETER）。os.Open + Readdirnames 可绕开。
func readDirNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}

func letterInUse(letter string) bool {	p := letter + ":\\"
	if _, err := os.Stat(p); err == nil {
		return true
	}
	code, _ := run("net", "use", letter+":")
	return code == 0
}

// diagReport 只体检
func diagReport(ip, share string, admin bool) {
	emit("")
	emit("  ===== 体检报告 =====")
	emit("  服务器 445        : 可达")
	emit("  网络位置          : %s", networkCategory())
	if admin {
		if v, found := regGetDword(regPathLwParams, "AllowInsecureGuestAuth"); found {
			emit("  允许来宾登录      : %d", v)
		} else {
			emit("  允许来宾登录      : 未设置（默认 0）")
		}
		if v, found := regGetDword(regPathLsa, "LmCompatibilityLevel"); found {
			emit("  NTLM 级别         : %d", v)
		}
	} else {
		emit("  客户端策略        : 需要管理员权限才能读取")
	}
	if hasCredential(ip) {
		emit("  已存凭据          : 有")
	} else {
		emit("  已存凭据          : 无（Win11 会退到来宾，随后被签名策略拦掉）")
	}
	code, out := run("net", "use")
	hit := "无"
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `\\`+ip) {
			hit = strings.TrimSpace(line)
			break
		}
	}
	_ = code
	emit("  现有映射          : %s", hit)
	emit("  目标共享          : \\\\%s\\%s", ip, share)
}

// ---------------------------------------------------------------- 系统交互

func isAdmin() bool {
	// fltmc 在非管理员下会以非 0 退出；万一系统里没有它，再用 net session 兜底
	if code, _ := run("fltmc"); code == 0 {
		return true
	}
	if code, _ := run("net", "session"); code == 0 {
		return true
	}
	return false
}

func serviceRunning(name string) bool {
	code, out := run("sc", "query", name)
	return code == 0 && strings.Contains(strings.ToUpper(out), "RUNNING")
}

// hasCredential 判断 Credential Manager 里是否有该主机的网络凭据。
// 两个坑：① `cmdkey /list:<host>` 只回显"目标: <host>"，不带 target= 前缀；
// ② 标题行本身也含 IP，空列表时照样匹配。所以查全量列表里的 "Domain:target=<host>"。
func hasCredential(ip string) bool {
	code, out := run("cmdkey", "/list")
	if code != 0 {
		return false
	}
	return strings.Contains(strings.ToLower(out), "target="+strings.ToLower(ip))
}

func elevate() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args, _ := syscall.UTF16PtrFromString(strings.Join(quoteArgs(os.Args[1:]), " "))
	ret, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(args)),
		0,
		1, // SW_SHOWNORMAL
	)
	if ret <= 32 {
		return fmt.Errorf("ShellExecute 返回 %d（1223 表示用户点了取消）", ret)
	}
	return nil
}

func quoteArgs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		if a == "" || strings.ContainsAny(a, " \t") {
			out = append(out, `"`+strings.ReplaceAll(a, `"`, `\"`)+`"`)
		} else {
			out = append(out, a)
		}
	}
	return out
}

func run(name string, args ...string) (int, string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return code, string(out)
}

func regOpenKey(path string, access uint32) (syscall.Handle, error) {
	var h syscall.Handle
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	r, _, _ := procRegOpenKeyExW.Call(
		uintptr(hkeyLocalMachine),
		uintptr(unsafe.Pointer(p)),
		0,
		uintptr(access|keyWow64_64),
		uintptr(unsafe.Pointer(&h)),
	)
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return h, nil
}

func regCreateKey(path string) (syscall.Handle, error) {
	var h syscall.Handle
	var disp uint32
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	r, _, _ := procRegCreateKeyExW.Call(
		uintptr(hkeyLocalMachine),
		uintptr(unsafe.Pointer(p)),
		0,
		0,
		0,
		uintptr(keySetValue|keyWow64_64),
		0,
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&disp)),
	)
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return h, nil
}

// regGetDword 读取 HKLM 下的一个 DWORD，找不到返回 false
func regGetDword(path, name string) (uint32, bool) {
	h, err := regOpenKey(path, keyRead)
	if err != nil {
		return 0, false
	}
	defer syscall.RegCloseKey(h)
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, false
	}
	var typ, cb uint32 = 0, 4
	var data uint32
	r, _, _ := procRegQueryValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(n)),
		0,
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&cb)),
	)
	if r != 0 {
		return 0, false
	}
	return data, true
}

// regSetDword 写入 HKLM 下的一个 DWORD，键不存在会自动创建
func regSetDword(path, name string, val uint32) error {
	h, err := regCreateKey(path)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(h)
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	v := val
	r, _, _ := procRegSetValueExW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(n)),
		0,
		regDword,
		uintptr(unsafe.Pointer(&v)),
		4,
	)
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func networkCategory() string {
	_, out := run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetConnectionProfile | Where-Object {$_.IPv4Connectivity -ne 'Disconnected'} | Select-Object -First 1).NetworkCategory")
	s := strings.TrimSpace(out)
	if s == "" {
		return "未知"
	}
	return s
}

func tcpAlive(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func tcpRTT(ip string, port int) string {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 4*time.Second)
	if err != nil {
		return "?"
	}
	conn.Close()
	return time.Since(start).Round(time.Millisecond).String()
}

func emitLocalNets(target string) {
	emit("  本机地址：")
	ifaces, _ := net.Interfaces()
	found := false
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			emit("    %-28s %s", ifc.Name, ipnet.String())
			found = true
		}
	}
	if !found {
		emit("    （没有找到已联网的网卡，是否没连 Wi-Fi/网线？）")
	}
	_ = target
}

func explain(code int, raw string) string {
	return fmt.Sprintf("%d %s", code, explainCode(code))
}

func explainCode(code int) string {
	switch code {
	case 0:
		return "成功"
	case 2:
		return "找不到指定的文件（共享名可能拼错）"
	case 5:
		return "拒绝访问（账号没有该共享的权限）"
	case 53:
		return "找不到网络路径（服务器不可达，或被路由器隔离）"
	case 64:
		return "指定的网络名不再可用（服务端断开）"
	case 67:
		return "找不到网络名（共享名不存在，或服务端拒绝）"
	case 86:
		return "指定的网络密码不正确"
	case 1326:
		return "用户名或密码不正确（服务端只认登记过的账号）"
	case 1327:
		return "账户限制：不允许空密码登录"
	case 1219:
		return "同一服务器存在多重连接冲突（已存的旧凭据挡着，请先删掉）"
	case 1272:
		return "该资源被策略阻止（组策略禁止访问此共享）"
	case 2250:
		return "该网络连接不存在 / 盘符已被占用"
	case 1355:
		return "指定的域不存在或无法联系"
	case 1311:
		return "目前没有可用的登录服务器"
	case 1331:
		return "该账户当前被禁用"
	default:
		return "未知错误，详见同目录 fsgw-connect.log"
	}
}

// ---------------------------------------------------------------- 输出

func initConsole() {
	procSetConsoleOutCP.Call(65001)
	procSetConsoleCP.Call(65001)
	if t, err := syscall.UTF16PtrFromString("家庭共享盘一键修复"); err == nil {
		procSetConsoleTitle.Call(uintptr(unsafe.Pointer(t)))
	}
}

func initLog() {
	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	p := filepath.Join(dir, "fsgw-connect.log")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		p = filepath.Join(os.TempDir(), "fsgw-connect.log")
		f, err = os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
	}
	logFile = f
	logPath = p
	line := fmt.Sprintf("\r\n===== %s  启动  ppid=%d =====\r\n", time.Now().Format("2006-01-02 15:04:05"), os.Getppid())
	f.WriteString(line)
}

func emit(format string, a ...any) {
	s := format
	if len(a) > 0 {
		s = fmt.Sprintf(format, a...)
	}
	fmt.Println(s)
	if logFile != nil {
		logFile.WriteString(s + "\r\n")
	}
}

func banner(ip, share, user string, diagOnly bool) {
	fmt.Println("  ============================================================")
	fmt.Println("   家庭共享盘一键修复  ·  Win11 SMB 客户端")
	fmt.Println("  ------------------------------------------------------------")
	fmt.Printf("   目标共享 : \\\\%s\\%s\n", ip, share)
	fmt.Printf("   登录账号 : %s\n", user)
	if diagOnly {
		fmt.Println("   运行模式 : 只体检，不修改")
	}
	fmt.Println("  ============================================================")
	if logFile != nil {
		logFile.WriteString(fmt.Sprintf("target=\\\\%s\\%s user=%s diag=%v\r\n", ip, share, user, diagOnly))
	}
}

func step(n int, format string, a ...any) {
	emit("")
	emit("[%d/%d] %s", n, totalSteps, fmt.Sprintf(format, a...))
}

func ok(format string, a ...any)   { emit("       [ OK ] "+format, a...) }
func warn(format string, a ...any) { emit("       [WARN] "+format, a...) }
func info(format string, a ...any) { emit("              "+format, a...) }

func bad(format string, a ...any) {
	emit("       [FAIL] "+format, a...)
	if logFile != nil {
		logFile.Sync()
	}
}

func finish(success bool) {
	emit("")
	if success {
		emit("  ============================================================")
		emit("   完成。共享盘已可用，重启后会自动重连。")
		emit("  ============================================================")
	} else {
		emit("  ============================================================")
		emit("   没修好。请把下面的日志文件发给管理员，里面有每一步的结果：")
		if logPath != "" {
			emit("     %s", logPath)
		}
		emit("  ============================================================")
	}
	if logFile != nil {
		logFile.WriteString("---- 结束 ----\r\n")
		logFile.Sync()
	}
	pause()
	if !success {
		os.Exit(2)
	}
}

func pause() {
	fmt.Println("")
	fmt.Print("  按回车键退出 ...")
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

// ---------------------------------------------------------------- 参数

func hasFlag(name string) bool {
	for _, a := range os.Args[1:] {
		if strings.EqualFold(a, "-"+name) || strings.EqualFold(a, "--"+name) {
			return true
		}
	}
	return false
}

func argVal(name, def string) string {
	args := os.Args[1:]
	for i, a := range args {
		for _, p := range []string{"-", "--"} {
			key := p + name
			if strings.EqualFold(a, key+"=") || strings.HasPrefix(strings.ToLower(a), strings.ToLower(key+"=")) {
				return a[len(key)+1:]
			}
			if strings.EqualFold(a, key) && i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return def
}
