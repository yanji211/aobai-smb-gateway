package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fsgw/internal/app"
	"fsgw/internal/config"
	"fsgw/internal/ctlapi"
	"fsgw/internal/platform"
	"fsgw/internal/selftest"
	"fsgw/internal/smbgo"
	"fsgw/internal/tray"
	"fsgw/internal/webdav"
)

// bareStart 标记"没带任何参数直接启动"（双击 exe 的典型路径）。
// 只有这种启动方式才需要在出错时停一下——双击出来的控制台窗口
// 会在进程退出瞬间消失，不留住就什么也看不到。
var bareStart bool

func main() {
	if len(os.Args) < 2 {
		// 不带参数 = run：转到后台、自动提权、起来后打开控制台。
		// 双击 exe 想要的就是这个效果，不需要用户记住任何参数。
		bareStart = true
		os.Exit(cmdRun([]string{"-detach", "-open"}))
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	// 以 - 开头的一律当成 run 的开关：`fsgw -noelevate`、`fsgw -config x.yaml`
	// 比要求写成 `fsgw run -noelevate` 顺手。
	if strings.HasPrefix(cmd, "-") {
		switch cmd {
		case "-h", "--help", "help":
			usage()
			return
		case "-v", "--version", "version":
			fmt.Println("fsgw", app.Version)
			return
		}
		os.Exit(cmdRun(os.Args[1:]))
	}

	switch cmd {
	case "run":
		os.Exit(cmdRun(args))
	case "stop":
		os.Exit(cmdStop(args))
	case "smb":
		os.Exit(cmdSMB(args))
	case "status":
		os.Exit(cmdStatus(args))
	case "on":
		os.Exit(cmdSwitch(args, "LAN"))
	case "off":
		os.Exit(cmdSwitch(args, "OFF"))
	case "ui":
		os.Exit(cmdUI(args))
	case "synctoken":
		os.Exit(cmdSyncToken(args))
	case "restart":
		os.Exit(cmdRestart(args))
	case "takeover":
		os.Exit(cmdTakeover(args))
	case "selftest":
		os.Exit(cmdSelftest(args))
	case "passwd":
		os.Exit(cmdPasswd(args))
	case "clean-meta":
		os.Exit(cmdCleanMeta(args))
	case "version", "-v", "--version":
		fmt.Println("fsgw", app.Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	usage := `熬拜共享家（fsgw）

用法:
  fsgw                                      直接启动：后台常驻 + 自动申请管理员 + 打开控制台
                                            （= fsgw run -detach -open，双击 exe 就是它）
  fsgw run [-config config.yaml] [-notray] [-noelevate] [-detach] [-open]
                                            前台启动（日志打在屏幕上；默认也会自动提权）
  fsgw stop                                 优雅退出（先拆暴露面，再结束进程）
  fsgw smb check                            检查 SMB 免密登录的四项开关
  fsgw smb client-guest on|off              允许/禁止本机访问别人的免密共享
  fsgw status [-config ...]                 打印当前状态
  fsgw on [-state LAN|WAN|ALL]              开启（WAN/ALL 需 -confirm）
  fsgw off                                  一键全关
  fsgw ui                                   打开控制台（带 token）
  fsgw synctoken                            打印快同步地址与 token（含可直接运行的客户端命令）
  fsgw restart                              换二进制后重启
  fsgw takeover [-config ...] [-gui]        结束已有实例，改用当前这份程序与配置重启
                                            （双击时选「接管」会自动调用，一般不用手打）
  fsgw selftest [-v]                        跑自动化功能测试，不需要管理员
  fsgw passwd -password xxx                 生成 WebDAV 口令摘要
  fsgw clean-meta [-v] [-force]             列出/清除 mac 留下的 .DS_Store、._xxx 等影子文件
                                            （默认只列清单，加 -force 才删）
  fsgw version

启动相关开关:
  -detach      转到后台（脱钩子进程），本进程立即返回，不占终端
  -elevate     没有管理员权限时弹 UAC 提权（默认开，-noelevate 关闭）
  -open        起来后自动用浏览器打开控制台
  -notray      不显示托盘图标（服务方式启动时用）

退出方式：托盘图标右键 → 退出程序；或 fsgw stop；或前台按 Ctrl+C。
三种方式都会先把 SMB 共享、防火墙规则、DLNA 与 WebDAV 拆干净再退。
`
	fmt.Print(usage)
}

// loadConfig 只认 -config，其余参数原样返回。
//
// 这里不用 flag 包：`fsgw restart -noelevate` 里的 -noelevate 是要透传给
// 新实例的开关，flag 包会当成"未定义参数"直接报错退出。手工摘 -config
// 既支持 `-config x` 也支持 `-config=x`，剩下的顺序不动。
func loadConfig(args []string) (*config.Config, []string, error) {
	var cfgPath string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-config" || a == "--config":
			if i+1 < len(args) {
				cfgPath = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-config="):
			cfgPath = strings.TrimPrefix(a, "-config=")
		case strings.HasPrefix(a, "--config="):
			cfgPath = strings.TrimPrefix(a, "--config=")
		default:
			rest = append(rest, a)
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	return cfg, rest, nil
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("fsgw", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径（默认 exe 同目录 config.yaml）")
	noTray := fs.Bool("notray", false, "不显示托盘图标")
	elevate := fs.Bool("elevate", true, "没有管理员权限时自动申请 UAC 提权")
	noElevate := fs.Bool("noelevate", false, "不自动提权（调试用；SMB 免密与 445 接管会失效）")
	detach := fs.Bool("detach", false, "转到后台运行，本进程立即返回")
	openUI := fs.Bool("open", false, "起来后自动用浏览器打开控制台")
	gui := fs.Bool("gui", false, "检测到已有实例时弹出图形对话框（双击 exe 自动开启）")
	daemon := fs.Bool("daemon", false, "内部标记：本进程已经是那个后台实例")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *noElevate {
		*elevate = false
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		pauseIfBare()
		return 1
	}

	// 1) 已经在跑就别再起一个：双击几次也只会有一个实例。
	//    判据是控制台端口能连上且 /healthz 正常，只读，不碰任何业务接口。
	//
	//    双击 exe 时不能只打印一行就退出——控制台窗口一闪而过，用户会以为
	//    "程序坏了、点了没反应"。这里把现状和两个选择摆到对话框里。
	if !*daemon && instanceUp(cfg.UI.Bind) {
		console := "http://" + ctlapi.Advertise(cfg.UI.Bind) + "/"
		allowGUI := bareStart || *gui
		switch askConflict("熬拜共享家 · 已有服务在运行", conflictMessage(cfg, console), allowGUI) {
		case choiceTakeOver:
			// 结束旧实例，改用"当前这份 exe + 当前这份 config"启动。
			// cmdTakeover 内部会申请管理员权限：旧实例多半是提权跑的。
			return cmdTakeover(takeoverArgs(cfg.Path, *noTray, *openUI, allowGUI))
		case choiceKeepOld:
			fmt.Println("已保留原有服务，本次启动关闭。")
			fmt.Println("控制台:", console, "（用原有服务的账号登录）")
			if *openUI {
				// 不带 token：原有服务的 control.token 不在本目录，硬塞一个
				// 本包的 token 只会让页面报鉴权失败，不如直接给登录页。
				if err := openBrowser(console); err != nil {
					fmt.Println("请手动打开上面的地址")
				}
			}
			return 0
		default: // choiceSkip：CLI / 计划任务 / 非 Windows，保持原有行为
			fmt.Println("fsgw 已经在运行，没有重复启动。")
			fmt.Println("控制台:", console)
			if *openUI {
				openConsole(cfg, slog.Default())
			}
			return 0
		}
	}

	// 2) 提权：SMB 共享、445 接管、防火墙规则都要管理员，双击 exe 默认没有。
	//    这里替用户按一次"以管理员身份运行"，Windows 弹 UAC；别的平台只提示。
	if *elevate && !*daemon && !platform.IsAdmin() && runtime.GOOS == "windows" {
		params := elevateParams(cfg.Path, *noTray, *detach, *openUI)
		// 要转后台时把提权出来的窗口藏起来：用户只需要 UAC 那一下，
		// 不需要再看一个一直亮着的黑框。
		if err := platform.RelaunchElevated(params, *detach); err != nil {
			// 提权没成（用户点了否、或当前会话不允许弹 UAC）：不能让双击
			// 变成"闪一下就没了"。降级为普通权限继续跑——控制台、DLNA、
			// 快同步都照常，只少 SMB 共享面，比什么都不起好。
			fmt.Fprintln(os.Stderr, "自动提权没成功:", err)
			fmt.Fprintln(os.Stderr, "先以普通权限启动（SMB 共享不可用；控制台、DLNA、快同步照常）。")
			fmt.Fprintln(os.Stderr, "要用共享：右键 fsgw.exe → 以管理员身份运行。")
			*elevate = false
			*noElevate = true
		} else {
			fmt.Println("已弹出 UAC，请在弹窗里点「是」。")
			fmt.Println("允许后程序在后台启动，本窗口会自动关闭。")
			return 0
		}
	}

	// 3) 转后台：把活交给脱钩的子进程，父进程立刻返回，不占终端。
	if *detach && !*daemon {
		self, exeErr := os.Executable()
		if exeErr != nil {
			fmt.Fprintln(os.Stderr, exeErr)
			pauseIfBare()
			return 1
		}
		if err := platform.SpawnDetached(self, detachArgv(cfg.Path, *noTray, *openUI, *noElevate)...); err != nil {
			fmt.Fprintln(os.Stderr, "转到后台失败:", err)
			pauseIfBare()
			return 1
		}
		if !waitListening(cfg.UI.Bind, 20*time.Second) {
			fmt.Fprintln(os.Stderr, "后台进程没能起来，看日志:", filepath.Join(cfg.Log.Dir, "fsgw.log"))
			pauseIfBare()
			return 1
		}
		fmt.Println("fsgw 已在后台运行。控制台:", "http://"+ctlapi.Advertise(cfg.UI.Bind)+"/")
		fmt.Println("退出：托盘图标右键 → 退出程序，或 fsgw stop。")
		return 0
	}

	if err := os.MkdirAll(cfg.Log.Dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		pauseIfBare()
		return 1
	}
	logFile, err := os.OpenFile(filepath.Join(cfg.Log.Dir, "fsgw.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		pauseIfBare()
		return 1
	}
	defer logFile.Close()

	level := slog.LevelInfo
	if strings.EqualFold(cfg.Log.Level, "debug") {
		level = slog.LevelDebug
	}
	// 后台实例没有控制台（stdout 是无效句柄），只写文件；
	// 前台则同时打到屏幕上，方便盯着看。
	var sink io.Writer = logFile
	if !*daemon {
		sink = io.MultiWriter(logFile, os.Stdout)
	}
	log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	a, err := app.New(app.Options{Config: cfg, Log: log})
	if err != nil {
		log.Error("初始化失败", "err", err)
		return 1
	}
	defer a.Close()

	if err := a.Start(context.Background()); err != nil {
		log.Error("启动失败", "err", err)
		return 1
	}
	log.Info("fsgw 已启动", "version", app.Version, "shares", len(cfg.Shares))

	// 托盘是"人怎么用"这一层：没有它，用户只能去任务管理器杀进程。
	// 拿不到通知区域（服务方式、无桌面会话）就降级为无托盘，不影响功能。
	if !*noTray {
		if err := startTray(a, cfg, log); err != nil {
			log.Warn("托盘图标未启用", "err", err)
		}
	}

	// 双击启动时顺手把控制台打开，省得用户还得去托盘里找。
	// 放个短延迟，等控制面把监听挂上再开页面。
	if *openUI {
		go func() {
			time.Sleep(800 * time.Millisecond)
			openConsole(cfg, log)
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		log.Info("收到退出信号，正在停止")
	case <-a.QuitCh():
		log.Info("收到退出请求，正在停止")
		// 留一点时间把 HTTP 响应发回浏览器/CLI，否则对端看到的是连接被重置。
		time.Sleep(500 * time.Millisecond)
	}
	tray.Stop()
	return 0
}

// startTray 把托盘菜单接到应用上：打开控制台、一键全关、退出。
// 菜单内容每次弹出时现算，所以永远是当前状态，不需要额外同步。
func startTray(a *app.App, cfg *config.Config, log *slog.Logger) error {
	err := tray.Start(tray.Options{
		Tip: "熬拜共享家",
		Items: func() []tray.Item {
			st := a.Status()
			label := map[string]string{
				"OFF": "全部关闭", "LAN": "局域网开放", "WAN": "仅外部开放", "ALL": "全部开放",
			}[st.State]
			if label == "" {
				label = st.State
			}
			return []tray.Item{
				{Label: "熬拜共享家 · " + label, Disabled: true},
				{Divider: true},
				{ID: "open", Label: "打开控制台"},
				{ID: "off", Label: "一键全关", Disabled: st.State == "OFF"},
				{Divider: true},
				{ID: "quit", Label: "退出程序"},
			}
		},
		OnActivate: func() { openConsole(cfg, log) },
		OnSelect: func(id string) {
			switch id {
			case "open":
				openConsole(cfg, log)
			case "off":
				if _, err := a.Switch(context.Background(), "OFF"); err != nil {
					log.Error("托盘：全关失败", "err", err)
				}
			case "quit":
				log.Info("托盘：请求退出程序")
				go a.Quit()
			}
		},
	})
	if err != nil {
		return err
	}
	log.Info("托盘图标已就绪", "菜单", "打开控制台 / 一键全关 / 退出程序")
	// 提示文字跟着状态走，鼠标一悬停就知道现在开着什么。
	go func() {
		last := ""
		for {
			st := a.Status()
			if st.State != last {
				last = st.State
				tray.SetTip("熬拜共享家 · " + stateCN(st.State))
			}
			select {
			case <-a.QuitCh():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
	return nil
}

func stateCN(s string) string {
	switch s {
	case "OFF":
		return "全部关闭"
	case "LAN":
		return "局域网开放"
	case "WAN":
		return "仅外部开放"
	case "ALL":
		return "全部开放"
	}
	return s
}

// openConsole 用默认浏览器打开控制台。token 放 fragment，不进日志。
func openConsole(cfg *config.Config, log *slog.Logger) {
	tok, err := cliToken(cfg)
	if err != nil {
		log.Error("打开控制台失败", "err", err)
		return
	}
	url := consoleURL(cfg, tok)
	if err := openBrowser(url); err != nil {
		log.Info("控制台地址已打印，请手动打开", "err", err, "url", url)
	}
}

// consoleURL 拼出"能点开"的控制台地址。
//
// 绑 0.0.0.0:8444 时不能直接拼 http://0.0.0.0:8444 —— 那是个不可访问的地址。
// ctlapi.Advertise 会挑一张真实网卡的 IP 顶上去，Linux 上就能把这一行直接
// 贴到别的机器的浏览器里。
func consoleURL(cfg *config.Config, token string) string {
	return "http://" + ctlapi.Advertise(cfg.UI.Bind) + "/#" + token
}

// cliToken 读取控制面 token，供 CLI 子命令调用同一套 HTTP API。
func cliToken(cfg *config.Config) (string, error) {
	raw, err := os.ReadFile(filepath.Join(cfg.DataDir, "control.token"))
	if err != nil {
		return "", fmt.Errorf("读取 control.token 失败（服务未启动过？）: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func cliDo(cfg *config.Config, method, path string, body any) (map[string]any, error) {
	tok, err := cliToken(cfg)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, "http://"+cfg.UI.Bind+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-FSGW-Token", tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接控制面失败（服务在跑吗？）: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(raw, &out)
	if resp.StatusCode >= 400 {
		msg, _ := out["error"].(string)
		if msg == "" {
			msg = string(raw)
		}
		return out, fmt.Errorf("%s", msg)
	}
	return out, nil
}

// conflictMessage 把"为什么双击没反应"讲清楚，并说明两个按钮各自的后果。
func conflictMessage(cfg *config.Config, console string) string {
	root := firstShareRoot(cfg)
	dir := filepath.Dir(cfg.Path)
	return "这台电脑上已经有一个「熬拜共享家」服务在运行：\r\n\r\n" +
		"    控制台　　" + console + "\r\n" +
		"    控制端口　" + cfg.UI.Bind + "\r\n" +
		"    当前包位置　" + dir + "\r\n\r\n" +
		"445 等共享端口同一时刻只能由一个服务持有，所以本次启动被挡住了。\r\n" +
		"刚才双击后「没反应」，就是这个原因，不是程序坏了。\r\n\r\n" +
		"请选择：\r\n\r\n" +
		"【是】结束原有服务，改用当前这个包启动\r\n" +
		"　　　共享目录会变成：" + root + "\r\n" +
		"　　　电视等已连接的设备可能要重启才会刷新列表。\r\n\r\n" +
		"【否】保留原有服务，关闭本次启动\r\n" +
		"　　　什么都不改，直接访问上面的控制台即可。"
}

// firstShareRoot 取当前这份配置真正会共享的目录，别在对话框里报一个
// 泛泛的 "share"——用户要判断的正是"换过去之后哪个目录会被共享"。
func firstShareRoot(cfg *config.Config) string {
	if len(cfg.Shares) > 0 && cfg.Shares[0].Root != "" {
		return cfg.Shares[0].Root
	}
	return filepath.Join(filepath.Dir(cfg.Path), "share")
}

// takeoverArgs 给 cmdTakeover 的 flag.FlagSet 用（元素不会被空格拆开）。
func takeoverArgs(cfgPath string, noTray, openUI, gui bool) []string {
	a := make([]string, 0, 8)
	if cfgPath != "" {
		a = append(a, "-config", cfgPath)
	}
	if noTray {
		a = append(a, "-notray")
	}
	if openUI {
		a = append(a, "-open")
	}
	if gui {
		a = append(a, "-gui")
	}
	return a
}

// takeoverParams 给 RelaunchElevated 用：ShellExecuteW 收的是一整串参数，
// 带空格的路径必须自己加引号。与 elevateParams 是同一个约定。
func takeoverParams(cfgPath string, noTray, openUI, gui bool) string {
	p := "takeover"
	if cfgPath != "" {
		p += ` -config "` + cfgPath + `"`
	}
	if noTray {
		p += " -notray"
	}
	if openUI {
		p += " -open"
	}
	if gui {
		p += " -gui"
	}
	return p
}

// cmdTakeover 结束已在跑的实例，改用"当前这份 exe + 当前这份 config"重启。
// 由双击时的冲突对话框调用，也可以手工执行：fsgw takeover -config x.yaml
func cmdTakeover(args []string) int {
	fs := flag.NewFlagSet("takeover", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径（默认 exe 同目录 config.yaml）")
	noTray := fs.Bool("notray", false, "不显示托盘图标")
	openUI := fs.Bool("open", false, "启动后打开控制台")
	gui := fs.Bool("gui", false, "用图形对话框报告结果")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// 旧实例多半是提权跑的，普通权限结束不了。先申请一次 UAC，让提权后的
	// 同一个子命令把活干完；用户已经看过说明框，这一步只是执行决定。
	if runtime.GOOS == "windows" && !platform.IsAdmin() {
		if err := platform.RelaunchElevated(takeoverParams(*cfgPath, *noTray, *openUI, *gui), false); err != nil {
			fmt.Fprintln(os.Stderr, "接管需要管理员权限，提权失败:", err)
			showError("熬拜共享家 · 接管失败",
				"结束原有服务需要管理员权限，UAC 没有通过：\r\n"+err.Error()+
					"\r\n\r\n原有服务保持不变。可以右键 fsgw.exe → 以管理员身份运行后重试。", *gui)
			return 1
		}
		fmt.Println("已弹出 UAC，点「是」后会自动结束原有服务并用本包启动。")
		return 0
	}
	return takeoverNow(cfg, *cfgPath, *noTray, *openUI, *gui)
}

// takeoverNow 已在管理员权限下运行：拆旧实例 → 等端口 → 拉起当前包的后台实例。
func takeoverNow(cfg *config.Config, cfgPath string, noTray, openUI, gui bool) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	console := "http://" + ctlapi.Advertise(cfg.UI.Bind) + "/"
	logPath := filepath.Join(cfg.Log.Dir, "fsgw.log")

	// 1) 先请旧实例优雅退出，好让它把 SMB 共享、防火墙规则、DLNA、WebDAV
	//    拆干净。control.token 通常不在本包目录，这条路失败是正常的。
	if _, err := cliDo(cfg, http.MethodPost, "/api/quit", nil); err == nil {
		fmt.Println("已请求原有服务退出…")
		platform.WaitPortFree(cfg.UI.Bind, 10*time.Second)
	}

	// 2) 端口还占着就结束其它同名进程（listPIDs 会排除自己）。
	if !platform.WaitPortFree(cfg.UI.Bind, 400*time.Millisecond) {
		n, kerr := platform.KillOtherInstances(filepath.Base(self))
		if kerr != nil || n == 0 {
			msg := "无法结束原有服务"
			if kerr != nil {
				msg += "：" + kerr.Error()
			} else {
				msg += "（没有找到同名进程，请确认是否以管理员身份运行）"
			}
			fmt.Fprintln(os.Stderr, msg)
			showError("熬拜共享家 · 接管失败", msg+"\r\n\r\n原有服务保持不变。", gui)
			return 1
		}
		fmt.Printf("已结束 %d 个原有进程，等待端口释放…\n", n)
		if !platform.WaitPortFree(cfg.UI.Bind, 15*time.Second) {
			msg := "端口 " + cfg.UI.Bind + " 仍被占用。\r\n\r\n" +
				"常见原因：开机自启任务（任务计划程序）把原有服务又拉起来了。\r\n" +
				"请先禁用该任务，再重新双击本包启动。"
			fmt.Fprintln(os.Stderr, msg)
			showError("熬拜共享家 · 接管失败", msg, gui)
			return 1
		}
	}

	// 3) 父进程已提权，spawn 出来的后台实例继承管理员令牌，能接管 445。
	//    -daemon 会跳过单例检测与二次提权，避免又弹一次 UAC。
	if err := platform.SpawnDetached(self, detachArgv(cfgPath, noTray, openUI, false)...); err != nil {
		msg := "拉起新实例失败：" + err.Error()
		fmt.Fprintln(os.Stderr, msg)
		showError("熬拜共享家 · 接管失败", msg, gui)
		return 1
	}

	// 控制台 /healthz 通了就算起来；大目录索引对齐可能还要几分钟，不必等它。
	if !waitListening(cfg.UI.Bind, 45*time.Second) {
		fmt.Fprintln(os.Stderr, "新实例还没就绪，看日志:", logPath)
		showInfo("熬拜共享家 · 正在启动",
			"原有服务已结束，新实例正在建索引（大目录可能要几分钟）。\r\n\r\n"+
				"稍后访问："+console+"\r\n日志："+logPath, gui)
		return 0
	}
	msg := "原有服务已结束，已用当前文件夹这个包重新启动。\r\n\r\n" +
		"共享目录　" + firstShareRoot(cfg) + "\r\n" +
		"控制台　　" + console + "\r\n\r\n" +
		"注意：电视等已连接的设备可能仍沿用旧挂载，必要时重启一下设备。"
	fmt.Println("接管完成。控制台:", console)
	showInfo("熬拜共享家 · 接管完成", msg, gui)
	return 0
}

// cmdStop 优雅退出：先让在跑的实例把暴露面拆干净，再等它结束。
// 控制面不响应时才退化为强杀，并明确告知可能残留什么。
func cmdStop(args []string) int {
	cfg, _, err := loadConfig(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if platform.WaitPortFree(cfg.UI.Bind, 400*time.Millisecond) {
		fmt.Println("没有在运行的实例")
		return 0
	}
	if _, err := cliDo(cfg, http.MethodPost, "/api/quit", nil); err != nil {
		fmt.Fprintln(os.Stderr, "控制面未响应:", err)
		self, e := os.Executable()
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		n, kerr := platform.KillOtherInstances(filepath.Base(self))
		if kerr != nil || n == 0 {
			fmt.Fprintf(os.Stderr, "强制结束也失败了（可能需要管理员权限）: %v\n", kerr)
			return 1
		}
		fmt.Printf("已强制结束 %d 个实例。注意：强杀不会清理 SMB 共享与防火墙规则，下次启动会自动清理。\n", n)
		return 0
	}
	fmt.Println("已请求退出，等待进程结束…")
	self, _ := os.Executable()
	portFree := platform.WaitPortFree(cfg.UI.Bind, 10*time.Second)
	gone := self == "" || platform.WaitProcessGone(filepath.Base(self), 5*time.Second)
	if portFree && gone {
		fmt.Println("已退出：SMB 共享、防火墙规则、DLNA、WebDAV 均已关闭")
		return 0
	}
	fmt.Fprintln(os.Stderr, "控制面已接受请求但进程仍未退出，请查看 logs/fsgw.log")
	return 1
}

// cmdSMB 检查/修复 SMB 免密登录相关开关。
// 免密不是"一个开关"，是四项条件的合取，哪项没到位现象都一样，
// 所以这里逐项打印现状，而不是只回一句"连不上"。
func cmdSMB(args []string) int {
	// 先把动作名摘出来再解析 flag：Go 的 flag 解析遇到第一个非 flag 参数就
	// 停下，"fsgw smb check -config /etc/fsgw/config.yaml" 里的 -config 会
	// 被悄悄丢掉，然后回退到可执行文件同目录的 config.yaml，报"文件不存在"。
	action := "check"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "check", "client-guest", "nt-hash":
			action = args[0]
			rest = args[1:]
		default:
			fmt.Fprintf(os.Stderr, "未知动作 %q，可用: check | client-guest on|off | nt-hash <口令>\n", args[0])
			return 2
		}
	}

	// nt-hash 只做一次哈希，不需要读配置（换机器上算也要能用）。
	if action == "nt-hash" {
		if len(rest) < 1 {
			fmt.Fprintln(os.Stderr, "用法: fsgw smb nt-hash <口令>   # 输出可直接写进 smb.nt_hash")
			return 2
		}
		fmt.Println(smbgo.NTHashHex(rest[0]))
		return 0
	}

	cfg, _, err := loadConfig(rest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if action == "client-guest" {
		if len(rest) < 1 || (rest[0] != "on" && rest[0] != "off") {
			fmt.Fprintln(os.Stderr, "用法: fsgw smb client-guest on|off")
			return 2
		}
		return smbClientGuest(rest[0] == "on")
	}
	return smbReport(cfg)
}

func cmdStatus(args []string) int {
	cfg, _, err := loadConfig(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	out, err := cliDo(cfg, http.MethodGet, "/api/status", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "获取状态失败:", err)
		return 1
	}
	fmt.Printf("状态      %v (期望 %v)\n", out["applied_state"], out["desired_state"])
	fmt.Printf("提权      %v\n", out["admin"])
	if e, ok := out["last_error"].(string); ok && e != "" {
		fmt.Printf("上次失败  %s\n", e)
	}
	if shares, ok := out["shares"].([]any); ok {
		for _, s := range shares {
			m := s.(map[string]any)
			fmt.Printf("共享      %v -> %v\n", m["name"], m["root"])
		}
	}
	if idx, ok := out["index"].(map[string]any); ok {
		fmt.Printf("索引      文件 %v · 目录 %v · 版本 %v · 路径历史 %v\n",
			idx["files"], idx["dirs"], idx["versions"], idx["path_history"])
	}
	if ls, ok := out["listeners"].([]any); ok {
		for _, l := range ls {
			m := l.(map[string]any)
			state := "停止"
			if m["ready"] == true {
				state = "就绪"
			} else if m["enabled"] == true {
				state = "启用但未就绪"
			}
			fmt.Printf("监听      %-8v %v  %v\n", m["name"], state, m["addr"])
		}
	}
	return 0
}

func cmdSwitch(args []string, def string) int {
	fs := flag.NewFlagSet("fsgw", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径")
	state := fs.String("state", def, "目标状态 OFF|LAN|WAN|ALL")
	confirm := fs.Bool("confirm", false, "确认开启外部访问")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	target := strings.ToUpper(*state)
	body := map[string]string{"state": target}
	if *confirm || target == "WAN" || target == "ALL" {
		body["confirm"] = target
	}
	out, err := cliDo(cfg, http.MethodPost, "/api/switch", body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "切换失败:", err)
		return 1
	}
	id, _ := out["operation_id"].(string)
	fmt.Println("已提交切换 ->", target, "operation:", id)
	// 轮询到结束
	for i := 0; i < 40; i++ {
		time.Sleep(250 * time.Millisecond)
		op, err := cliDo(cfg, http.MethodGet, "/api/operations/"+id, nil)
		if err != nil {
			break
		}
		stage, _ := op["stage"].(string)
		fmt.Print("\r  stage: " + stage + "        ")
		if done, _ := op["done"].(bool); done {
			fmt.Println()
			if e, _ := op["error"].(string); e != "" {
				fmt.Fprintln(os.Stderr, "失败:", e)
				return 1
			}
			fmt.Println("完成:", target)
			return 0
		}
	}
	fmt.Println()
	return 0
}

func cmdUI(args []string) int {
	cfg, _, err := loadConfig(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	tok, err := cliToken(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	url := consoleURL(cfg, tok)
	fmt.Println("控制台:", url)
	fmt.Printf("（其它设备人工登录用这个地址就行：http://%s/ ，账号是共享设置里的用户名+口令）\n",
		ctlapi.Advertise(cfg.UI.Bind))
	if err := openBrowser(url); err != nil {
		fmt.Println("（当前环境没有浏览器，把上面的地址复制到能连到本机的设备上打开）")
	}
	return 0
}

// cmdSyncToken 打印「快同步」的地址与 token。
//
// 同步 token 单独一把钥匙：它只能往共享里写文件，拿不到控制台那种
// "停服务/改口令"的权限。要换钥匙就删掉 data_dir/sync.token 重启。
func cmdSyncToken(args []string) int {
	cfg, _, err := loadConfig(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	p := filepath.Join(cfg.DataDir, "sync.token")
	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "还没有同步 token（服务没启动过？）：%v\n", err)
		return 1
	}
	tok := strings.TrimSpace(string(b))
	addr := ctlapi.Advertise(cfg.Sync.Bind)
	if !cfg.Sync.Enabled {
		fmt.Println("注意：config.yaml 里 sync.enabled 为 false，服务不会监听")
	}
	fmt.Println("快同步地址: http://" + addr)
	fmt.Println("token:      " + tok)
	fmt.Println()
	fmt.Println("客户端（Windows / Linux 都用同一个 fsgw-sync）：")
	fmt.Printf("  fsgw-sync -server http://%s -token %s -src <本地目录> -dst <目标目录>\n", addr, tok)
	fmt.Println()
	fmt.Println("首次可加 -dry-run 看看会传什么；中断后原样重跑即断点续传。")
	return 0
}

// cmdRestart 结束同名旧实例并拉起新实例。
// 用于"换了二进制但旧进程还占着端口和文件"的场景；需要在提权环境执行，
// 否则结束不了以管理员身份运行的旧实例。
func cmdRestart(args []string) int {
	cfg, rest, err := loadConfig(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// 先走控制面优雅退出：这条路不需要管理员，也会把 SMB 共享、防火墙规则、
	// DLNA、WebDAV 拆干净再走。拆不干净时再退回强杀（强杀需要管理员）。
	if !platform.WaitPortFree(cfg.UI.Bind, 300*time.Millisecond) {
		if _, qerr := cliDo(cfg, http.MethodPost, "/api/quit", nil); qerr == nil {
			fmt.Println("已请求旧实例退出…")
			platform.WaitPortFree(cfg.UI.Bind, 12*time.Second)
		}
	}
	if !platform.WaitPortFree(cfg.UI.Bind, 3*time.Second) {
		killed, kerr := platform.KillOtherInstances(filepath.Base(self))
		if kerr != nil {
			fmt.Fprintf(os.Stderr, "结束旧实例失败（通常是没有提权）: %v\n", kerr)
			return 1
		}
		fmt.Printf("已强制结束 %d 个旧实例（未清理的共享与规则下次启动会收拾）\n", killed)
		if !platform.WaitPortFree(cfg.UI.Bind, 8*time.Second) {
			fmt.Fprintf(os.Stderr, "端口 %s 仍被占用，放弃启动\n", cfg.UI.Bind)
			return 1
		}
	}

	argv := append([]string{"run"}, rest...)
	if cfg.Path != "" {
		argv = append(argv, "-config", cfg.Path)
	}
	if err := platform.SpawnDetached(self, argv...); err != nil {
		fmt.Fprintln(os.Stderr, "拉起新实例失败:", err)
		return 1
	}
	if !platform.IsAdmin() && runtime.GOOS == "windows" &&
		!hasFlag(rest, "-noelevate") && !hasFlag(rest, "-elevate=false") {
		fmt.Println("新实例会弹一次 UAC，请点「是」；不想要提权就加 -noelevate。")
	}
	if !waitListening(cfg.UI.Bind, 45*time.Second) {
		fmt.Fprintln(os.Stderr, "新实例还没起来（多半是在等 UAC 授权）；授权后它会自己起，日志在",
			filepath.Join(cfg.Log.Dir, "fsgw.log"))
		return 1
	}
	fmt.Println("新实例已启动，控制台:", "http://"+ctlapi.Advertise(cfg.UI.Bind)+"/")
	return 0
}

func cmdSelftest(args []string) int {
	verbose := false
	for _, a := range args {
		if a == "-v" || a == "--verbose" {
			verbose = true
		}
	}
	res := selftest.Run(verbose)
	fmt.Print(res.Report())
	if res.Failed() > 0 {
		return 1
	}
	return 0
}

func cmdPasswd(args []string) int {
	fs := flag.NewFlagSet("fsgw", flag.ContinueOnError)
	pw := fs.String("password", "", "明文口令")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *pw == "" {
		fmt.Fprintln(os.Stderr, "需要 -password")
		return 1
	}
	fmt.Println(webdav.HashPassword(*pw))
	return 0
}

// hasFlag 判断参数表里有没有某个开关（兼容 -x=false 写法）。
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// elevateParams 拼出提权后要执行的那条命令行。
// 抽成纯函数是为了能测：这一行拼错，用户双击之后只会看到 UAC 一闪、
// 然后什么都没发生，排查起来极其费劲。
func elevateParams(cfgPath string, noTray, detach, openUI bool) string {
	p := "run -elevate"
	if cfgPath != "" {
		p += ` -config "` + cfgPath + `"`
	}
	if noTray {
		p += " -notray"
	}
	if detach {
		p += " -detach"
	}
	if openUI {
		p += " -open"
	}
	return p
}

// detachArgv 拼出后台实例的参数。带上 -daemon 是关键：
// 否则子进程会再转一次后台，无限套娃。
func detachArgv(cfgPath string, noTray, openUI, noElevate bool) []string {
	argv := []string{"run", "-daemon"}
	if cfgPath != "" {
		argv = append(argv, "-config", cfgPath)
	}
	if noTray {
		argv = append(argv, "-notray")
	}
	if openUI {
		argv = append(argv, "-open")
	}
	// 提权已经被否掉时要把这个决定传下去：否则子进程又会自己弹一次 UAC，
	// 用户点否两次、程序还是没起来。
	if noElevate {
		argv = append(argv, "-noelevate")
	}
	return argv
}

// instanceUp 判断控制台端口上是否已经有实例在答话。
// 判据是能连上并且 /healthz 返回 200——这个接口免令牌，也不需要登录，
// 所以连"刚起来还在建索引""没登录"都能认出来。
func instanceUp(bind string) bool {
	addr := bind
	if h, p, err := net.SplitHostPort(bind); err == nil {
		if h == "" || h == "0.0.0.0" || h == "::" {
			addr = net.JoinHostPort("127.0.0.1", p)
		}
	}
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	cl := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := cl.Get("http://" + addr + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// waitListening 等端口开始服务（后台实例真正起来没有）。
// 比起固定 sleep，它能区分"起来了"和"根本没起来"。
func waitListening(bind string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if instanceUp(bind) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// pauseIfBare 只在"双击 exe"（无参数）时停一下再退出。
// 提权被拒、配置写错这类错误如果一闪而过，用户根本来不及看。
func pauseIfBare() {
	if !bareStart {
		return
	}
	fmt.Print("\n按回车键关闭窗口…")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
