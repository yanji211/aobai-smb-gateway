//go:build windows

package smbhost

// Windows 上 445 端口不是"谁先听谁用"：系统服务 LanmanServer（Server）在开机
// 时就绑上了 0.0.0.0:445，任何用户进程再去 bind 都只会拿到 WSAEADDRINUSE
// （"通常每个套接字地址只允许使用一次"）。所以自研服务端要在 Windows 上对外
// 提供共享，必须先把 LanmanServer 让出来。
//
// 这里的做法是"可还原的接管"，而不是"永久关掉系统共享"：
//   - 接管前把服务的启动类型与运行状态写进 <数据目录>\lanserver_backup.json；
//   - 停服务 → 启动类型改手动（避免重启后它又把 445 抢回去）→ 确认端口已释放；
//   - 网关关闭或切换回系统共享时，按备份还原启动类型，原来在跑就重新拉起。
//
// 进程被强杀也不丢：备份文件在，下次启动要么接着用（引擎是 go），
// 要么在切换回 native 时按备份还原。
//
// 副作用必须说清楚：接管期间本机的系统共享（C$、D$、IPC$ 以及用户自己用
// net share 建的那些）都不可用——445 只有一个。这正是"用自研服务端替换
// 系统服务端"的必然结果，不是 bug。

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	lanmanService = "LanmanServer"
	port445Backup = "lanserver_backup.json"
	// port445Blocked 记录"这台机器停掉系统共享后 445 也不释放"这个事实，
	// 避免每次启动都白停一次系统共享（那会顺带踢掉别人正在用的连接）。
	port445Blocked = "port445_blocked.json"
	// port445Grace 是停掉服务后等内核释放端口的宽限时间。
	// 一般几百毫秒就够；个别机器（SMB 驱动不卸载）永远不释放，所以只等这么久。
	port445Grace = 6 * time.Second
)

// port445State 是接管前的现场。
type port445State struct {
	StartType  uint32 `json:"start_type"`
	WasRunning bool   `json:"was_running"`
	At         string `json:"at,omitempty"`
}

var (
	portMu       sync.Mutex
	portStateDir string
)

// setPortStateDir 告诉本文件把备份写到哪里。app 在启动前调用。
func setPortStateDir(dir string) {
	portMu.Lock()
	portStateDir = dir
	portMu.Unlock()
}

func port445BackupPath() string {
	dir := portStateDir
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, port445Backup)
}

func loadPort445State() *port445State {
	raw, err := os.ReadFile(port445BackupPath())
	if err != nil {
		return nil
	}
	var st port445State
	if json.Unmarshal(raw, &st) != nil {
		return nil
	}
	return &st
}

func savePort445State(st port445State) error {
	p := port445BackupPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(p, raw, 0o644)
}

func clearPort445State() { os.Remove(port445BackupPath()) }

// ---------- "这台机器抢不到 445" 的短期记忆 ----------

// blockedState 记住本次开机内是否已经确认过抢不到 445。
type blockedState struct {
	Boot   string `json:"boot"`
	Reason string `json:"reason"`
}

func blockedPath() string {
	dir := portStateDir
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, port445Blocked)
}

// bootToken 生成"本次开机"的标识：开机时刻（精确到分钟）。
// 用它而不是时间戳，是为了让重启后自动重试一次——有些机器改完配置重启就能接管了。
func bootToken() string {
	k := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")
	v, _, _ := k.Call()
	up := time.Duration(v) * time.Millisecond
	return time.Now().Add(-up).Format("2006-01-02T15:04")
}

func loadBlocked() *blockedState {
	raw, err := os.ReadFile(blockedPath())
	if err != nil {
		return nil
	}
	var b blockedState
	if json.Unmarshal(raw, &b) != nil {
		return nil
	}
	return &b
}

func saveBlocked(reason string) {
	raw, _ := json.MarshalIndent(blockedState{Boot: bootToken(), Reason: reason}, "", "  ")
	_ = os.WriteFile(blockedPath(), raw, 0o644)
}

func clearBlocked() { os.Remove(blockedPath()) }

// port445Holder 报告当前谁占着 445，用于失败时的日志（PID + 进程名）。
func port445Holder() string {
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return "未知"
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.EqualFold(f[0], "TCP") {
			continue
		}
		if !strings.HasSuffix(f[1], ":445") || !strings.EqualFold(f[len(f)-2], "LISTENING") {
			continue
		}
		pid := f[len(f)-1]
		name := "?"
		if o, err := exec.Command("tasklist", "/FI", "PID eq "+pid, "/FO", "CSV", "/NH").Output(); err == nil {
			if s := strings.SplitN(strings.TrimSpace(string(o)), ",", 2); len(s) == 2 {
				name = strings.Trim(s[0], "\"")
			}
		}
		return "PID " + pid + "（" + name + "）"
	}
	return "未知"
}

// port445Free 试着绑一下 445，能绑就是空着的。
func port445Free() bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", defaultPort))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// ensurePort445 保证 445 可以被本进程监听。已是空闲则直接返回。
//
// 失败分两种，处理方式不同：
//   - 本次开机已经确认抢不到（blocked 记录）：立刻返回，不再动系统服务；
//   - 第一次尝试：停服务 → 等端口释放。真释放不了就还原服务并把结论记下来。
func ensurePort445() error {
	portMu.Lock()
	defer portMu.Unlock()

	if port445Free() {
		clearBlocked()
		return nil
	}

	// 同一开机内已经试过并且失败：别再停一次系统共享（会踢掉别人正在用的连接）。
	if b := loadBlocked(); b != nil && b.Boot == bootToken() {
		return fmt.Errorf("%s", b.Reason)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("445 被占用，且连接服务管理器失败（需要管理员权限）: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(lanmanService)
	if err != nil {
		return fmt.Errorf("445 被占用，但打不开 %s 服务（占用者：%s）: %w", lanmanService, port445Holder(), err)
	}
	defer s.Close()

	// 只在第一次接管时记录现场。上次被强杀的话备份还在，不能覆盖成
	// "已经被我们改成手动"的中间态，否则退出时还原不回原样。
	if loadPort445State() == nil {
		cur, err := s.Query()
		if err != nil {
			return fmt.Errorf("查询 %s 状态失败: %w", lanmanService, err)
		}
		cfg, err := s.Config()
		if err != nil {
			return fmt.Errorf("读取 %s 配置失败: %w", lanmanService, err)
		}
		if err := savePort445State(port445State{
			StartType:  cfg.StartType,
			WasRunning: cur.State == svc.Running,
			At:         time.Now().Format(time.RFC3339),
		}); err != nil {
			return fmt.Errorf("记录 %s 接管现场失败: %w", lanmanService, err)
		}
	}

	// 先改启动类型再停：否则服务可能在我们的等待过程中被其它东西拉起来。
	if cfg, err := s.Config(); err == nil && cfg.StartType != mgr.StartManual {
		cfg.StartType = mgr.StartManual
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("把 %s 改成手动启动失败: %w", lanmanService, err)
		}
	}

	if st, err := s.Query(); err != nil {
		// 查不到状态也要继续试：有些受限句柄能停不能查，这里只记一笔。
		slog.Default().Warn("查询 LanmanServer 状态失败，仍尝试停止", "err", err)
	} else if st.State != svc.Stopped {
		if _, cerr := s.Control(svc.Stop); cerr != nil {
			slog.Default().Warn("停止 LanmanServer 失败", "err", cerr)
		}
		if err := waitStopped(s); err != nil {
			releasePort445Locked(m, s)
			return err
		}
	}

	// 服务状态变成 Stopped 不代表 445 立刻空出来：srv2/srvnet 还要在内核里
	// 关掉监听套接字。这里给宽限期再判定，否则会出现"服务明明停了、
	// 却报 445 仍被占用"的假失败并还原服务。
	begin := time.Now()
	if !waitPort445Free(port445Grace) {
		holder := port445Holder()
		releasePort445Locked(m, s)
		reason := fmt.Sprintf("停止 %s 后 445 仍被占用（占用者：%s，等了 %s）——本机 SMB 驱动没有卸载，自研服务端无法接管",
			lanmanService, holder, time.Since(begin).Round(100*time.Millisecond))
		saveBlocked(reason)
		return fmt.Errorf("%s", reason)
	}
	slog.Default().Info("已接管 445", "waited", time.Since(begin).Round(100*time.Millisecond))
	clearBlocked()
	return nil
}

// waitPort445Free 等 445 真正空出来（最多 d，每 100ms 探一次）。
// 停止 LanmanServer 之后内核释放监听有延迟，直接判 !port445Free() 会误报。
func waitPort445Free(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if port445Free() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitStopped 最多等 20 秒，等服务真正停掉（SMB 会话断开可能慢）。
func waitStopped(s *mgr.Service) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s 在 20 秒内没有停下来", lanmanService)
}

// releasePort445 把系统共享服务还原到接管前的样子。
// 只有在备份存在时才动，没接管过就什么都不做。
func releasePort445() {
	portMu.Lock()
	defer portMu.Unlock()
	if loadPort445State() == nil {
		return
	}
	m, err := mgr.Connect()
	if err != nil {
		return // 没权限就留着备份，下次启动再试
	}
	defer m.Disconnect()
	s, err := m.OpenService(lanmanService)
	if err != nil {
		return
	}
	defer s.Close()
	releasePort445Locked(m, s)
}

func releasePort445Locked(m *mgr.Mgr, s *mgr.Service) {
	st := loadPort445State()
	if st == nil {
		return
	}
	if cfg, err := s.Config(); err == nil && cfg.StartType != st.StartType {
		cfg.StartType = st.StartType
		_ = s.UpdateConfig(cfg)
	}
	if st.WasRunning {
		// 端口可能还被我们的监听占着，起不来就算了，下次开机会自己起。
		_ = s.Start()
	}
	clearPort445State()
}

// systemGuestActive 报告"免密"是否要靠系统策略实现。
// 只有 native 引擎才是——自研服务端的免密在进程内完成，不动系统任何设置。
func systemGuestActive() bool { return Engine() == "native" }
