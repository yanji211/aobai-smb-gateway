// Package app 负责装配、生命周期与开关状态机（见 docs/01 第 4、5 节）。
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"fsgw/internal/audit"
	"fsgw/internal/config"
	"fsgw/internal/ctlapi"
	"fsgw/internal/dlna"
	"fsgw/internal/index"
	"fsgw/internal/platform"
	"fsgw/internal/smbgo"
	"fsgw/internal/smbhost"
	"fsgw/internal/syncsvc"
	"fsgw/internal/vfs"
	"fsgw/internal/webdav"
	"fsgw/internal/webui"
)

const Version = "0.1.0"

type App struct {
	cfg   *config.Config
	store *index.Store
	ix    *index.Indexer
	vfs   *vfs.VFS
	aud   *audit.Log
	log   *slog.Logger
	start time.Time
	admin bool
	dry   bool

	mu        sync.RWMutex
	applied   string
	desired   string
	lastError string
	smbState  string
	smbNote   string
	smbAuth   string
	warnings  []string
	// rebuilding 记着哪些共享正在重建索引（改根目录之后）。
	// 前端据此显示"重建中"，而不是让用户对着一个空目录以为文件丢了。
	rebuilding map[string]bool
	// guestACLBusy 是正在后台做免密授权（Everyone + 继承传播）的目录。
	// 大目录上这一步要跑几分钟，不能挡在开关切换的同步路径里，
	// 但界面得说清楚"还在弄"，否则用户以为免密又坏了。
	guestACLBusy string
	// guestACLPending 是"排队等授权"的目录。
	// 连着换两次目录时第一次的传播还在跑，第二次不能就这么被丢掉——
	// 丢掉的话新目录一直没授权，用户只会看到"guest 还是进不去"。
	guestACLPending guestACLTarget

	opsMu sync.Mutex
	ops   map[string]*ctlapi.Operation

	srvMu     sync.Mutex
	wdSrv     *http.Server
	wdLn      net.Listener
	dlnaSrv   *dlna.Server
	ctlSrv    *http.Server
	ctlLn     net.Listener
	ctlAPI    *ctlapi.Server
	syncSrv   *syncsvc.Server
	syncLn    net.Listener
	syncToken string

	// 退出请求。关闭 quitCh 表示"拆除已完成，可以结束进程"。
	quitOnce sync.Once
	quitCh   chan struct{}
}

type Options struct {
	Config *config.Config
	Log    *slog.Logger
	// DryRun 跳过整机副作用（防火墙规则、SMB 共享），供 selftest 使用。
	DryRun bool
}

func New(o Options) (*App, error) {
	cfg := o.Config
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	store, err := index.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	aud, err := audit.Open(filepath.Join(cfg.Log.Dir, "audit.log"), 20<<20, 5)
	if err != nil {
		store.Close()
		return nil, err
	}

	shares := make([]vfs.Share, 0, len(cfg.Shares))
	for _, s := range cfg.Shares {
		shares = append(shares, vfs.Share{
			ShareID: s.ShareID, Name: s.Name, Root: s.Root,
			Writable: s.Writable, Media: s.Media,
		})
	}

	a := &App{
		cfg:     cfg,
		store:   store,
		vfs:     vfs.New(shares),
		aud:     aud,
		log:     o.Log,
		start:   time.Now(),
		admin:   platform.IsAdmin(),
		dry:     o.DryRun,
		ops:     map[string]*ctlapi.Operation{},
		applied: "OFF",
		desired: "OFF",
		quitCh:  make(chan struct{}),

		rebuilding: map[string]bool{},
	}
	a.ix = index.NewIndexer(store, index.Params{
		DebounceStructuralMS: cfg.Index.DebounceStructuralMS,
		DebounceContentMS:    cfg.Index.DebounceContentMS,
		HashMaxMB:            cfg.Index.HashMaxMB,
		Source:               index.SourceLocal,
	}, o.Log, aud)
	return a, nil
}

// Start 启动索引与监听，并按 startup_state 应用开关。
func (a *App) Start(ctx context.Context) error {
	for _, s := range a.cfg.Shares {
		a.ix.RegisterShare(s.ShareID, s.Root)
	}

	// 控制台先起：它是"看得见"的唯一途径，不该排在索引后面等。
	// 大共享根（几十万文件）的全量对齐要跑几分钟，那段时间必须有界面能看状态、
	// 能看日志，否则 Linux 上只能靠 SSH 猜。
	if err := a.startControl(); err != nil {
		return err
	}

	// 每个共享根做一次初始对齐（只读元数据，不读内容），再挂文件监听。
	// 这一步仍是阻塞的：共享面对外之前索引必须是完整的，否则刚复制进来的文件
	// 在列表里查不到，反而更像"坏了"。进度日志见 indexer.walkUpsert。
	if len(a.cfg.Shares) > 0 {
		a.log.Info("开始索引对齐（完成前不会开放共享面）", "shares", len(a.cfg.Shares))
	}
	for _, s := range a.cfg.Shares {
		if _, err := a.ix.BuildInitial(s.ShareID, s.Root); err != nil {
			a.log.Error("初始索引失败", "share", s.ShareID, "err", err)
			continue
		}
		a.ix.Run(s.ShareID, s.Root)
	}
	a.log.Info("索引对齐完成，准备开放共享面")

	startup := strings.ToUpper(a.cfg.Switch.StartupState)
	if startup == "" {
		startup = "OFF"
	}
	// 进程上次可能是被强杀的，SMB 共享与防火墙规则会留在系统里。
	// 启动时先清一遍，保证"状态 OFF 就等于零暴露"这句话在崩溃后依然成立。
	a.cleanupLeftovers(startup)
	// 上一次如果是被强杀在"已接管 445"的状态，系统自带的共享服务可能还停着。
	// 这里先把它还原，再按配置决定要不要重新接管。
	smbhost.Recover()
	if _, err := a.Switch(ctx, startup); err != nil {
		a.log.Warn("按配置启动开关失败，回落到 OFF", "target", startup, "err", err)
		if _, err2 := a.Switch(ctx, "OFF"); err2 != nil {
			return err2
		}
	}
	return nil
}

// cleanupLeftovers 在启动时把上一次残留的暴露面拆掉。
func (a *App) cleanupLeftovers(startup string) {
	if startup != "OFF" {
		return
	}
	shareName := a.cfg.Shares[0].Name
	if smbhost.Exists(shareName) {
		if a.admin {
			if err := smbhost.RemoveShare(shareName); err != nil {
				a.log.Warn("清理残留 SMB 共享失败", "err", err)
			} else {
				a.log.Info("已清理上次残留的 SMB 共享", "share", shareName)
			}
		} else {
			a.log.Warn("检测到残留 SMB 共享，但当前未提权，无法清理", "share", shareName)
		}
	}
	if a.admin {
		if names, err := platform.List("FSGW-"); err == nil && len(names) > 0 {
			if err := platform.RemoveByPrefix("FSGW-"); err != nil {
				a.log.Warn("清理残留防火墙规则失败", "err", err)
			} else {
				a.log.Info("已清理残留防火墙规则", "count", len(names))
			}
		}
		// 上次可能是被强杀的，免密策略（Guest / ForceGuest / NTFS）还留在系统里。
		// 这次以 OFF 启动，就该把这些一起还原。
		a.restoreGuest()
	}
}

func (a *App) Close() {
	// 无论走哪条退出路径（Ctrl+C、托盘退出、控制台退出），
	// 都不能把 SMB 共享和防火墙规则留在系统里——"进程没了"必须等于"零暴露"。
	if a.appliedState() != "OFF" {
		a.teardownAll()
		a.mu.Lock()
		a.applied, a.desired = "OFF", "OFF"
		a.mu.Unlock()
		a.persistState()
	}

	a.srvMu.Lock()
	if a.dlnaSrv != nil {
		a.dlnaSrv.Stop()
		a.dlnaSrv = nil
	}
	if a.syncSrv != nil {
		_ = a.syncSrv.Close()
		a.syncSrv = nil
	}
	if a.wdSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		a.wdSrv.Shutdown(ctx)
		cancel()
	}
	if a.ctlSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		a.ctlSrv.Shutdown(ctx)
		cancel()
	}
	a.srvMu.Unlock()

	a.ix.Close()
	a.store.Close()
	a.aud.Close()
}

func (a *App) appliedState() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.applied
}

// QuitCh 在拆除完成、可以结束进程时关闭。
func (a *App) QuitCh() <-chan struct{} { return a.quitCh }

// Quit 优雅退出：先把所有暴露面拆干净，再通知主循环结束。
// 幂等——托盘、控制台、信号可能同时触发。
func (a *App) Quit() {
	a.quitOnce.Do(func() {
		a.log.Info("收到退出请求，先拆除全部暴露面")
		a.teardownAll()
		a.mu.Lock()
		a.applied, a.desired = "OFF", "OFF"
		a.warnings = nil
		a.mu.Unlock()
		a.persistState()
		a.aud.Write(audit.Entry{
			Source: "ctlapi", Action: "quit", Result: "ok",
			Detail: "退出前已关闭 WebDAV / SMB / DLNA 与防火墙规则",
		})
		if a.ctlAPI != nil {
			a.ctlAPI.Broadcast(a.Status())
		}
		a.log.Info("暴露面已全部关闭，准备退出")
		close(a.quitCh)
	})
}

// ---------- 控制面 ----------

func (a *App) startControl() error {
	token, err := a.loadToken()
	if err != nil {
		return err
	}
	a.ctlAPI = ctlapi.New(ctlapi.Options{
		Core:         a,
		Token:        token,
		Bind:         a.cfg.UI.Bind,
		Log:          a.log,
		WebUI:        webui.FS,
		AllowedHosts: a.cfg.UI.AllowedHosts,
		// 控制台的人工登录用共享账号，不再让人去服务器上找 token。
		Accounts:    a.CheckAccount,
		SessionFile: filepath.Join(a.cfg.DataDir, "ui-sessions.json"),
	})
	ln, err := net.Listen("tcp", a.cfg.UI.Bind)
	if err != nil {
		return fmt.Errorf("控制面监听 %s 失败: %w", a.cfg.UI.Bind, err)
	}
	srv := &http.Server{Handler: a.ctlAPI.Handler(), ReadHeaderTimeout: 10 * time.Second}
	a.srvMu.Lock()
	a.ctlLn, a.ctlSrv = ln, srv
	a.srvMu.Unlock()
	go srv.Serve(ln)
	a.log.Info("控制台已启动", "addr", a.cfg.UI.Bind, "allowed_hosts", a.cfg.UI.AllowedHosts)
	// 绑 0.0.0.0 时直接把 0.0.0.0 打进 URL 是点不开的，换成真实网卡地址。
	fmt.Printf("\n  控制台: http://%s/#%s\n\n", ctlapi.Advertise(a.cfg.UI.Bind), token)
	return nil
}

// loadToken 读取或生成控制面 token。前端从 URL fragment 取，不进 Referer 与服务端日志。
func (a *App) loadToken() (string, error) {
	p := filepath.Join(a.cfg.DataDir, "control.token")
	raw, err := os.ReadFile(p)
	if err == nil {
		if t := strings.TrimSpace(string(raw)); len(t) >= 16 {
			return t, nil
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	t := hex.EncodeToString(buf)
	if err := os.WriteFile(p, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

func (a *App) Token() string {
	t, _ := a.loadToken()
	return t
}

// ---------- 开关状态机 ----------

func validState(s string) bool {
	switch s {
	case "OFF", "LAN", "WAN", "ALL":
		return true
	}
	return false
}

func (a *App) Switch(ctx context.Context, target string) (string, error) {
	target = strings.ToUpper(strings.TrimSpace(target))
	if !validState(target) {
		return "", fmt.Errorf("状态只能是 OFF/LAN/WAN/ALL，收到 %q", target)
	}
	op := &ctlapi.Operation{
		ID:        newID(),
		Target:    target,
		Stage:     "queued",
		StartedAt: time.Now(),
	}
	a.opsMu.Lock()
	a.ops[op.ID] = op
	a.opsMu.Unlock()

	a.mu.Lock()
	a.desired = target
	a.mu.Unlock()

	go a.apply(op, target)
	return op.ID, nil
}

func (a *App) setStage(op *ctlapi.Operation, stage string) {
	a.opsMu.Lock()
	op.Stage = stage
	a.opsMu.Unlock()
	if a.ctlAPI != nil {
		a.ctlAPI.Broadcast(a.Status())
	}
}

func (a *App) addWarning(msg string) {
	a.mu.Lock()
	a.warnings = append(a.warnings, msg)
	a.mu.Unlock()
	a.log.Warn(msg)
}

func (a *App) fail(op *ctlapi.Operation, stage string, err error) {
	a.opsMu.Lock()
	op.Stage = stage
	op.Error = err.Error()
	op.Done = true
	a.opsMu.Unlock()

	a.mu.Lock()
	a.lastError = err.Error()
	a.mu.Unlock()

	// 失败必须回落到 OFF，不允许停在中间态。
	a.teardownAll()
	a.mu.Lock()
	a.applied = "OFF"
	a.warnings = nil
	a.mu.Unlock()
	a.persistState()

	a.aud.Write(audit.Entry{Source: "ctlapi", Action: "switch " + op.Target, Result: "error", Detail: err.Error()})
	if a.ctlAPI != nil {
		a.ctlAPI.Broadcast(a.Status())
	}
}

func (a *App) apply(op *ctlapi.Operation, target string) {
	a.mu.Lock()
	a.warnings = nil
	a.lastError = ""
	a.mu.Unlock()

	// 从中间态切到别的状态：先全部拆干净，再按目标拉起，避免残留。
	if target == "OFF" {
		a.setStage(op, "teardown")
		a.teardownAll()
		a.mu.Lock()
		a.applied, a.smbState, a.smbNote, a.smbAuth = "OFF", "", "", ""
		a.mu.Unlock()
		a.finish(op)
		return
	}

	// 1) 防火墙规则
	a.setStage(op, "firewall")
	rules := platform.FirewallRules(target, a.syncFirewallRules()...)
	if len(rules) > 0 {
		if a.dry {
			a.addWarning("dry-run：跳过防火墙规则变更")
		} else if a.admin {
			if err := platform.RemoveByPrefix("FSGW-"); err != nil {
				a.addWarning("清理旧防火墙规则失败: " + err.Error())
			}
			if err := platform.EnsureRules(rules); err != nil {
				a.fail(op, "firewall", err)
				return
			}
		} else {
			a.addWarning("未以管理员运行，防火墙规则未变更（局域网设备可能连不上）")
		}
	}

	// 2) 监听
	a.setStage(op, "listener")
	if target == "LAN" || target == "ALL" {
		// SMB 与 DLNA 是两个独立面，不能互相拖累：
		//   SMB  要管理员（net share + 445 放行）
		//   DLNA 只是 HTTP/SSDP，任何权限都能跑
		// 所以 SMB 失败只降级为警告，并把原因写进 smbState，绝不整体回退——
		// 否则电视连发现都做不到。但也不能静默：界面必须显式说明哪一项没就绪。
		if err := a.startSMB(op); err != nil {
			hint := ""
			if !a.admin {
				hint = "；要用网络邻居方式访问，请用管理员身份运行 fsgw（或用 fsgw.exe 启动并同意提权）"
			}
			a.addWarning("SMB 共享未创建：" + err.Error() + hint + "。DLNA 与快同步仍可用。")
		}
		if err := a.startDLNA(); err != nil {
			a.fail(op, "listener", err)
			return
		}
		// 快同步也是局域网面的一部分：它是能覆盖文件的写通道，
		// 不能脱离"关闭即零暴露"的开关单独常驻。
		if err := a.startSync(); err != nil {
			a.addWarning("快同步服务未启动：" + err.Error())
		}
	} else {
		a.stopDLNA()
		a.stopSync()
	}
	if target == "WAN" || target == "ALL" {
		if err := a.startWebDAV(); err != nil {
			a.fail(op, "listener", err)
			return
		}
	} else {
		a.stopWebDAV()
	}

	// 3) 自检
	a.setStage(op, "selfcheck")
	if target == "WAN" || target == "ALL" {
		if err := probe(a.cfg.WebDAV.Bind); err != nil {
			a.fail(op, "selfcheck", fmt.Errorf("WebDAV 自检失败: %w", err))
			return
		}
	}

	a.mu.Lock()
	a.applied = target
	a.mu.Unlock()
	a.finish(op)
}

func (a *App) finish(op *ctlapi.Operation) {
	a.opsMu.Lock()
	op.Stage = "done"
	op.Done = true
	a.opsMu.Unlock()
	a.persistState()

	a.aud.Write(audit.Entry{Source: "ctlapi", Action: "switch " + op.Target, Result: "ok", Detail: "applied=" + op.Target})
	if a.ctlAPI != nil {
		a.ctlAPI.Broadcast(a.Status())
	}
	a.log.Info("开关切换完成", "state", op.Target)
}

// guestMode 判断配置是否要求免密（来宾）登录。
// both 与 guest 在系统层面没有区别：ForceGuest 是整机开关，
// 打开后所有网络登录都映射为 Guest，"两种方式并存"在 Windows 上不存在。
func (a *App) guestMode() bool {
	switch strings.ToLower(strings.TrimSpace(a.cfg.SMB.Auth)) {
	case "guest", "both":
		return true
	}
	return false
}

func (a *App) guestBackupPath() string {
	return filepath.Join(a.cfg.DataDir, "smb_guest_backup.json")
}

// guestACLMark 记录"哪个目录的免密授权已经做完"。
// 不靠"根目录 DACL 里有没有 Everyone"来判断：大目录的继承传播要跑几分钟，
// 中途被打断时根目录已经有 ACE、子对象却还没收到，只看根会把半成品当成完成。
type guestACLMark struct {
	Root     string `json:"root"`
	Writable bool   `json:"writable"`
}

func (a *App) guestACLMarkPath() string {
	return filepath.Join(a.cfg.DataDir, "guest_acl.json")
}

func (a *App) guestACLDone(root string, writable bool) bool {
	raw, err := os.ReadFile(a.guestACLMarkPath())
	if err != nil {
		return false
	}
	var m guestACLMark
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	return m.Writable == writable && samePath(m.Root, root)
}

func (a *App) markGuestACLDone(root string, writable bool) {
	raw, _ := json.MarshalIndent(guestACLMark{Root: root, Writable: writable}, "", "  ")
	if err := os.WriteFile(a.guestACLMarkPath(), raw, 0o644); err != nil {
		a.log.Warn("记录免密授权状态失败（下次会重做一遍授权）", "err", err)
	}
}

// clearGuestACLDone 在关闭免密或换目录时清标记，避免下次误判"已经好了"。
func (a *App) clearGuestACLDone() {
	_ = os.Remove(a.guestACLMarkPath())
}

// guestACLTarget 是一次待做的目录授权。
type guestACLTarget struct {
	Root     string
	Writable bool
}

// ensureGuestACL 在后台给共享根授权，不挡在开关切换的同步路径上。
//
// 为什么要异步：Windows 要把 Everyone 的可继承 ACE 逐个传播到子对象。
// desk88 那种五十多万文件的目录，实测同步跑要好几分钟，接口早就超时了，
// 界面上看到的就是"点了开关一直转圈"。共享本体此时其实已经起来了
// （账号口令可以进），所以先把面起来，权限在后台补更合理。
func (a *App) ensureGuestACL(root string, writable bool) {
	if root == "" || a.dry || !a.guestMode() {
		return
	}
	if a.guestACLDone(root, writable) {
		return
	}
	a.mu.Lock()
	if a.guestACLBusy != "" {
		// 正在给别的目录授权（多半是用户连着换了两次）。记下来，
		// 等当前这轮跑完再接着做，不能直接丢掉。后来的覆盖先来的，
		// 因为用户最后选的那个才作数。
		if !samePath(a.guestACLBusy, root) {
			a.guestACLPending = guestACLTarget{Root: root, Writable: writable}
		}
		a.mu.Unlock()
		return
	}
	a.guestACLBusy = root
	a.mu.Unlock()

	if a.ctlAPI != nil {
		a.ctlAPI.Broadcast(a.Status())
	}
	a.log.Info("开始后台设置免密目录权限（大目录需要几分钟）", "root", root, "writable", writable)

	go func() {
		err := smbhost.EnsureRootAccess(root, writable)

		a.mu.Lock()
		a.guestACLBusy = ""
		next := a.guestACLPending
		a.guestACLPending = guestACLTarget{}
		a.mu.Unlock()

		if err != nil {
			a.log.Error("免密目录授权失败", "root", root, "err", err)
			a.aud.Write(audit.Entry{Source: "smb", Action: "guest acl", Result: "error",
				Detail: root + ": " + err.Error()})
			a.addWarning("免密目录授权失败：" + err.Error())
		} else {
			a.markGuestACLDone(root, writable)
			a.log.Info("免密目录权限已就绪", "root", root, "writable", writable)
			a.aud.Write(audit.Entry{Source: "smb", Action: "guest acl", Result: "ok", Detail: root})
		}
		if a.ctlAPI != nil {
			a.ctlAPI.Broadcast(a.Status())
		}
		if next.Root != "" {
			a.ensureGuestACL(next.Root, next.Writable)
		}
	}()
}

// applyGuest 打开免密：启用 Guest、切来宾模式、给 Everyone 授 NTFS 权限。
// 备份只在第一次写入——进程被强杀后重启会走这里，此时系统已经在免密态，
// 若再存一次备份，"最初的样子"就丢了，退出时还原不回去。
func (a *App) applyGuest(root string, writable bool) error {
	// 自研服务端的免密是进程内的认证策略：不过校验证书就按 Guest 放行，
	// 顺便按 guest_writable 决定写不看。它一个系统开关都不动，
	// 所以既不需要备份"改动前状态"，也不会把整机切进来宾模式。
	if !smbhost.GuestBySystem() {
		if _, err := smbhost.Enable(root, writable); err != nil {
			return fmt.Errorf("设置免密访问失败: %w", err)
		}
		a.log.Info("SMB 免密模式已生效（自研服务端，未改动任何系统设置）", "writable", writable)
		a.aud.Write(audit.Entry{
			Source: "smb", Action: "guest on", Result: "ok",
			Detail: fmt.Sprintf("engine=%s / Guest 放行 / %s", smbhost.Engine(),
				map[bool]string{true: "可读写", false: "只读"}[writable]),
		})
		return nil
	}
	if _, err := os.Stat(a.guestBackupPath()); err == nil {
		a.log.Info("检测到未还原的免密备份，复用原备份（上次可能被强制结束）")
		// 备份复用意味着不会重跑 Enable，但「登录类型」那两道门可能已经被
		// 系统策略刷新回去了（例如重启、组策略刷新），必须再确保一次。
		if err := smbhost.EnsureGuestLogon(); err != nil {
			return fmt.Errorf("重新确认 Guest 网络登录失败: %w", err)
		}
		// 同理，NTFS 授权是按目录打的：换了共享根、或上次进程在授权前
		// 就被强杀，新根上就没有 Everyone，Guest 能登录却连目录都列不出来。
		// 这里每次都按当前根重新确认一次（后台跑，见 ensureGuestACL）。
		a.ensureGuestACL(root, writable)
		return nil
	}
	bk, err := smbhost.Enable(root, writable)
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(bk, "", "  ")
	if err := os.WriteFile(a.guestBackupPath(), raw, 0o644); err != nil {
		return fmt.Errorf("记录免密前状态失败: %w", err)
	}
	a.log.Info("SMB 免密模式已开启",
		"guest_active_before", bk.GuestActive, "force_guest_before", bk.ForceGuest,
		"writable", writable)
	a.aud.Write(audit.Entry{
		Source: "smb", Action: "guest on", Result: "ok",
		Detail: fmt.Sprintf("Guest 启用 / ForceGuest=1 / Everyone %s（后台授权）", map[bool]string{true: "可读写", false: "只读"}[writable]),
	})
	// 目录授权单独走后台：开关的响应时间不能被"传播五十万条 ACL"绑架。
	a.ensureGuestACL(root, writable)
	return nil
}

// restoreGuest 还原免密改过的系统设置。没开过免密就直接返回。
func (a *App) restoreGuest() {
	p := a.guestBackupPath()
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var bk smbhost.Backup
	if err := json.Unmarshal(raw, &bk); err != nil {
		a.log.Warn("免密备份文件损坏，跳过还原", "err", err)
		return
	}
	root := ""
	if len(a.cfg.Shares) > 0 {
		root = a.cfg.Shares[0].Root
	}
	if err := smbhost.Restore(root, bk); err != nil {
		// 保留备份文件，下次启动还能再试一次
		a.log.Warn("还原免密相关系统设置失败，备份已保留", "err", err)
		return
	}
	os.Remove(p)
	// 撤销 Everyone 授权要传播整棵子树，大目录上要跑几分钟。
	// 关闭开关和退出程序都不能被它拖住，所以放后台；即便进程先退出，
	// 最坏结果也只是"权限没收回"，不会多给谁权限。
	if !bk.EveryoneHadAccess && root != "" {
		go func(dir string) {
			if err := smbhost.RevokeRootAccess(dir); err != nil {
				a.log.Warn("撤销免密目录的 Everyone 授权失败", "root", dir, "err", err)
			} else {
				a.log.Info("已撤销免密目录的 Everyone 授权", "root", dir)
			}
		}(root)
	}
	a.clearGuestACLDone()
	a.log.Info("已还原 SMB 免密相关系统设置",
		"guest_active", bk.GuestActive, "force_guest", bk.ForceGuest)
	a.aud.Write(audit.Entry{Source: "smb", Action: "guest off", Result: "ok", Detail: "已还原 Guest / ForceGuest / NTFS 授权"})
}

func (a *App) startSMB(op *ctlapi.Operation) error {
	cfgShare := a.cfg.Shares[0]
	if a.dry {
		a.mu.Lock()
		a.smbState, a.smbNote = "dry-run", "selftest 跳过真实共享创建"
		a.mu.Unlock()
		return nil
	}
	if !a.cfg.SMB.Enabled {
		a.mu.Lock()
		a.smbState, a.smbNote = "disabled", "配置中已关闭 SMB"
		a.mu.Unlock()
		return nil
	}
	if !a.admin {
		a.mu.Lock()
		a.smbState, a.smbNote = "skipped", "需要管理员权限创建共享"
		a.mu.Unlock()
		return fmt.Errorf("创建 SMB 共享需要管理员权限")
	}
	// 引擎要在创建共享之前定下来：go 引擎要先让 LanmanServer 让出 445，
	// native 引擎则不动系统服务。备份文件放在数据目录，换引擎时好还原。
	if err := smbhost.SetEngine(a.cfg.SMB.Engine, a.cfg.DataDir); err != nil {
		a.mu.Lock()
		a.smbState, a.smbNote = "error", err.Error()
		a.mu.Unlock()
		return err
	}
	// 账号表要在启动前配好：纯 Go 服务端要拿它做 NTLM 校验，
	// 否则 Win11（强制签名）进来的会话既没口令也没密钥，只能被拒。
	smbhost.SetAccounts(a.smbAccountList())
	// 接入端人工指定表同理：连接建立时读一次，决定补哪套兼容处理。
	smbhost.SetClientHints(a.smbClientHints())
	// mac 影子文件（.DS_Store / ._xxx）默认在列目录里藏掉，见 applemeta.go。
	smbhost.SetAppleMeta(a.smbAppleMeta())
	// 纯 SMB1 客户端（小米电视等）的兜底后端，见 config.SMB.SMB1Backend。
	smbhost.SetSMB1Backend(a.cfg.SMB.SMB1Backend)
	if err := smbhost.EnsureShare(cfgShare.Name, cfgShare.Root, cfgShare.Writable); err != nil {
		a.mu.Lock()
		a.smbState, a.smbNote = "error", err.Error()
		a.mu.Unlock()
		return fmt.Errorf("创建 SMB 共享: %w", err)
	}
	// 免密模式：共享建好只是第一步，还得让"不带凭据来的设备"能映射到 Guest。
	// 这三件事（启用 Guest / ForceGuest=1 / NTFS 给 Everyone）任何一步没做成都连不上，
	// 所以失败必须如实报出来，不能只留个"已就绪"骗人。
	note := "\\\\" + "本机" + "\\" + cfgShare.Name
	// 回退到系统共享时说明白原因：用户会问"为什么不是自研服务端"。
	if r := smbhost.FallbackReason(); r != "" {
		note += "（系统共享）"
		a.log.Warn("SMB 已回退系统共享", "reason", r)
		a.addWarning("SMB 用系统共享提供服务：" + r + "。需要账号口令访问；免密要看系统来宾模式是否可用。")
	}
	auth := "需账户口令"
	var guestErr error
	if a.guestMode() {
		if err := a.applyGuest(cfgShare.Root, a.cfg.SMB.GuestWritable); err != nil {
			// 共享本身已经能用了（账号口令可访问），免密没生效不该把整个面标成失败，
			// 否则界面上只看到"创建失败"，用户会以为共享根本没起来。
			guestErr = err
		} else if a.cfg.SMB.GuestWritable {
			auth = "免密可读写"
		} else {
			auth = "免密只读"
		}
	}
	a.mu.Lock()
	a.smbState, a.smbNote, a.smbAuth = "ready", note, auth
	if guestErr != nil {
		a.smbNote = note + " · 免密未生效：" + guestErr.Error()
	}
	a.mu.Unlock()
	if guestErr != nil {
		a.log.Warn("SMB 免密模式未生效，共享仍可凭账号口令访问", "err", guestErr)
		a.addWarning("SMB 免密未生效：" + guestErr.Error() + "。共享已就绪，可用账号口令访问。")
	}
	return nil
}

// ---------- SMB 客户端账号 ----------

// smbAppleMeta 把 apple_meta 配置规范成 hide / all / off 三选一。
//
// 留空或写错一律按 hide：老配置里没有这一项，升级上来就该默认生效，
// 而不是让用户先去补一行 yaml 才发现"怎么还是满屏 ._xxx"。
func (a *App) smbAppleMeta() string {
	switch v := strings.ToLower(strings.TrimSpace(a.cfg.SMB.AppleMeta)); v {
	case "off", "all":
		return v
	default:
		return "hide"
	}
}

// smbClientHints 把配置里的接入端人工指定项转成服务端要的格式。
//
// 只做清洗不做校验报错：kind 写错不该让整个 SMB 面起不来（那等于为了一个
// 提示把共享弄没了），忽略掉并在日志里说一声，用户看到的是"提示没生效"
// 而不是"共享打不开"。
func (a *App) smbClientHints() []smbhost.ClientHint {
	list := a.cfg.SMB.ClientHints
	if len(list) == 0 {
		return nil
	}
	out := make([]smbhost.ClientHint, 0, len(list))
	for _, h := range list {
		ip := strings.TrimSpace(h.IP)
		kind := strings.ToLower(strings.TrimSpace(h.Kind))
		if ip == "" || kind == "" {
			continue
		}
		out = append(out, smbhost.ClientHint{IP: ip, Kind: smbhost.ClientKind(kind)})
	}
	return out
}

// smbAccountList 汇总"允许登录的账号表"，两个来源：
//   - config.yaml 里的单账号写法（account_name / password / nt_hash），兼容老配置；
//   - smb_clients.yaml 里由控制台登记的客户端账号。
//
// 同名以客户端账号表为准（后加入的覆盖先加入的），这样在面板里改口令能生效。
func (a *App) smbAccountList() []smbgo.Account {
	var out []smbgo.Account
	seen := make(map[string]int)

	add := func(name string, hash []byte, override bool) {
		name = strings.TrimSpace(name)
		if name == "" || len(hash) == 0 {
			return
		}
		k := strings.ToLower(name)
		if i, ok := seen[k]; ok {
			if override {
				out[i].NTHash = hash
			}
			return
		}
		seen[k] = len(out)
		out = append(out, smbgo.Account{Name: name, NTHash: hash})
	}

	if a.cfg.SMB.Account != "" {
		if h, ok := smbgo.ParseNTHash(a.cfg.SMB.NTHash); ok {
			add(a.cfg.SMB.Account, h, false)
		} else if a.cfg.SMB.Password != "" {
			add(a.cfg.SMB.Account, smbgo.NTHashBytes(a.cfg.SMB.Password), false)
		}
	}
	clients, err := config.LoadClients(a.cfg.Path)
	if err != nil {
		if a.log != nil {
			a.log.Warn("读取 SMB 客户端账号表失败", "err", err)
		}
	}
	for _, c := range clients {
		if h, ok := smbgo.ParseNTHash(c.NTHash); ok {
			add(c.Name, h, true)
		}
	}
	return out
}

// SMBAuth 返回面板要展示的一组数据：登记过的账号、在线连接、最近的登录尝试。
func (a *App) SMBAuth() ctlapi.SMBAuth {
	info := ctlapi.SMBAuth{
		Path:     config.ClientsPath(a.cfg.Path),
		Sessions: smbgo.Sessions(),
		Attempts: smbgo.Attempts(),
	}
	if a.cfg.SMB.Account != "" {
		info.Accounts = append(info.Accounts, ctlapi.SMBAccount{
			Name: a.cfg.SMB.Account, Note: "config.yaml 中配置", Source: "config",
		})
	}
	clients, err := config.LoadClients(a.cfg.Path)
	if err != nil && a.log != nil {
		a.log.Warn("读取 SMB 客户端账号表失败", "err", err)
	}
	seen := make(map[string]bool)
	for _, c := range clients {
		seen[strings.ToLower(c.Name)] = true
		info.Accounts = append(info.Accounts, ctlapi.SMBAccount{
			Name: c.Name, Note: c.Note, AddedAt: c.AddedAt, Source: "console",
		})
	}
	// config.yaml 里的账号若已被同名客户端账号覆盖，就别重复列一行。
	if a.cfg.SMB.Account != "" && seen[strings.ToLower(a.cfg.SMB.Account)] {
		info.Accounts = info.Accounts[1:]
	}
	return info
}

// AddSMBClient 登记（或更新）一个客户端账号：写盘 + 让 445 立即按新表工作。
//
// 口令在这一层就转成 NT 哈希，明文不落盘、不写日志。
func (a *App) AddSMBClient(name, pass, note string) error {
	name = strings.TrimSpace(name)
	note = strings.TrimSpace(note)
	if name == "" {
		return fmt.Errorf("客户名不能为空")
	}
	if len([]rune(name)) > 64 {
		return fmt.Errorf("客户名最长 64 字")
	}
	if strings.ContainsAny(name, " \t/:\\") {
		return fmt.Errorf("客户名不能含空格与 / : \\")
	}
	if len(pass) < 4 {
		return fmt.Errorf("口令至少 4 位")
	}

	list, err := config.LoadClients(a.cfg.Path)
	if err != nil {
		return err
	}
	hash := smbgo.NTHashHex(pass)
	found := false
	for i := range list {
		if strings.EqualFold(list[i].Name, name) {
			list[i].NTHash = hash
			if note != "" {
				list[i].Note = note
			}
			found = true
			break
		}
	}
	if !found {
		list = append(list, config.SMBClient{
			Name: name, NTHash: hash, Note: note,
			AddedAt: time.Now().Format(time.RFC3339),
		})
	}
	if err := config.SaveClients(a.cfg.Path, list); err != nil {
		return fmt.Errorf("保存账号表: %w", err)
	}
	a.reloadSMBAccounts()
	if a.log != nil {
		a.log.Info("已登记 SMB 客户端账号", "user", name, "updated", found)
	}
	return nil
}

// RemoveSMBClient 删掉一个登记的客户端账号。config.yaml 里的账号不在这里删
// （那是手工配置，面板不该去改它），只在提示里说明。
func (a *App) RemoveSMBClient(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("客户名不能为空")
	}
	list, err := config.LoadClients(a.cfg.Path)
	if err != nil {
		return err
	}
	out := list[:0]
	removed := false
	for _, c := range list {
		if strings.EqualFold(c.Name, name) {
			removed = true
			continue
		}
		out = append(out, c)
	}
	if !removed {
		return fmt.Errorf("账号表里没有 %q（config.yaml 里配置的账号请在配置文件里改）", name)
	}
	if err := config.SaveClients(a.cfg.Path, out); err != nil {
		return fmt.Errorf("保存账号表: %w", err)
	}
	a.reloadSMBAccounts()
	if a.log != nil {
		a.log.Info("已移除 SMB 客户端账号", "user", name)
	}
	return nil
}

// reloadSMBAccounts 让运行中的 445 服务按新账号表重启。
// 服务没在跑时只更新"下次启动要用"的表，不能顺手把它拉起来——
// 总开关处于 OFF 时拉起监听，等于绕过了用户的关闭意图。
func (a *App) reloadSMBAccounts() {
	smbhost.SetAccounts(a.smbAccountList())
	smbhost.SetClientHints(a.smbClientHints())
	smbhost.SetAppleMeta(a.smbAppleMeta())
	// 纯 SMB1 客户端（小米电视等）的兜底后端，见 config.SMB.SMB1Backend。
	smbhost.SetSMB1Backend(a.cfg.SMB.SMB1Backend)
	if len(a.cfg.Shares) == 0 {
		return
	}
	share := a.cfg.Shares[0]
	if !smbhost.Exists(share.Name) {
		return
	}
	if err := smbhost.EnsureShare(share.Name, share.Root, share.Writable); err != nil && a.log != nil {
		a.log.Error("SMB 账号表已更新，但服务重启失败", "err", err)
	}
}

func (a *App) startWebDAV() error {
	if !a.cfg.WebDAV.Enabled {
		return nil
	}
	a.srvMu.Lock()
	defer a.srvMu.Unlock()
	if a.wdSrv != nil {
		return nil
	}
	wd := webdav.New(webdav.Options{
		VFS:      a.vfs,
		Store:    a.store,
		Log:      a.log,
		Audit:    a.aud,
		User:     a.cfg.WebDAV.Username,
		Password: a.cfg.WebDAV.Password,
		Hash:     a.cfg.WebDAV.PasswordHash,
		Creds:    webdavCreds(a.cfg.WebDAV.Users),
		Writable: map[string]bool{},
	})
	ln, err := net.Listen("tcp", a.cfg.WebDAV.Bind)
	if err != nil {
		return fmt.Errorf("WebDAV 监听 %s 失败: %w", a.cfg.WebDAV.Bind, err)
	}
	srv := &http.Server{Handler: wd.Handler(), ReadHeaderTimeout: 15 * time.Second}
	a.wdLn, a.wdSrv = ln, srv
	go srv.Serve(ln)
	a.log.Info("WebDAV 已启动", "addr", a.cfg.WebDAV.Bind)
	return nil
}

// webdavCreds 把配置里的 users 列表转成 webdav 的账号结构。
func webdavCreds(us []config.WebDAVUser) []webdav.Cred {
	out := make([]webdav.Cred, 0, len(us))
	for _, u := range us {
		out = append(out, webdav.Cred{User: u.Username, Password: u.Password, Hash: u.PasswordHash})
	}
	return out
}

func (a *App) stopWebDAV() {
	a.srvMu.Lock()
	defer a.srvMu.Unlock()
	if a.wdSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	a.wdSrv.Shutdown(ctx)
	cancel()
	a.wdSrv, a.wdLn = nil, nil
	a.log.Info("WebDAV 已停止")
}

// SetDLNAFriendlyName 改电视/手机里显示的设备名。
//
// 名字是 SSDP 宣告的一部分，改完必须让 DLNA 面重启一轮：
// 光改配置文件不行（内存里还是旧的），光改内存也不行（重启后又变回去）。
// 重启时会先发 byebye 再发 alive，客户端才会把旧名字换掉，否则它会一直
// 显示缓存里的老条目。
func (a *App) SetDLNAFriendlyName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("设备名不能为空")
	}
	if n := utf8.RuneCountInString(name); n > 32 {
		return fmt.Errorf("设备名最长 32 个字符，现在 %d 个", n)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("设备名不能包含控制字符")
		}
	}

	a.mu.RLock()
	old := a.cfg.DLNA.FriendlyName
	a.mu.RUnlock()
	if old == name {
		return nil
	}

	// 先写盘再改内存：写失败就直接不动，避免"界面改了、重启又变回去"。
	if err := a.cfg.SaveDLNAFriendlyName(a.cfg.Path, name); err != nil {
		return fmt.Errorf("写配置失败: %w", err)
	}

	a.mu.Lock()
	a.cfg.DLNA.FriendlyName = name
	a.mu.Unlock()

	// 只有 DLNA 面真起来了才需要重启；OFF 状态下改名字，下次开就生效。
	a.srvMu.Lock()
	up := a.dlnaSrv != nil
	a.srvMu.Unlock()
	if up {
		a.stopDLNA()
		if err := a.startDLNA(); err != nil {
			return fmt.Errorf("设备名已保存，但 DLNA 重启失败（重启程序后生效）: %w", err)
		}
	}

	a.aud.Write(audit.Entry{
		Source: "ctlapi", Action: "dlna name", Result: "ok", Detail: old + " -> " + name,
	})
	a.log.Info("DLNA 设备名已修改", "old", old, "new", name)
	return nil
}

func (a *App) startDLNA() error {
	if !a.cfg.DLNA.Enabled {
		return nil
	}
	// dry-run 只跳过"改整机状态"的操作（防火墙、net share）。
	// DLNA 只是进程内监听端口，selftest 需要真跑起来才测得到。
	a.srvMu.Lock()
	defer a.srvMu.Unlock()
	if a.dlnaSrv != nil {
		return nil
	}
	srv := dlna.New(dlna.Options{
		Config: dlna.Config{
			FriendlyName: a.cfg.DLNA.FriendlyName,
			Port:         a.cfg.DLNA.HTTPPort,
		},
		// 设备 UUID 落在这里，保证多台机器各用各的（否则电视按 UUID 去重，
		// 只会看见其中一台，另一台怎么刷新都不出现）。
		DataDir: a.cfg.DataDir,
		VFS:     a.vfs,
		Store:   a.store,
		Log:     a.log,
		Audit:   a.aud,
	})
	if err := srv.Start(); err != nil {
		return fmt.Errorf("DLNA: %w", err)
	}
	a.dlnaSrv = srv
	return nil
}

func (a *App) stopDLNA() {
	a.srvMu.Lock()
	defer a.srvMu.Unlock()
	if a.dlnaSrv == nil {
		return
	}
	a.dlnaSrv.Stop()
	a.dlnaSrv = nil
	a.log.Info("DLNA 已停止")
}

func (a *App) teardownAll() {
	a.stopWebDAV()
	a.stopDLNA()
	a.stopSync()
	if a.dry {
		a.mu.Lock()
		a.smbState, a.smbNote, a.smbAuth = "", "", ""
		a.mu.Unlock()
		return
	}
	if a.admin && a.cfg.SMB.Enabled {
		if err := smbhost.RemoveShare(a.cfg.Shares[0].Name); err != nil {
			a.log.Warn("移除 SMB 共享失败", "err", err)
		}
	}
	if a.admin {
		if err := platform.RemoveByPrefix("FSGW-"); err != nil {
			a.log.Warn("清理防火墙规则失败", "err", err)
		}
		// 免密模式改的是整机策略（Guest 账户、ForceGuest、NTFS 授权），
		// 进程退出后这些不会自己回去，必须显式还原，否则"关了"也只是关了共享。
		a.restoreGuest()
	}
	a.mu.Lock()
	a.smbState, a.smbNote, a.smbAuth = "", "", ""
	a.mu.Unlock()
}

func probe(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// ---------- 状态持久化 ----------

type stateFile struct {
	DesiredState string `json:"desired_state"`
	AppliedState string `json:"applied_state"`
	LastError    string `json:"last_error"`
}

func (a *App) persistState() error {
	a.mu.RLock()
	st := stateFile{DesiredState: a.desired, AppliedState: a.applied, LastError: a.lastError}
	a.mu.RUnlock()
	raw, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(filepath.Join(a.cfg.DataDir, "state.json"), raw, 0o644)
}

// ---------- ctlapi.Core 实现 ----------

func (a *App) Status() ctlapi.Status {
	a.mu.RLock()
	applied := a.applied
	desired := a.desired
	lastErr := a.lastError
	smbState, smbNote, smbAuth := a.smbState, a.smbNote, a.smbAuth
	aclBusy := a.guestACLBusy
	a.mu.RUnlock()

	st := ctlapi.Status{
		State:         applied,
		Desired:       desired,
		LastError:     lastErr,
		Version:       Version,
		UptimeSeconds: int64(time.Since(a.start).Seconds()),
		Admin:         a.admin,
	}

	// 面板的「SMB 客户端」一栏：登记了谁、谁在线、最近谁被拒。
	st.SMBAuth = a.SMBAuth()

	a.mu.RLock()
	for _, s := range a.cfg.Shares {
		st.Shares = append(st.Shares, ctlapi.ShareInfo{
			ShareID: s.ShareID, Name: s.Name, Root: s.Root,
			Writable: s.Writable, Media: s.Media,
			Rebuilding: a.rebuilding[s.ShareID],
		})
	}
	a.mu.RUnlock()

	lanOn := applied == "LAN" || applied == "ALL"
	wanOn := applied == "WAN" || applied == "ALL"

	a.srvMu.Lock()
	wdUp := a.wdSrv != nil
	dlnaUp := a.dlnaSrv != nil
	dlnaAddr := ""
	dlnaSSDP := false
	if dlnaUp {
		dlnaAddr = a.dlnaSrv.LANAddr()
		dlnaSSDP = a.dlnaSrv.SSDPActive()
	}
	a.srvMu.Unlock()

	dlnaNote := "未启动"
	switch {
	case !a.cfg.DLNA.Enabled:
		dlnaNote = "配置中已关闭"
	case !lanOn:
		dlnaNote = "需开启局域网面"
	case !dlnaUp:
		dlnaNote = "启动失败，详见日志"
	case !dlnaSSDP:
		// HTTP 通了但 SSDP 没起来，电视搜不到设备。这种状态最坑：
		// 界面上"已开启"，实际发现不了，必须显式告警。
		dlnaNote = "HTTP 就绪，但 SSDP 未启动（电视无法自动发现，可手动填地址）"
	default:
		dlnaNote = "已广播，电视可自动发现"
	}

	// SMB 的 note 用中文短句，别把内部状态词（skipped/ready）直接抛给用户看。
	smbStatusText := "未启用"
	smbAddr := ""
	switch smbState {
	case "ready":
		smbStatusText, smbAddr = "已就绪", smbNote
		if smbAuth != "" {
			smbStatusText += " · " + smbAuth
		}
		// 免密目录授权在后台跑，得让用户知道"这会儿免密还不通"，
		// 而不是以为又坏了。
		if aclBusy != "" {
			smbStatusText += " · 正在设置免密目录权限（目录大时要几分钟）"
		}
	case "skipped":
		smbStatusText = "需管理员权限，共享未创建"
	case "disabled":
		smbStatusText = "配置中已关闭"
	case "error":
		smbStatusText = "创建失败：" + smbNote
	case "dry-run":
		smbStatusText = "dry-run 跳过"
	}

	st.Listeners = append(st.Listeners,
		ctlapi.Listener{Name: "SMB", Enabled: lanOn && a.cfg.SMB.Enabled, Ready: smbState == "ready",
			Addr: smbAddr, Note: smbStatusText},
		ctlapi.Listener{Name: "DLNA", Enabled: lanOn && a.cfg.DLNA.Enabled, Ready: dlnaUp,
			Addr: dlnaAddr, Note: dlnaNote,
			// 设备名就是电视/手机里显示的那一行，做成可改的：
			// 同一局域网里有两台 fsgw 时，靠它区分谁是谁。
			Extra: &ctlapi.ListenerExtra{
				Label: "设备名", Value: a.cfg.DLNA.FriendlyName, Action: "dlna-name",
			}},
		ctlapi.Listener{Name: "WebDAV", Enabled: wanOn, Ready: wdUp,
			Addr: a.cfg.WebDAV.Bind, Note: "只读"},
	)
	syncAddr, syncReady, syncSessions, syncBytes := a.SyncInfo()
	syncNote := "未启动"
	switch {
	case !a.cfg.Sync.Enabled:
		syncNote = "配置中已关闭"
	case !lanOn:
		syncNote = "需开启局域网面"
	case !syncReady:
		syncNote = "启动失败，详见日志"
	default:
		syncNote = "分块并行 · 断点续传"
	}
	st.Listeners = append(st.Listeners, ctlapi.Listener{
		Name: "快同步", Enabled: lanOn && a.cfg.Sync.Enabled, Ready: syncReady,
		Addr: syncAddr, Note: syncNote,
	})
	st.Sync = ctlapi.SyncInfo{
		Enabled:  a.cfg.Sync.Enabled,
		Ready:    syncReady,
		Addr:     syncAddr,
		Token:    a.syncToken,
		Sessions: syncSessions,
		Bytes:    syncBytes,
		ChunkMB:  a.cfg.Sync.ChunkMB,
	}

	if stats, err := a.store.Stats(); err == nil {
		st.Index = ctlapi.IndexStats{
			Files: stats.Files, Dirs: stats.Dirs, Objects: stats.Objects,
			Versions: stats.Versions, PathHistory: stats.PathHistory,
			PendingMoves: stats.PendingMoves,
			Events:       a.ix.Events(),
			Queue:        a.ix.Queue(),
		}
		if !stats.LastReconcile.IsZero() {
			st.Index.LastReconcile = stats.LastReconcile.Format("2006-01-02 15:04:05")
		}
	}
	st.Snapshot = ctlapi.SnapshotStats{Enabled: a.cfg.Snapshot.Enabled, QuotaGB: a.cfg.Snapshot.QuotaGB}
	st.Security = ctlapi.SecurityInfo{
		WebDAVBind:  a.cfg.WebDAV.Bind,
		Username:    a.cfg.WebDAV.Username,
		PasswordSet: a.cfg.WebDAV.Password != "" || a.cfg.WebDAV.PasswordHash != "",
	}
	return st
}

// SetWebDAVCredentials 改外部只读面的账号口令。
// 只把哈希写进配置，明文不落盘、不回传前端（见 docs/01 11.4）。
func (a *App) SetWebDAVCredentials(user, pass string) error {
	user = strings.TrimSpace(user)
	if user == "" {
		return fmt.Errorf("用户名不能为空")
	}
	for _, r := range user {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == '-'
		if !ok {
			return fmt.Errorf("用户名只能包含字母、数字、. _ -，收到 %q", string(r))
		}
	}
	if len([]rune(pass)) < 6 {
		return fmt.Errorf("口令至少 6 位")
	}
	// 只算一次哈希：内存配置、落盘、重启后的监听都用同一个。
	hash := webdav.HashPassword(pass)

	a.mu.Lock()
	a.cfg.WebDAV.Username = user
	a.cfg.WebDAV.Password = ""
	a.cfg.WebDAV.PasswordHash = hash
	a.mu.Unlock()

	if err := a.cfg.SaveWebDAV(a.cfg.Path, user, hash); err != nil {
		return fmt.Errorf("写配置失败: %w", err)
	}

	// 监听已在跑的话，重启一次让新口令立刻生效。
	a.srvMu.Lock()
	running := a.wdSrv != nil
	a.srvMu.Unlock()
	if running {
		a.stopWebDAV()
		if err := a.startWebDAV(); err != nil {
			return fmt.Errorf("重启 WebDAV 失败: %w", err)
		}
	}

	a.aud.Write(audit.Entry{Source: "ctlapi", Action: "webdav credentials", Result: "ok", Detail: "user=" + user})
	a.log.Info("外部访问口令已更新", "user", user)
	return nil
}

// ---------- 共享目录 ----------

// SetShareRoot 把某个共享的根目录换掉，并让改动当场生效。
//
// 换根不是改一行配置那么简单，三件事必须一起做完，否则会留下"配置说 A、
// 索引里是 B、SMB 还开着 C"的分裂状态：
//  1. 落盘配置（保留注释），下次冷启动也对；
//  2. 停旧根的监听、清掉旧根的索引行（否则搜索会指向不存在的文件）；
//  3. 重启把根目录烘在自己状态里的对外面（SMB / DLNA / 快同步 / WebDAV）。
//
// 索引重建放在后台：几十万文件的目录要几分钟，不能把 HTTP 请求挂在那儿。
func (a *App) SetShareRoot(shareID, root string) (string, error) {
	root, err := a.ValidateShareRoot(shareID, root)
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	idx := -1
	for i := range a.cfg.Shares {
		if a.cfg.Shares[i].ShareID == shareID {
			idx = i
			break
		}
	}
	if idx < 0 {
		a.mu.Unlock()
		return "", fmt.Errorf("没有这个共享：%s", shareID)
	}
	old := a.cfg.Shares[idx].Root
	if samePath(old, root) {
		a.mu.Unlock()
		return old, nil
	}
	a.cfg.Shares[idx].Root = root
	shares := a.shareList()
	// vfs 是 WebDAV / DLNA 解析路径时用的那套根，必须换新的；
	// 下面重启这几个面时它们会重新取 a.vfs。
	a.vfs = vfs.New(shares)
	a.rebuilding[shareID] = true
	a.mu.Unlock()

	if err := a.cfg.SaveShareRoot(a.cfg.Path, shareID, root); err != nil {
		// 写盘失败就整体回滚：内存里换了、重启后又变回去，比直接报错更迷惑。
		a.mu.Lock()
		a.cfg.Shares[idx].Root = old
		delete(a.rebuilding, shareID)
		shares = a.shareList()
		a.vfs = vfs.New(shares)
		a.mu.Unlock()
		return "", fmt.Errorf("写配置失败: %w", err)
	}

	// 先断新事件的入口，再清旧账：反过来的话，清理过程中又冒出来的旧路径
	// 事件会往刚清空的表里补行。
	a.ix.StopShare(shareID)
	a.ix.ClearTimers()
	a.ix.UnregisterShare(shareID)

	// 对外面重启是同步的（几百毫秒），索引重建是异步的。
	a.rebuildIndex(shareID, root)
	for _, n := range a.restartFaces() {
		a.addWarning(n)
	}

	// 免密模式给目录打的 Everyone 是按路径来的：新根已经在上面的 restartFaces
	// 里重新授权，旧根还得主动摘掉，否则换出去的目录依旧对全网敞着。
	// 撤销要传播整棵子树（大目录几分钟），不能挡在这里，放后台做。
	if a.guestMode() && old != "" && !a.rootStillShared(old) {
		go func(dir string) {
			if err := smbhost.RevokeRootAccess(dir); err != nil {
				a.log.Warn("撤销旧共享目录的 Everyone 授权失败", "root", dir, "err", err)
			} else {
				a.log.Info("已撤销旧共享目录的 Everyone 授权", "root", dir)
			}
		}(old)
	}

	a.aud.Write(audit.Entry{
		Source: "ctlapi", Action: "share root", Result: "ok", Detail: shareID + ": " + old + " -> " + root,
	})
	a.log.Info("共享目录已更换", "share", shareID, "old", old, "new", root)
	return root, nil
}

// rootStillShared 判断这个目录是否还被别的共享引用。
// 撤销 Everyone 之前必须问一句：多个共享指向同一目录时，
// 换掉其中一个不该把另一个的免密访问顺手弄坏。
func (a *App) rootStillShared(root string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, s := range a.cfg.Shares {
		if samePath(s.Root, root) {
			return true
		}
	}
	return false
}

// shareList 把配置里的共享转成 vfs 需要的结构。调用方需持有 a.mu。
func (a *App) shareList() []vfs.Share {
	out := make([]vfs.Share, 0, len(a.cfg.Shares))
	for _, s := range a.cfg.Shares {
		out = append(out, vfs.Share{
			ShareID: s.ShareID, Name: s.Name, Root: s.Root,
			Writable: s.Writable, Media: s.Media,
		})
	}
	return out
}

// ValidateShareRoot 校验并规范化用户填的目录。
// 宁可在这里把话说清楚，也不要等到索引跑到一半才因为路径不对报错。
func (a *App) ValidateShareRoot(shareID, root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("目录不能为空")
	}
	if strings.HasPrefix(root, `\\`) || strings.HasPrefix(root, "//") {
		return "", fmt.Errorf(`请填本机路径，不支持网络路径（\\主机\共享）`)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf(`必须是绝对路径，例如 D:\share 或 /srv/share`)
	}
	clean := filepath.Clean(root)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("不能共享整个根目录 /")
	}
	// 和启动时的配置校验用同一套规则，否则会出现"界面改得动、重启起不来"。
	if err := config.CheckShareRoot(clean); err != nil {
		return "", err
	}

	info, err := os.Stat(platform.LongPath(clean))
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("目录不存在：%s", clean)
		}
		return "", fmt.Errorf("无法访问 %s：%w", clean, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s 不是目录", clean)
	}
	// 先真读一次：没权限的目录 stat 得到，但索引会刷一屏报错。
	f, err := os.Open(platform.LongPath(clean))
	if err != nil {
		return "", fmt.Errorf("没有读取权限：%s", clean)
	}
	f.Close()

	dataDir := filepath.Clean(a.cfg.DataDir)
	if pathHas(clean, dataDir) || pathHas(dataDir, clean) {
		return "", fmt.Errorf("这个目录和数据目录（%s）互相包含，索引会把自己的库当成内容反复扫", dataDir)
	}

	a.mu.RLock()
	others := append([]config.Share(nil), a.cfg.Shares...)
	a.mu.RUnlock()
	for _, s := range others {
		if s.ShareID == shareID || strings.TrimSpace(s.Root) == "" {
			continue
		}
		if pathHas(clean, s.Root) || pathHas(s.Root, clean) {
			return "", fmt.Errorf("和另一个共享（%s：%s）重叠，同一批文件会被两套相对路径索引",
				s.ShareID, s.Root)
		}
	}
	return clean, nil
}

// rebuildIndex 在后台把新根扫进索引，扫完再挂监听。
//
// 顺序是有意的：先 PurgeShare 再 BuildInitial。反过来的话，扫描期间旧行还在，
// 按名字查会命中旧根下的同名文件，版本链就串到别的文件上去了。
func (a *App) rebuildIndex(shareID, root string) {
	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.rebuilding, shareID)
			a.mu.Unlock()
			if a.ctlAPI != nil {
				a.ctlAPI.Broadcast(a.Status())
			}
		}()

		if n, err := a.store.PurgeShare(shareID); err != nil {
			a.log.Error("清理旧索引失败（继续按新目录重建）", "share", shareID, "err", err)
		} else if n > 0 {
			a.log.Info("已清理旧共享根的索引行", "share", shareID, "rows", n)
		}

		a.ix.RegisterShare(shareID, root)
		n, err := a.ix.BuildInitial(shareID, root)
		if err != nil {
			a.log.Error("重建索引失败", "share", shareID, "root", root, "err", err)
			a.addWarning("索引重建失败：" + err.Error())
			return
		}
		a.ix.Run(shareID, root)
		a.log.Info("共享根索引重建完成", "share", shareID, "root", root, "entries", n)
	}()
}

// restartFaces 把"根目录已经写进自己状态里"的几个对外面重新拉起。
//
// 谁需要重启取决于它有没有缓存根：SMB 服务端的启动参数带 root、
// DLNA 的内容源是 vfs、快同步按 shares 算 roots、WebDAV 持有 vfs 指针。
// 没在跑的面不动——下次开的时候自然会读到新配置。
func (a *App) restartFaces() []string {
	var notes []string

	a.mu.RLock()
	applied := a.applied
	a.mu.RUnlock()
	lanOn := applied == "LAN" || applied == "ALL"
	wanOn := applied == "WAN" || applied == "ALL"

	a.srvMu.Lock()
	dlnaUp := a.dlnaSrv != nil
	syncUp := a.syncSrv != nil
	wdUp := a.wdSrv != nil
	a.srvMu.Unlock()

	// SMB：EnsureShare 发现 root 变了会自己重启服务端，不用先 Remove；
	// 但免密那套 NTFS 授权是对着具体目录给的，必须重新跑一遍。
	if lanOn && a.cfg.SMB.Enabled && !a.dry {
		if err := a.startSMB(nil); err != nil {
			notes = append(notes, "SMB 未跟着换根："+err.Error())
		}
	}
	if lanOn && dlnaUp {
		a.stopDLNA()
		if err := a.startDLNA(); err != nil {
			notes = append(notes, "DLNA 重启失败："+err.Error())
		}
	}
	if lanOn && syncUp {
		a.stopSync()
		if err := a.startSync(); err != nil {
			notes = append(notes, "快同步重启失败："+err.Error())
		}
	}
	if wanOn && wdUp {
		a.stopWebDAV()
		if err := a.startWebDAV(); err != nil {
			notes = append(notes, "WebDAV 重启失败："+err.Error())
		}
	}
	return notes
}

// samePath 比较两个路径是否指向同一处。Windows 上大小写与分隔符都不敏感。
func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// pathHas 判断 child 是否在 parent 之内（含相等）。
func pathHas(parent, child string) bool {
	parent = strings.ToLower(filepath.Clean(parent))
	child = strings.ToLower(filepath.Clean(child))
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func (a *App) Operation(id string) (ctlapi.Operation, bool) {
	a.opsMu.Lock()
	defer a.opsMu.Unlock()
	op, ok := a.ops[id]
	if !ok {
		return ctlapi.Operation{}, false
	}
	return *op, true
}

func (a *App) ConfigYAML() (string, error) {
	raw, err := os.ReadFile(a.cfg.Path)
	if err != nil {
		return "", err
	}
	// 口令不回传给前端。
	lines := strings.Split(string(raw), "\n")
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "password:") || strings.HasPrefix(trimmed, "password_hash:") {
			indent := l[:len(l)-len(strings.TrimLeft(l, " "))]
			key := strings.SplitN(trimmed, ":", 2)[0]
			lines[i] = indent + key + ": \"***\""
		}
	}
	return strings.Join(lines, "\n"), nil
}

// ListDirs 只返回子目录：浏览器拿不到本地绝对路径，必须由后端列目录。
func (a *App) ListDirs(p string) ([]ctlapi.DirEntry, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "\\" || p == "/" {
		return listDrives(), nil
	}
	// 只拒绝真正的 ".." 路径段（跳目录），不误伤 "a..b" 这类正常目录名。
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' }) {
		if seg == ".." {
			return nil, fmt.Errorf("路径不允许包含 ..")
		}
	}
	if strings.HasPrefix(p, `\\`) {
		return nil, fmt.Errorf("不支持 UNC 路径")
	}
	if !filepath.IsAbs(p) {
		return nil, fmt.Errorf("必须是绝对路径")
	}
	clean := filepath.Clean(p)

	// 这里不限制在已配置的共享根之内：控制台的「更换目录」要能浏览到
	// 一个还没被共享的目录，否则选不了新位置。控制台本身已经过登录/令牌校验，
	// 且只回目录名、不回文件名。
	entries, err := os.ReadDir(platform.LongPath(clean))
	if err != nil {
		return nil, err
	}
	out := make([]ctlapi.DirEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		out = append(out, ctlapi.DirEntry{Name: e.Name(), Path: filepath.Join(clean, e.Name())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// listDrives 是「此电脑」这一层：Windows 给各个盘符，类 Unix 给根和常见挂载点。
func listDrives() []ctlapi.DirEntry {
	var out []ctlapi.DirEntry
	if runtime.GOOS != "windows" {
		out = append(out, ctlapi.DirEntry{Name: "/", Path: "/"})
		for _, d := range []string{"/mnt", "/media", "/home", "/srv", "/data"} {
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				out = append(out, ctlapi.DirEntry{Name: d, Path: d})
			}
		}
		return out
	}
	for c := 'A'; c <= 'Z'; c++ {
		p := string(c) + `:\`
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, ctlapi.DirEntry{Name: string(c) + ":", Path: p})
		}
	}
	return out
}

func (a *App) Reconcile(rel string) error {
	if rel == "" {
		return fmt.Errorf("缺少 path")
	}
	abs := rel
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(a.cfg.Shares[0].Root, filepath.FromSlash(rel))
	}
	return a.ix.Reconcile(a.cfg.Shares[0].ShareID, abs, "manual")
}

func (a *App) Diagnose() []ctlapi.DiagItem {
	var items []ctlapi.DiagItem
	add := func(level, title, detail string) {
		items = append(items, ctlapi.DiagItem{Level: level, Title: title, Detail: detail})
	}

	if a.admin {
		add("ok", "管理员权限", "已提权，防火墙与共享操作可用")
	} else {
		add("warn", "管理员权限", "未提权：防火墙规则与 SMB 共享不会被创建，局域网设备可能连不上")
	}

	a.srvMu.Lock()
	wd := a.wdSrv != nil
	dlnaOn := a.dlnaSrv != nil
	dlnaAddr := ""
	if dlnaOn {
		dlnaAddr = a.dlnaSrv.LANAddr()
	}
	a.srvMu.Unlock()
	if wd {
		add("ok", "WebDAV", "监听 "+a.cfg.WebDAV.Bind+"（只读，强制认证）")
	} else {
		add("ok", "WebDAV", "未启动")
	}

	switch {
	case !a.cfg.DLNA.Enabled:
		add("ok", "DLNA", "配置中已关闭（dlna.enabled=false）")
	case dlnaOn:
		add("ok", "DLNA", "监听 "+dlnaAddr+"，已通过 SSDP 广播「"+a.cfg.DLNA.FriendlyName+"」")
	default:
		add("warn", "DLNA", "未启动：需要先开启局域网面")
	}

	if names, err := platform.List("FSGW-"); err == nil {
		if len(names) == 0 {
			add("ok", "防火墙规则", "无 FSGW- 前缀规则")
		} else {
			add("ok", "防火墙规则", fmt.Sprintf("%d 条: %s", len(names), strings.Join(names, ", ")))
		}
	} else {
		add("warn", "防火墙规则", err.Error())
	}

	// 免密登录是四个开关的合取：Guest 账户、ForceGuest、共享权限、NTFS。
	// 任何一项没到位，现象都一样——"打不开共享"，所以逐项报出来。
	gs := smbhost.ReadState()
	switch {
	case !a.cfg.SMB.Enabled:
		add("ok", "SMB 登录", "配置中已关闭 SMB")
	case a.guestMode():
		if !gs.GuestExists {
			add("warn", "免密 SMB", "系统里没有 Guest 账户，免密无法实现（部分精简版系统会移除它）")
			break
		}
		switch {
		case gs.GuestActive && gs.ForceGuest == 1:
			add("ok", "免密 SMB", "已开启：同一局域网内任何设备不用用户名口令直接进")
		default:
			miss := []string{}
			if !gs.GuestActive {
				miss = append(miss, "Guest 账户未启用")
			}
			if gs.ForceGuest != 1 {
				miss = append(miss, "来宾模式未开（ForceGuest≠1）")
			}
			add("warn", "免密 SMB", strings.Join(miss, "；")+"。开启局域网面时会自动处理（需管理员）")
		}
		add("warn", "免密是整机设置",
			"ForceGuest=1 期间，本机所有本地账户的网络登录都会映射为 Guest；网关关闭时会自动还原")
	default:
		add("ok", "SMB 登录", "需本机账户口令（smb.auth=account）")
	}
	if !gs.ClientGuest {
		add("warn", "本机访问免密共享",
			"本机作为客户端去连免密共享会被系统拒（Windows 10 1903+ 默认），如遇到请执行 fsgw smb client-guest on")
	}

	if stats, err := a.store.Stats(); err == nil {
		add("ok", "索引", fmt.Sprintf("文件 %d，目录 %d，版本 %d，路径历史 %d",
			stats.Files, stats.Dirs, stats.Versions, stats.PathHistory))
	}

	if free, total, err := platform.FreeSpace(a.cfg.Shares[0].Root); err == nil {
		add("ok", "磁盘空间", fmt.Sprintf("剩余 %.1f GB / %.1f GB", float64(free)/1e9, float64(total)/1e9))
	}

	if a.cfg.Snapshot.Enabled {
		add("warn", "内容快照", "已开启但 SMB 来源只能尽力捕获（见 docs/04 D-02）")
	} else {
		add("ok", "内容快照", "未启用：只保证索引版本链，不承诺内容历史")
	}
	return items
}

func (a *App) AuditPath() string { return filepath.Join(a.cfg.Log.Dir, "audit.log") }

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
