// Package ctlapi 是控制面：只接受"登录会话"或"机器令牌"的请求，
// 并校验 Origin 与 Host 防 DNS rebinding（见 docs/01 第 11 节）。
//
// 两条通道：
//   - 人：POST /api/login 用共享账号（WebDAV / SMB）的用户名+口令，签发会话 cookie；
//   - 机器：X-FSGW-Token 头（SSE 可用 ?token=），给 fsgw ui、脚本、外部工具。
package ctlapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fsgw/internal/audit"
	"fsgw/internal/smbgo"
)

// Status 是 /api/status 的返回体，也是前端首屏唯一数据源。
type Status struct {
	State         string        `json:"applied_state"`
	Desired       string        `json:"desired_state"`
	LastError     string        `json:"last_error"`
	Version       string        `json:"version"`
	UptimeSeconds int64         `json:"uptime_seconds"`
	Admin         bool          `json:"admin"`
	Shares        []ShareInfo   `json:"shares"`
	Listeners     []Listener    `json:"listeners"`
	Index         IndexStats    `json:"index"`
	Snapshot      SnapshotStats `json:"snapshot"`
	Security      SecurityInfo  `json:"security"`
	SMBAuth       SMBAuth       `json:"smb_auth"`
	Sync          SyncInfo      `json:"sync"`
}

// SyncInfo 是「快同步」服务对外暴露的状态：地址、token、当前会话数。
//
// token 一并回传是有意的：控制台本身已经是最高权限（能停服务、改口令），
// 再藏一个"能写共享"的 token 只会让用户多跑一趟 SSH。前端把它拼成一条
// 可直接复制的客户端命令。
type SyncInfo struct {
	Enabled  bool   `json:"enabled"`
	Ready    bool   `json:"ready"`
	Addr     string `json:"addr"`
	Token    string `json:"token"`
	Sessions int64  `json:"sessions"`
	Bytes    int64  `json:"bytes"`
	ChunkMB  int    `json:"chunk_mb"`
}

// SMBAuth 是「SMB 客户端」一栏的数据：登记了谁、谁在线、最近谁被拒。
//
// 为什么把这三样放一起：它们回答的是同一个问题——"为什么这台设备连不上"。
// 账号表说明该不该放行，在线连接说明现在有谁进来了，登录尝试说明刚才
// 是谁被拒了（面板据此可以一键把他的名字填进添加框）。
type SMBAuth struct {
	Path     string          `json:"path"` // 账号表文件路径，方便直接去编辑
	Accounts []SMBAccount    `json:"accounts"`
	Sessions []smbgo.Session `json:"sessions"`
	Attempts []smbgo.Attempt `json:"attempts"`
}

// SMBAccount 是一个登记过的 SMB 客户端账号。口令/哈希一律不回传。
type SMBAccount struct {
	Name    string `json:"name"`
	Note    string `json:"note"`
	AddedAt string `json:"added_at"`
	Source  string `json:"source"` // console（面板添加）/ config（config.yaml 配置）
}

// SecurityInfo 只回状态，不回口令本身。
type SecurityInfo struct {
	WebDAVBind  string `json:"webdav_bind"`
	Username    string `json:"username"`
	PasswordSet bool   `json:"password_set"`
}

type ShareInfo struct {
	ShareID  string `json:"share_id"`
	Name     string `json:"name"`
	Root     string `json:"root"`
	Writable bool   `json:"writable"`
	Media    bool   `json:"media"`
	// Rebuilding 为真表示换了根目录、正在重建索引：此时目录可能是空的，
	// 界面要明说"在扫"，不能让人以为文件没了。
	Rebuilding bool `json:"rebuilding"`
}

type Listener struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Ready   bool   `json:"ready"`
	Addr    string `json:"addr"`
	Note    string `json:"note"`
	// Extra 是这一行右侧可直接看到、可修改的属性。
	// 目前只有 DLNA 的设备名：它既不属于地址也不属于状态，
	// 但用户在电视里看到的就是它，得能在界面上改。
	Extra *ListenerExtra `json:"extra,omitempty"`
}

type ListenerExtra struct {
	Label  string `json:"label"`  // 例如"设备名"
	Value  string `json:"value"`  // 例如"家庭共享"
	Action string `json:"action"` // 前端据此决定调哪个接口，如 dlna-name
}

type IndexStats struct {
	Files         int64  `json:"files"`
	Dirs          int64  `json:"dirs"`
	Objects       int64  `json:"objects"`
	Versions      int64  `json:"versions"`
	PathHistory   int64  `json:"path_history"`
	PendingMoves  int64  `json:"pending_moves"`
	Events        int64  `json:"events"`
	Queue         int64  `json:"queue"`
	LastReconcile string `json:"last_reconcile"`
}

type SnapshotStats struct {
	Enabled bool  `json:"enabled"`
	Count   int64 `json:"count"`
	Bytes   int64 `json:"bytes"`
	QuotaGB int   `json:"quota_gb"`
}

type Operation struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Stage     string    `json:"stage"`
	Done      bool      `json:"done"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

type DiagItem struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

type DirEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// Core 是 app 需要提供的业务能力。ctlapi 只依赖这个接口，不反向 import。
type Core interface {
	Status() Status
	Switch(ctx context.Context, state string) (string, error)
	Operation(id string) (Operation, bool)
	ConfigYAML() (string, error)
	ListDirs(abs string) ([]DirEntry, error)
	Reconcile(rel string) error
	Diagnose() []DiagItem
	AuditPath() string
	SetWebDAVCredentials(user, pass string) error
	// SetShareRoot 换掉某个共享的根目录，返回规范化后的路径（会当场重建索引）。
	SetShareRoot(shareID, root string) (string, error)
	// SetDLNAFriendlyName 改电视/手机里显示的设备名（写入配置并重启 DLNA 广播）。
	SetDLNAFriendlyName(name string) error
	// AddSMBClient / RemoveSMBClient 维护 SMB 客户端账号表（面板用）。
	AddSMBClient(name, pass, note string) error
	RemoveSMBClient(name string) error
	// Quit 拆除全部暴露面并请求进程退出（幂等）。
	Quit()
}

type Server struct {
	core    Core
	token   string
	port    string
	log     *slog.Logger
	local   bool
	webui   fs.FS
	hosts   map[string]bool // 允许出现在 Host / Origin 里的主机名（小写，不含端口）
	mu      sync.Mutex
	clients map[chan Status]struct{}

	// accounts 校验"用户名+口令"，返回规范用户名。nil = 本实例不支持口令登录。
	accounts func(user, pass string) (string, bool)
	// sess 是人用登录会话（落盘，重启不掉线）。
	sess *sessionStore
}

type Options struct {
	Core  Core
	Token string
	Bind  string
	Log   *slog.Logger
	WebUI fs.FS
	// AllowedHosts 是额外放行的主机名（config.yaml 的 ui.allowed_hosts）。
	// 用于"域名访问"或反向代理场景；不填时回环 + 本机网卡地址已经够用。
	AllowedHosts []string
	// Accounts 校验控制台的用户名+口令，实现里复用共享账号表。
	// 为 nil 时登录接口返回 503，只能用 token（自检、单元测试会这么用）。
	Accounts func(user, pass string) (string, bool)
	// SessionFile 是会话落盘路径；空 = 只放内存。
	SessionFile string
}

func New(o Options) *Server {
	host, port, _ := net.SplitHostPort(o.Bind)
	hosts := map[string]bool{
		"127.0.0.1": true,
		"localhost": true,
		"::1":       true,
	}
	if h := strings.ToLower(strings.Trim(host, "[]")); h != "" && h != "0.0.0.0" && h != "::" {
		hosts[h] = true
	}
	// 本机各张网卡的地址：Linux 没有桌面，控制台只能从别的机器按 IP 访问。
	for _, h := range LocalHosts() {
		hosts[strings.ToLower(h)] = true
	}
	for _, h := range o.AllowedHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h == "" {
			continue
		}
		// 允许写成 "fsgw.lan" 或 "fsgw.lan:8444"，统一按无端口保存。
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		hosts[strings.Trim(h, "[]")] = true
	}
	return &Server{
		core:     o.Core,
		token:    o.Token,
		port:     port,
		log:      o.Log,
		local:    true,
		webui:    o.WebUI,
		hosts:    hosts,
		clients:  map[chan Status]struct{}{},
		accounts: o.Accounts,
		sess:     newSessionStore(o.SessionFile),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	// 登录三件套免 token：登录本身要是还要 token，人工就用不上了。
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/whoami", s.handleWhoAmI)
	mux.HandleFunc("GET /api/status", s.guard(s.status))
	mux.HandleFunc("GET /api/events", s.guard(s.events))
	mux.HandleFunc("POST /api/switch", s.guard(s.switchState))
	mux.HandleFunc("GET /api/operations/{id}", s.guard(s.operation))
	mux.HandleFunc("GET /api/config", s.guard(s.config))
	mux.HandleFunc("GET /api/shares", s.guard(s.shares))
	mux.HandleFunc("PUT /api/shares/{id}/root", s.guard(s.setShareRoot))
	mux.HandleFunc("PUT /api/dlna/name", s.guard(s.setDLNAName))
	mux.HandleFunc("GET /api/fs/list", s.guard(s.fsList))
	mux.HandleFunc("POST /api/index/reconcile", s.guard(s.reconcile))
	mux.HandleFunc("GET /api/diagnose", s.guard(s.diagnose))
	mux.HandleFunc("GET /api/audit", s.guard(s.auditTail))
	mux.HandleFunc("POST /api/snapshot/gc", s.guard(s.notImplemented))
	mux.HandleFunc("PUT /api/webdav/credentials", s.guard(s.setCredentials))
	mux.HandleFunc("POST /api/smb/clients", s.guard(s.addSMBClient))
	mux.HandleFunc("DELETE /api/smb/clients/{name}", s.guard(s.removeSMBClient))
	mux.HandleFunc("POST /api/quit", s.guard(s.quit))

	if s.webui != nil {
		mux.Handle("/", http.FileServer(http.FS(s.webui)))
	}
	return mux
}

// guard 是四道防线的实现：登录（会话或令牌）、Origin、Host、无 CORS。
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1) Host 校验：防 DNS rebinding。攻击者域名解析到回环后，Host 仍是该域名。
		if !s.hostOK(r.Host) {
			http.Error(w, "bad host", http.StatusForbidden)
			return
		}
		// 2) Origin 校验：允许为空（非浏览器）或自身来源。
		if o := r.Header.Get("Origin"); o != "" && !s.originOK(o) {
			http.Error(w, "bad origin", http.StatusForbidden)
			return
		}
		// 3) 认证：机器令牌或人工会话，任一条通过即可。
		//    令牌头优先，SSE 允许用查询参数（EventSource 不能设头）。
		if !s.tokenOK(r) {
			if _, ok := s.sessionOf(r); !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		// 4) 不回任何 CORS 头，跨源预检因此拿不到放行，走不到业务逻辑。
		next(w, r)
	}
}

func (s *Server) hostOK(host string) bool {
	host = strings.ToLower(host)
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		h, p = host, s.port
	}
	if p != s.port {
		return false
	}
	h = strings.Trim(h, "[]")
	if h == "" {
		return false
	}
	return s.hosts[h]
}

func (s *Server) originOK(origin string) bool {
	u, err := url.Parse(strings.TrimSuffix(strings.ToLower(origin), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if port != s.port {
		return false
	}
	return s.hosts[strings.Trim(u.Hostname(), "[]")]
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	// 免 token，因此只回不携带细节的状态字。
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok\n"))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.core.Status())
}

func (s *Server) switchState(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State   string `json:"state"`
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
		return
	}
	if req.State == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 state"})
		return
	}
	// 危险方向必须有二次确认：从 OFF 开 WAN/ALL。
	if (req.State == "WAN" || req.State == "ALL") && req.Confirm != req.State {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "开启外部访问需要二次确认（confirm 字段）"})
		return
	}
	id, err := s.core.Switch(r.Context(), req.State)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"operation_id": id})
}

func (s *Server) operation(w http.ResponseWriter, r *http.Request) {
	op, ok := s.core.Operation(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "没有该操作"})
		return
	}
	writeJSON(w, http.StatusOK, op)
}

func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	y, err := s.core.ConfigYAML()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": y})
}

func (s *Server) shares(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.core.Status().Shares)
}

// setShareRoot 换共享根目录。
//
// 返回 200 只代表"配置已写、旧索引已清、重建已开始"，不代表索引扫完了：
// 几十万文件的目录要扫几分钟，这期间前端靠 status 里的 rebuilding 判断。
func (s *Server) setShareRoot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Root string `json:"root"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少共享 ID"})
		return
	}
	root, err := s.core.SetShareRoot(id, req.Root)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// rebuilding 取真正的状态：小目录可能已经扫完了，
	// 一律回 true 会让界面挂着一个永远转不完的"重建中"。
	rebuilding := false
	for _, sh := range s.core.Status().Shares {
		if sh.ShareID == id {
			rebuilding = sh.Rebuilding
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": "ok", "root": root, "rebuilding": rebuilding})
}

func (s *Server) setDLNAName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
		return
	}
	if err := s.core.SetDLNAFriendlyName(req.Name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	// 名字变了会重启 DLNA，客户端重新出现需要几秒；状态里带上新值是给界面
	// 立刻更新的依据，不用等 SSE 下一帧。
	s.Broadcast(s.core.Status())
	writeJSON(w, http.StatusOK, map[string]any{"result": "ok", "name": name})
}

func (s *Server) fsList(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	entries, err := s.core.ListDirs(p)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// 盘符 / 根列表每次都带回去，界面拿它做顶部快捷条，不用再单独请求一趟。
	drives, _ := s.core.ListDirs("")
	// 回规范化的路径：用户手输的可能是 d:/share/ 这种写法，
	// 前端要拿它算"上一级"，必须是统一格式（D:\share）。
	norm := p
	if strings.TrimSpace(norm) != "" {
		norm = filepath.Clean(norm)
		// 盘符统一大写：手输 d:\share 时显示成 D:\share，看着不别扭。
		// 注意连冒号一起取，否则 D: 会变成 D。
		if len(norm) >= 2 && norm[1] == ':' {
			norm = strings.ToUpper(norm[:2]) + norm[2:]
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": norm, "entries": entries, "drives": drives})
}

// setCredentials 修改外部只读面的用户名与口令。
// 只落哈希进配置文件，明文不落盘、不回传前端。
func (s *Server) setCredentials(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
		return
	}
	if err := s.core.SetWebDAVCredentials(req.Username, req.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// addSMBClient 登记一个 SMB 客户端账号（客户名 + 口令）。
// 口令只在这一层短暂存在，写盘前就被换成 NT 哈希。
func (s *Server) addSMBClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
		return
	}
	if err := s.core.AddSMBClient(req.Name, req.Password, req.Note); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.log.Info("面板登记了 SMB 客户端账号", "user", req.Name)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// removeSMBClient 删掉一个登记的客户端账号。
func (s *Server) removeSMBClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.core.RemoveSMBClient(name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.log.Info("面板移除了 SMB 客户端账号", "user", name)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// quit 优雅退出：先拆干净暴露面再结束进程。
// 先回包再让主循环退出，避免浏览器/CLI 拿到连接被重置的错误。
func (s *Server) quit(w http.ResponseWriter, r *http.Request) {
	s.log.Info("收到退出请求", "from", r.RemoteAddr)
	s.core.Quit()
	writeJSON(w, http.StatusOK, map[string]any{"result": "ok", "state": "OFF"})
}

func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if err := s.core.Reconcile(req.Path); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (s *Server) diagnose(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.core.Diagnose())
}

func (s *Server) auditTail(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	filter := r.URL.Query().Get("filter")
	entries, err := audit.Tail(s.core.AuditPath(), limit, filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) notImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "第一版未启用内容快照（见 docs/04 D-02：SMB 来源无法写前捕获）",
	})
}

// events 用 SSE 推送状态。开关是长任务，靠这条流把阶段变化实时给到前端。
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ch := make(chan Status, 8)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	send := func(st Status) bool {
		raw, err := json.Marshal(st)
		if err != nil {
			return true
		}
		if _, err := w.Write([]byte("event: status\ndata: " + string(raw) + "\n\n")); err != nil {
			return false
		}
		fl.Flush()
		return true
	}

	if !send(s.core.Status()) {
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if !send(s.core.Status()) {
				return
			}
		case st := <-ch:
			if !send(st) {
				return
			}
		}
	}
}

// Broadcast 由 app 在状态机推进时调用，把阶段变化立刻推给所有客户端。
func (s *Server) Broadcast(st Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- st:
		default:
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// subtleCompare 用常量时间比字符串，避免按字节提前返回泄露前缀。
func subtleCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
