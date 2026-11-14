// Package config 负责加载与校验 config.yaml。
// 校验在启动时一次性完成，失败即退出，不做降级启动（见 docs/01 第 14 节）。
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version int    `yaml:"version"`
	DataDir string `yaml:"data_dir"`

	Shares []Share `yaml:"shares"`

	Index    Index    `yaml:"index"`
	Snapshot Snapshot `yaml:"snapshot"`
	SMB      SMB      `yaml:"smb"`
	DLNA     DLNA     `yaml:"dlna"`
	WebDAV   WebDAV   `yaml:"webdav"`
	Sync     Sync     `yaml:"sync"`
	UI       UI       `yaml:"ui"`
	Switch   Switch   `yaml:"switch"`
	Log      Log      `yaml:"log"`

	// Path 记录本配置文件所在位置，便于把相对路径解析成绝对路径。
	Path string `yaml:"-"`
}

type Share struct {
	ShareID  string `yaml:"share_id"`
	Root     string `yaml:"root"`
	Name     string `yaml:"name"`
	Writable bool   `yaml:"writable"`
	Media    bool   `yaml:"media"`
	Dirs     []Dir  `yaml:"dirs"`
}

type Dir struct {
	RelPath  string `yaml:"rel_path"`
	Writable *bool  `yaml:"writable"`
}

type Index struct {
	DebounceStructuralMS int    `yaml:"debounce_structural_ms"`
	DebounceContentMS    int    `yaml:"debounce_content_ms"`
	HashMaxMB            int    `yaml:"hash_max_mb"`
	ReconcileInterval    string `yaml:"reconcile_interval"`
	ReconcileRecentWnd   string `yaml:"reconcile_recent_window"`
	QueueStructural      int    `yaml:"write_queue_structural"`
	QueueContent         int    `yaml:"write_queue_content"`
}

type Snapshot struct {
	Enabled      bool   `yaml:"enabled"`
	Mode         string `yaml:"mode"`
	Dir          string `yaml:"dir"`
	MaxPerObject int    `yaml:"max_versions_per_object"`
	QuotaGB      int    `yaml:"quota_gb"`
	MinFreeGB    int    `yaml:"min_free_gb"`
	CaptureMaxMB int    `yaml:"capture_max_mb"`
}

type SMB struct {
	Enabled bool `yaml:"enabled"`
	// Auth: account = 经典模式，必须用本机账户口令；
	//       guest   = 免密（来宾）模式，局域网内任何设备直接进；
	//       both    = 与 guest 等价——ForceGuest 是整机开关，两种方式无法并存。
	Auth      string `yaml:"auth"`
	Account   string `yaml:"account_name"`
	LANOnly   bool   `yaml:"lan_only"`
	Exclusive bool   `yaml:"exclusive"`

	// Engine 决定 SMB 由谁提供（仅 Windows 有意义，Linux 恒为 go）：
	//
	//	auto  （默认）先起进程内的纯 Go SMB2/3 服务端，起不来再退回系统共享；
	//	go    只用自研服务端。需要先让 LanmanServer 让出 445，本机系统共享
	//	      在网关运行期间不可用；
	//	native 只用 Windows 自带的 SMB 服务（net share）。
	//
	// 为什么默认不是 native：Win11 24H2/25H2 起 SMB 客户端默认强制签名，
	// 来宾会话没有会话密钥签不了名；native 路线的免密只能靠 ForceGuest=1
	// （整机开关，一开就把本机所有网络登录都映射成 Guest）。自研服务端
	// 是唯一同时满足"免密可用"与"账号可验"的路线。
	Engine string `yaml:"engine"`
	// GuestWritable 免密模式下是否允许写入。
	// 默认 false：电视/手机只是播放，不该有删文件的权限。
	GuestWritable bool `yaml:"guest_writable"`

	// AppleMeta 控制 macOS 自动写的元数据文件（.DS_Store、._xxx、.Trashes、
	// .Spotlight-V100 …）在 SMB 列目录里是否可见。
	//
	//	macos 客户端访问非 Apple 卷时会把 Finder 窗口布局、资源分叉、xattr
	//	平铺成这些影子文件。它们对 Windows/Linux 客户端是纯垃圾，但删掉会
	//	丢 mac 的图标位置与标签，所以默认不删、只藏。
	//
	// 取值：
	//   hide（留空等同，推荐）= 只对非 macOS 接入端隐藏：Windows / Linux / 电视
	//                          看目录时不会再冒出 ._xxx 与 .DS_Store；mac 自己
	//                          照旧看得见（它找得到就不会每次进目录重写一遍）
	//   all                  = 连 mac 一起隐藏（mac 会因此反复重写 ._DS_Store，
	//                          不推荐，除非确定 mac 侧已关掉 DSDontWriteNetworkStores）
	//   off                  = 都不过滤（只用于排障，确认过滤有没有误伤）
	//
	// 想连文件都不产生，得在 mac 上执行一次（Apple 官方开关，重启 Finder 生效）：
	//   defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
	// 存量文件用 `fsgw clean-meta` 扫描删除（默认只列清单，-force 才删）。
	AppleMeta string `yaml:"apple_meta"`

	// SMB1Backend 是"纯 SMB1 客户端"要转交的外部后端地址（host:port）。
	//
	// 留空 = 用进程内置的最小 SMB1 通道（internal/smbgo/smb1srv.go）直接服务，
	// 这是默认也是推荐配置：两个平台同一套代码，不需要在系统里装 samba。
	//
	// 为什么需要 SMB1 通道：网关自己的服务端是纯 SMB2/3 实现，而小米电视、老投影、
	// 老播放器的 SMB 客户端只声明 `NT LM 0.12` 一个方言——把它的协商改写成 SMB2
	// 之后，它拿到一份看不懂的响应就静默放弃（现象：端口通、认证都没开始）。
	//
	// 分流方式：网关仍独占 445，认出纯 SMB1 客户端后，那一条 TCP 连接要么交给内置
	// 通道，要么（配了这个字段时）原样转交给外部后端。配置外部后端只是给想用
	// samba 全套特性（比如多用户、日志）的人留的出口：
	//
	//   smb1_backend: 127.0.0.1:4450
	SMB1Backend string `yaml:"smb1_backend"`

	// Password 是 SMB 账号的口令（明文），只在 Linux 的纯 Go 服务端上使用：
	// 它要做 NTLMv2 校验，而 NTLM 只认口令的 NT 哈希，认不了 WebDAV 那种加盐哈希。
	//
	// 为什么非要有它：Windows 11 24H2 起 SMB 客户端默认强制签名，而来宾会话
	// 没有会话密钥、签不了名，于是免密共享在 Win11 上必然连不上（报"策略阻止
	// 未经验证的来宾访问"）。配一个账号，Win11 就能用「用户名+口令」正常登录。
	//
	// 留空 = 纯来宾模式（电视/手机/老系统照旧，Win11 会被它自己的策略挡住）。
	Password string `yaml:"password"`
	// NTHash 是口令的 NT 哈希（32 位十六进制）。填了它就优先用它，
	// 这样配置里不必留明文；可用 `fsgw smb nt-hash <口令>` 生成。
	NTHash string `yaml:"nt_hash"`

	// ClientHints 手工指定某台机器是什么客户端，优先级高于协议指纹识别。
	//
	// 为什么需要人工指定：服务端在 NEGOTIATE 阶段只能靠方言表与能力位推断，
	// 推断结果用于决定补哪些兼容处理（例如 Linux 内核 CIFS 会查
	// FileFsDeviceInformation，Windows 不查）。万一某台设备的指纹被认错，
	// 这里一行配置就能纠正，不用改代码重发版。
	//
	// ip 支持完整地址或前缀：192.0.2.50 精确匹配，192.0.2. 匹配整段。
	// kind 取值：windows / macos / linux-cifs / linux-samba / other
	ClientHints []ClientHint `yaml:"client_hints"`
}

// ClientHint 是一条人工指定的接入端类型。
type ClientHint struct {
	IP   string `yaml:"ip"`
	Kind string `yaml:"kind"`
}

type DLNA struct {
	Enabled      bool   `yaml:"enabled"`
	HTTPPort     int    `yaml:"http_port"`
	FriendlyName string `yaml:"friendly_name"`
}

type WebDAV struct {
	Enabled  bool   `yaml:"enabled"`
	Bind     string `yaml:"bind"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// PasswordHash 留空时用 Password 现算，便于本地快速验证。
	PasswordHash string `yaml:"password_hash"`
	// Users 可选的额外账号表。配了它之后，username/password_hash 仍然有效，
	// 两边是"并集"，便于给不同人发不同口令而不用共享一个。
	Users []WebDAVUser `yaml:"users"`
}

// WebDAVUser 是 users 列表里的一条账号。
// 口令只落 PasswordHash（sha256$salt$hash），明文 Password 仅供本地临时验证。
type WebDAVUser struct {
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	PasswordHash string `yaml:"password_hash"`
}

type UI struct {
	Enabled bool   `yaml:"ui_enabled"`
	Bind    string `yaml:"bind"`
	// AllowRemote 是"允许控制台监听非回环地址"的显式开关。
	// 控制台本身是 token 鉴权 + Host/Origin 校验，但"能被局域网访问"属于
	// 暴露面变化，必须由配置明确点头（Linux 服务器没有桌面，不开放就没法用）。
	AllowRemote bool `yaml:"allow_remote"`
	// AllowedHosts 额外放行的主机名（域名访问 / 反向代理场景）。
	// 本机各网卡 IP 与回环地址永远放行，不需要在这里重复。
	AllowedHosts []string `yaml:"allowed_hosts"`
}

// Sync 是「快同步」服务的配置。
//
// 它存在的理由很直接：SMB 在单条会话里是串行的，客户端的"多线程复制"往往只是
// 在一个核上排队投递请求，带宽根本吃不满；大文件传到一半断了还得从头再来。
// 这里换一条自己的 HTTP 协议：分块并行、小文件打包、断点续传、按内容校验落盘。
type Sync struct {
	Enabled bool   `yaml:"enabled"`
	Bind    string `yaml:"bind"`
	// AllowRemote 与 UI 同义：绑非回环地址必须显式点头（这里默认为 true，
	// 因为同步服务天生要给别的机器用；本机自用改成 127.0.0.1:8445 即可）。
	AllowRemote bool `yaml:"allow_remote"`
	// Roots 限定可写入的 share_id 列表；留空 = 所有 writable 的共享根。
	// 同步是"能覆盖你文件的"接口，减少暴露面比方便更重要。
	Roots []string `yaml:"roots"`
	// ChunkMB 是分块大小。太小→请求数暴涨；太大→单请求失败重传代价高。
	ChunkMB int `yaml:"chunk_mb"`
	// MaxParallelFiles 是服务端同时接受的分块写入文件数上限（保护磁盘）。
	MaxParallelFiles int `yaml:"max_parallel_files"`
	// SessionTTLHours 过后，未完成的会话与它的暂存块自动清理。
	SessionTTLHours int `yaml:"session_ttl_hours"`
	// MaxFiles 是单次会话的清单上限（客户端一次推多少个文件）。
	// 默认 100 万：一个装满 node_modules 的工作目录很容易过十万，
	// 上限卡得太低会让整目录同步直接失败，反而逼着人去分目录手工推。
	MaxFiles int `yaml:"max_files"`
	// Verify: chunk = 只校验每块（默认，速度快）；full = 落盘后再整文件 hash 一次。
	Verify string `yaml:"verify"`
}

type Switch struct {
	StartupState string `yaml:"startup_state"`
}

type Log struct {
	Level              string `yaml:"level"`
	Dir                string `yaml:"dir"`
	AuditRetentionDays int    `yaml:"audit_retention_days"`
}

// Default 返回带默认值的配置，供 selftest 与首次生成使用。
func Default() *Config {
	return &Config{
		Version: 1,
		DataDir: "data",
		Shares: []Share{{
			ShareID:  "main",
			Root:     `D:\share`,
			Name:     "share",
			Writable: true,
			Media:    true,
		}},
		Index: Index{
			DebounceStructuralMS: 150,
			DebounceContentMS:    400,
			HashMaxMB:            64,
			ReconcileInterval:    "6h",
			ReconcileRecentWnd:   "24h",
			QueueStructural:      1024,
			QueueContent:         8192,
		},
		Snapshot: Snapshot{Enabled: false, Mode: "gateway_only", MaxPerObject: 10, QuotaGB: 200, MinFreeGB: 20, CaptureMaxMB: 8},
		SMB:      SMB{Enabled: true, Auth: "account", Account: "fsgw", LANOnly: true},
		DLNA:     DLNA{Enabled: false, HTTPPort: 8200, FriendlyName: "熬拜共享家"},
		WebDAV:   WebDAV{Enabled: true, Bind: "127.0.0.1:8443", Username: "fsgw"},
		Sync:     Sync{Enabled: true, Bind: "0.0.0.0:8445", AllowRemote: true, ChunkMB: 4, MaxParallelFiles: 8, SessionTTLHours: 72, MaxFiles: 1000000, Verify: "chunk"},
		UI:       UI{Enabled: true, Bind: "127.0.0.1:8444"},
		Switch:   Switch{StartupState: "OFF"},
		Log:      Log{Level: "info", AuditRetentionDays: 30},
	}
}

// Load 读取并校验配置。path 为空时按 exe 同目录的 config.yaml 查找。
func Load(path string) (*Config, error) {
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(filepath.Dir(exe), "config.yaml")
		if _, statErr := os.Stat(path); statErr != nil {
			// exe 同目录没有就往系统位置找，否则 `fsgw off` 这类不带参数的
			// 命令在有 systemd 部署的机器上永远失败（见 paths_linux.go）。
			for _, alt := range extraDefaultPaths() {
				if _, err := os.Stat(alt); err == nil {
					path = alt
					break
				}
			}
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s: %w", abs, err)
	}
	cfg := Default()
	// 覆盖在默认值之上，避免字段缺失导致零值。
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", abs, err)
	}
	cfg.Path = abs
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// normalize 把相对路径解析到配置文件所在目录。
func (c *Config) normalize() error {
	base := filepath.Dir(c.Path)
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	c.DataDir = absJoin(base, c.DataDir)
	if c.Snapshot.Dir == "" {
		c.Snapshot.Dir = filepath.Join(c.DataDir, "snapshots")
	} else {
		c.Snapshot.Dir = absJoin(base, c.Snapshot.Dir)
	}
	if c.Log.Dir == "" {
		c.Log.Dir = filepath.Join(c.DataDir, "logs")
	} else {
		c.Log.Dir = absJoin(base, c.Log.Dir)
	}
	for i := range c.Shares {
		if c.Shares[i].Root != "" {
			c.Shares[i].Root = absJoin(base, c.Shares[i].Root)
		}
		if c.Shares[i].Name == "" {
			c.Shares[i].Name = c.Shares[i].ShareID
		}
	}
	return nil
}

func absJoin(base, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}

var systemRoots = []string{
	`c:\windows`, `c:\program files`, `c:\program files (x86)`,
	`c:\programdata`,
}

// CheckShareRoot 是「这个目录能不能拿来共享」的唯一判定。
//
// 为什么必须唯一：启动时会 Validate 整份配置，界面改目录走的是
// app.ValidateShareRoot。两边规则不一致的话就会出现最难查的一类问题——
// 界面上改得动、写回配置、重启却因为校验不过而起不来。
//
// 用户目录（C:\Users\xxx）单独处理：整个用户目录不能共享，
// 但「共享桌面上某个文件夹」是非常正常的需求，它下面的子目录必须放行。
func CheckShareRoot(root string) error {
	clean := filepath.Clean(root)
	low := strings.ToLower(clean)
	if low == `c:\` || low == "/" {
		return fmt.Errorf("不允许共享整个系统盘")
	}
	for _, sr := range systemRoots {
		if low == sr || strings.HasPrefix(low, sr+`\`) {
			return fmt.Errorf("不允许共享系统目录 %s", clean)
		}
	}
	if low == `c:\users` {
		return fmt.Errorf("不能共享整个 Users 目录")
	}
	if strings.HasPrefix(low, `c:\users\`) {
		rest := strings.TrimPrefix(low, `c:\users\`)
		if !strings.Contains(rest, `\`) {
			return fmt.Errorf("不能共享整个用户目录 %s（请选它下面的具体文件夹，比如桌面上的某个目录）", clean)
		}
	}
	return nil
}

// Validate 校验所有字段，错误信息带字段路径。
func (c *Config) Validate() error {
	var errs []string
	add := func(f string, args ...any) { errs = append(errs, fmt.Sprintf(f, args...)) }

	if c.Version != 1 {
		add("version: 只支持 1，当前 %d", c.Version)
	}
	if len(c.Shares) == 0 {
		add("shares: 至少需要一个共享根")
	}
	seen := map[string]bool{}
	for i, s := range c.Shares {
		f := fmt.Sprintf("shares[%d]", i)
		if s.ShareID == "" {
			add("%s.share_id: 不能为空", f)
		}
		if seen[s.ShareID] {
			add("%s.share_id: 重复的 %q", f, s.ShareID)
		}
		seen[s.ShareID] = true
		if s.Root == "" {
			add("%s.root: 不能为空", f)
			continue
		}
		if !filepath.IsAbs(s.Root) {
			add("%s.root: 必须是绝对路径，当前 %q", f, s.Root)
		}
		if err := CheckShareRoot(s.Root); err != nil {
			add("%s.root: %v", f, err)
		}
		st, err := os.Stat(s.Root)
		if err != nil {
			add("%s.root: 无法访问 %s: %v", f, s.Root, err)
		} else if !st.IsDir() {
			add("%s.root: 不是目录 %s", f, s.Root)
		}
		for j, d := range s.Dirs {
			if strings.Contains(d.RelPath, "..") {
				add("%s.dirs[%d].rel_path: 不允许包含 ..", f, j)
			}
		}
	}

	if c.Index.DebounceStructuralMS <= 0 {
		c.Index.DebounceStructuralMS = 150
	}
	if c.Index.DebounceContentMS <= 0 {
		c.Index.DebounceContentMS = 400
	}
	if c.Index.QueueStructural <= 0 {
		c.Index.QueueStructural = 1024
	}
	if c.Index.QueueContent <= 0 {
		c.Index.QueueContent = 8192
	}
	if c.Index.ReconcileInterval == "" {
		c.Index.ReconcileInterval = "6h"
	}
	if _, err := time.ParseDuration(c.Index.ReconcileInterval); err != nil {
		add("index.reconcile_interval: 无法解析 %q", c.Index.ReconcileInterval)
	}

	if !isLoopback(c.UI.Bind) {
		if !c.UI.AllowRemote {
			add("ui.bind: 监听非回环地址 %q 需要同时显式设置 ui.allow_remote: true", c.UI.Bind)
		}
		if _, _, err := net.SplitHostPort(c.UI.Bind); err != nil {
			add("ui.bind: 非回环监听必须写成 host:port，当前 %q", c.UI.Bind)
		}
	}
	for _, h := range c.UI.AllowedHosts {
		if strings.Contains(h, "://") || strings.Contains(h, "/") {
			add("ui.allowed_hosts: 只写主机名或 host:port，不要带协议和路径，当前 %q", h)
		}
	}
	if c.Sync.Enabled {
		if c.Sync.Bind == "" {
			c.Sync.Bind = "0.0.0.0:8445"
		}
		if !isLoopback(c.Sync.Bind) {
			if !c.Sync.AllowRemote {
				add("sync.bind: 监听非回环地址 %q 需要同时显式设置 sync.allow_remote: true", c.Sync.Bind)
			}
			if _, _, err := net.SplitHostPort(c.Sync.Bind); err != nil {
				add("sync.bind: 非回环监听必须写成 host:port，当前 %q", c.Sync.Bind)
			}
		}
		if c.Sync.ChunkMB == 0 {
			c.Sync.ChunkMB = 4
		}
		if c.Sync.ChunkMB < 1 || c.Sync.ChunkMB > 32 {
			add("sync.chunk_mb: 取值 1-32，当前 %d", c.Sync.ChunkMB)
		}
		if c.Sync.MaxParallelFiles == 0 {
			c.Sync.MaxParallelFiles = 8
		}
		if c.Sync.SessionTTLHours == 0 {
			c.Sync.SessionTTLHours = 72
		}
		if c.Sync.MaxFiles == 0 {
			c.Sync.MaxFiles = 1000000
		}
		if c.Sync.MaxFiles < 1000 || c.Sync.MaxFiles > 5000000 {
			add("sync.max_files: 取值 1000-5000000，当前 %d", c.Sync.MaxFiles)
		}
		switch c.Sync.Verify {
		case "", "chunk":
			c.Sync.Verify = "chunk"
		case "full":
		default:
			add("sync.verify: 只能是 chunk 或 full，当前 %q", c.Sync.Verify)
		}
		for _, id := range c.Sync.Roots {
			if !seen[id] {
				add("sync.roots: 未知的 share_id %q", id)
			}
		}
	}
	if c.WebDAV.Enabled && c.WebDAV.Bind == "" {
		c.WebDAV.Bind = "127.0.0.1:8443"
	}
	if c.WebDAV.Enabled && c.WebDAV.Password == "" && c.WebDAV.PasswordHash == "" && len(c.WebDAV.Users) == 0 {
		add("webdav.password: 外部只读面必须设置口令")
	}
	seenWD := map[string]bool{}
	if c.WebDAV.Username != "" {
		seenWD[c.WebDAV.Username] = true
	}
	for i, u := range c.WebDAV.Users {
		if u.Username == "" {
			add("webdav.users[%d]: username 不能为空", i)
			continue
		}
		if seenWD[u.Username] {
			add("webdav.users[%d]: 账号 %q 重复", i, u.Username)
		}
		seenWD[u.Username] = true
		if u.Password == "" && u.PasswordHash == "" {
			add("webdav.users[%d]: 账号 %q 没有口令", i, u.Username)
		}
	}

	switch c.Switch.StartupState {
	case "", "OFF", "LAN", "WAN", "ALL":
	default:
		add("switch.startup_state: 只能是 OFF/LAN/WAN/ALL，当前 %q", c.Switch.StartupState)
	}
	switch c.SMB.Auth {
	case "", "guest", "account", "both":
	default:
		add("smb.auth: 只能是 guest/account/both，当前 %q", c.SMB.Auth)
	}
	switch strings.ToLower(strings.TrimSpace(c.SMB.Engine)) {
	case "", "auto", "go", "native":
	default:
		add("smb.engine: 只能是 auto/go/native，当前 %q", c.SMB.Engine)
	}

	if len(errs) > 0 {
		return errors.New("配置校验失败:\n  - " + strings.Join(errs, "\n  - "))
	}
	return nil
}

func isLoopback(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

// SaveShareRoot 只把某个共享的 root: 一行替换掉，其余内容与注释原样保留。
//
// 不整文件重写的原因和 SaveWebDAV 一样：这份配置是人手写的，注释里写着
// 为什么这么配；yaml.Marshal 一遍全丢，下次改配置的人就得重新猜。
func (c *Config) SaveShareRoot(path, shareID, root string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")

	inShares, inBlock := false, false
	blockIndent, patched := -1, false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inShares = strings.HasPrefix(trimmed, "shares:")
			inBlock = false
			continue
		}
		if !inShares {
			continue
		}
		// 列表项开头："- share_id: main"，顺着它判断当前落在哪个共享块里。
		if strings.HasPrefix(trimmed, "- ") {
			inBlock = strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")) == "share_id: "+shareID ||
				strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")) == `share_id: "`+shareID+`"`
			if inBlock {
				blockIndent = indent
			}
			continue
		}
		if !inBlock || indent <= blockIndent {
			inBlock = false
			continue
		}
		if key := strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[0]); key == "root" {
			// 行尾可能写着"为什么是这个目录"，换值时留着它。
			comment := ""
			if j := strings.Index(line, " #"); j >= 0 {
				comment = line[j:]
			}
			lines[i] = strings.Repeat(" ", indent) + "root: " + quoteYAML(root) + comment
			patched = true
			break
		}
	}

	if !patched {
		// 配置里写法和预期不一样（比如 flow style），退回整文件重写：
		// 注释会丢，但配置至少是对的。
		return c.Save(path)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SaveDLNAFriendlyName 只改 dlna.friendly_name 一行，注释与其它配置原样保留。
//
// 和 SaveShareRoot 同一套思路：这是人手写的配置，注释里有"为什么这么配"，
// 不值得为了一个设备名把整份文件 yaml.Marshal 一遍。配置里没有这一行时
// （用的是默认名）就地插一行，也不重写全文。
func (c *Config) SaveDLNAFriendlyName(path, name string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")

	dlnaIdx, childIndent, patched := -1, 2, false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			if dlnaIdx >= 0 && !patched {
				break // dlna 段已经结束，后面是别的顶层键
			}
			if strings.HasPrefix(trimmed, "dlna:") {
				dlnaIdx = i
			}
			continue
		}
		if dlnaIdx < 0 {
			continue
		}
		if key := strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[0]); key == "friendly_name" {
			comment := ""
			if j := strings.Index(line, " #"); j >= 0 {
				comment = line[j:]
			}
			lines[i] = strings.Repeat(" ", indent) + "friendly_name: " + quoteYAML(name) + comment
			patched = true
			break
		}
		childIndent = indent // 记住同段其它键的缩进，插行时对齐
	}

	if !patched {
		entry := strings.Repeat(" ", childIndent) + "friendly_name: " + quoteYAML(name)
		if dlnaIdx >= 0 {
			lines = append(lines[:dlnaIdx+1], append([]string{entry}, lines[dlnaIdx+1:]...)...)
		} else {
			// 配置里根本没有 dlna: 段（全用默认值），补一个。
			// 只写 friendly_name，其余字段 Load 会用默认值补齐。
			lines = append(lines, "", "dlna:", entry)
		}
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// quoteYAML 用单引号包路径：单引号里反斜杠不转义，Windows 路径能原样写进去
// （写成双引号会变成 "D:\\share"，能读但看着别扭）。路径里唯一的特殊字符是
// 单引号本身，YAML 用两个单引号表示一个。
func quoteYAML(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		// 路径里不该有换行；真有就让 yaml 自己处理，别拼出半个字符串。
		return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// Save 原子写回配置（临时文件 + rename）。
// 注意：这是整文件重写，YAML 注释会丢。只改某个字段请用 SaveWebDAV。
func (c *Config) Save(path string) error {
	out := *c
	out.Path = ""
	raw, err := yaml.Marshal(&out)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SaveWebDAV 只替换 webdav 段里的 username / password / password_hash 三行，
// 其余内容和注释原样保留。找不到字段时退回整文件重写。
func (c *Config) SaveWebDAV(path, user, hash string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	inWebdav := false
	patchedHash := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inWebdav = strings.HasPrefix(trimmed, "webdav:")
			continue
		}
		if !inWebdav {
			continue
		}
		pad := strings.Repeat(" ", indent)
		key := strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[0])
		switch key {
		case "username":
			lines[i] = pad + "username: " + user
		case "password":
			lines[i] = pad + `password: ""`
		case "password_hash":
			lines[i] = pad + `password_hash: "` + hash + `"`
			patchedHash = true
		}
	}

	if !patchedHash {
		return c.Save(path)
	}

	out := strings.Join(lines, "\n")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(out), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
