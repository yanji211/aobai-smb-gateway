//go:build linux || windows

package smbhost

// 进程内的纯 Go SMB2/3 服务端托管层（Linux 与 Windows 共用）。
//
// 为什么两个平台共用一份：Windows 版早期走的是"托管系统共享"（net share +
// ForceGuest 整机来宾模式），在 Win11 24H2+ 上有两个绕不过去的问题——
//   1) 24H2 客户端默认强制 SMB 签名，来宾会话没有会话密钥、签不了名，
//      免密共享必然被拒（报"组织的安全策略阻止未经身份验证的来宾访问"）；
//   2) 免密只能靠 ForceGuest=1，那是整机开关：一开，本机所有网络登录都被
//      映射成 Guest，等于为了一个共享把整台机器的网洛身份废掉。
// 换成自研服务端后，两个问题同时消失：认证在进程内做（免密/账号可并存），
// 签名密钥由 NT 哈希派生，Win11 24H2 也能正常签名；而且关闭网关 = 445 立刻
// 不再监听，系统里没有任何残留配置要还原。
//
// Windows 侧多一步：445 由系统 LanmanServer 服务占着（见 port445_windows.go），
// 启动前必须先把它让出来。

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"fsgw/internal/smbgo"
)

const defaultPort = 445

var (
	mu       sync.Mutex
	running  *smbgo.Server
	curName  string
	curRoot  string
	curWrite bool
	curSig   string

	// wantAccounts 是"下次启动要用的账号表"，由 SetAccounts 在 EnsureShare 之前写入。
	wantAccounts []smbgo.Account

	// wantHints 是"下次启动要用的接入端人工指定表"，由 SetClientHints 写入。
	// 它只在连接建立时读一次（决定补哪些兼容处理），所以改了必须重启服务端。
	wantHints  []smbgo.ClientHint
	curHintSig string

	// wantAppleMeta 是"列目录怎么处理 mac 影子文件"（hide / all / off），
	// 由 SetAppleMeta 写入。它是每个新连接建立时抄一份到连接状态里的，
	// 所以改了同样要重启。
	wantAppleMeta string
	curAppleMeta  string

	// wantSMB1 是"纯 SMB1 客户端转交给谁"，由 SetSMB1Backend 写入（空 = 不转交）。
	wantSMB1 string
	curSMB1  string
)

// goSetAccounts 设置允许登录的 SMB 客户端账号表（自研服务端用它做 NTLM 校验）。
//
// 必须在 EnsureShare 之前调用：一是服务端启动时就要知道账号表，
// 二是账号表变化会触发一次重启（见 startLocked 里的签名比较）。
// 传空表表示纯来宾模式。
func goSetAccounts(list []smbgo.Account) {
	mu.Lock()
	wantAccounts = append([]smbgo.Account(nil), list...)
	mu.Unlock()
}

// goSetClientHints 设置接入端类型的人工指定表（覆盖协议指纹）。
// 与账号表一样必须在 EnsureShare 之前调用。
func goSetClientHints(list []smbgo.ClientHint) {
	mu.Lock()
	wantHints = append([]smbgo.ClientHint(nil), list...)
	mu.Unlock()
}

// goSetSMB1Backend 设置纯 SMB1 客户端的兜底后端地址（见 smbgo/proxy.go 的 relayToSMB1）。
// 与账号表一样必须在 EnsureShare 之前调用。
func goSetSMB1Backend(addr string) {
	mu.Lock()
	wantSMB1 = strings.TrimSpace(addr)
	mu.Unlock()
}

// goSetAppleMeta 设置"列目录怎么处理 mac 影子文件"（见 smbgo/applemeta.go）。
// 与账号表一样必须在 EnsureShare 之前调用：连接建立时才抄进连接状态。
func goSetAppleMeta(mode string) {
	mu.Lock()
	wantAppleMeta = mode
	mu.Unlock()
}

// hintsSig 把提示表压成可比较字符串，用来判断"要不要因为改了提示而重启"。
func hintsSig(list []smbgo.ClientHint) string {
	parts := make([]string, 0, len(list))
	for _, h := range list {
		if h.IP == "" {
			continue
		}
		parts = append(parts, h.IP+"="+string(h.Kind))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// accountsSig 把账号表压成一个可比较的字符串，用来判断"要不要重启"。
// 只比用户名和哈希，顺序无关。
func accountsSig(list []smbgo.Account) string {
	parts := make([]string, 0, len(list))
	for _, a := range list {
		if a.Name == "" || len(a.NTHash) == 0 {
			continue
		}
		parts = append(parts, strings.ToLower(strings.TrimSpace(a.Name))+"="+hex.EncodeToString(a.NTHash))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// validName 校验共享名。两个平台用同一套规则：Windows 的 net share 允许 "."
// 但 Go 服务端把它当成路径分隔的边界容易出歧义，统一收窄。
func validName(name string) error {
	if name == "" || len(name) > 32 {
		return fmt.Errorf("共享名长度需在 1-32 之间")
	}
	for _, r := range name {
		ok := r == '-' || r == '_' || r == '.' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return fmt.Errorf("共享名只允许字母数字与 -_.")
		}
	}
	return nil
}

// goEnsureShare 启动（或重启）Go SMB 服务端。
func goEnsureShare(name, root string, writable bool) error {
	if err := validName(name); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	return startLocked(name, root, writable)
}

func startLocked(name, root string, writable bool) error {
	if running != nil {
		// app 会先 EnsureShare 再 Enable(guest_writable)，参数一样时别白停一次服务。
		// 账号口令也算参数：改了口令必须重启，否则旧密钥还在用。
		if curName == name && curRoot == root && curWrite == writable &&
			curSig == accountsSig(wantAccounts) && curHintSig == hintsSig(wantHints) &&
			curAppleMeta == wantAppleMeta && curSMB1 == wantSMB1 {
			return nil
		}
		running.Stop()
		running = nil
	}
	// Windows 上 445 被系统 LanmanServer 占着，先让它让出来；Linux 上是空操作。
	if err := ensurePort445(); err != nil {
		return err
	}
	s, err := smbgo.Start(smbgo.Options{
		Addr:        fmt.Sprintf(":%d", defaultPort),
		Root:        root,
		Share:       name,
		ReadOnly:    !writable,
		Accounts:    append([]smbgo.Account(nil), wantAccounts...),
		ClientHints: append([]smbgo.ClientHint(nil), wantHints...),
		AppleMeta:   wantAppleMeta,
		SMB1Backend: wantSMB1,
		Log:         slog.Default(),
	})
	if err != nil {
		return err
	}
	running, curName, curRoot, curWrite = s, name, root, writable
	curAppleMeta = wantAppleMeta
	curSMB1 = wantSMB1
	curSig = accountsSig(wantAccounts)
	curHintSig = hintsSig(wantHints)
	return nil
}

// goRemoveShare 停掉服务端，445 立即关闭。
func goRemoveShare(name string) error {
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		running.Stop()
		running = nil
	}
	curName, curRoot, curWrite = "", "", false
	// 让出 445 之后把系统服务还原（Windows 才会用到）。
	releasePort445()
	return nil
}

// goExists 共享当前是否真的在对外提供。
func goExists(name string) bool {
	mu.Lock()
	defer mu.Unlock()
	return running != nil && name == curName
}

// ShareRoot 当前共享根（诊断用）。
func ShareRoot() string {
	mu.Lock()
	defer mu.Unlock()
	return curRoot
}

// ShareWritable 当前共享是否可写（诊断用）。
func ShareWritable() bool {
	mu.Lock()
	defer mu.Unlock()
	return curWrite
}

// ---------- 免密（自研服务端口径） ----------

// goEnableGuest 按 guest_writable 重设共享的读写属性。
// 服务端自己就是认证方，所以"免密"不需要动系统任何设置，
// 只读也必须在 VFS 层强制（smbgo 已做），文件权限拦不住它。
func goEnableGuest(root string, writable bool) error {
	mu.Lock()
	defer mu.Unlock()
	if running == nil || curName == "" {
		return fmt.Errorf("SMB 共享尚未启动")
	}
	return startLocked(curName, root, writable)
}

// goRestoreGuest 停掉服务端，445 不再监听。系统里没有任何配置需要还原。
func goRestoreGuest(root string) error {
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		running.Stop()
		running = nil
	}
	curName, curRoot, curWrite = "", "", false
	releasePort445()
	return nil
}
