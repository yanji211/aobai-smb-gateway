// Package smbgo 是纯 Go 的 SMB2/3 服务端封装：把共享根直接以 SMB 共享暴露，
// 不需要 samba、不需要 /etc/samba/smb.conf、不需要系统账户。
//
// 认证策略是「宽松」：完整走 NTLMSSP 握手（客户端才认），但校验不过时按来宾放行。
// 这样电视、iOS 文件、Android 文件管理器、Windows 资源管理器都能进，
// 并且不需要事先在系统里建任何账号。代价是——同一个局域网内谁能连上谁就能读，
// 这是方案里明确的取舍（开关即边界，而不是靠口令）。
package smbgo

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/server"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

// ErrReadOnly 只读共享上的写操作。
var ErrReadOnly = errors.New("smbgo: 共享为只读")

type Options struct {
	Addr     string // 默认 :445
	Root     string
	Share    string
	ReadOnly bool
	Log      *slog.Logger

	// AppleMeta 决定列目录时怎么处理 macOS 自动写的元数据文件
	// （.DS_Store、._xxx、.Trashes 等，见 applemeta.go）：
	//
	//	"hide"（留空等同）= 只对非 macOS 接入端隐藏：Windows / Linux / 电视
	//	                    看不到，mac 自己照旧——它读得到自己的 .DS_Store，
	//	                    就不会每次浏览都重写一遍，窗口布局也不丢；
	//	"all"             = 所有接入端都隐藏（含 mac）；
	//	"off"             = 都不过滤，排障用。
	//
	// 只影响"看得见与否"，不动磁盘。
	AppleMeta string

	// SMB1Backend 非空时，只支持 SMB1 的客户端（方言表里没有 SMB 2.xxx）会被
	// 原样转交到这个后端（host:port），由它用 SMB1 服务。
	//
	// 留空（默认）= 用进程内置的最小 SMB1 通道（smb1srv.go）直接服务。
	// 这条内置通道两个平台共用一份代码，Linux 不需要装 samba，Windows 也不需要
	// 打开系统 SMB1 功能——老电视 / 老投影靠它就能看到共享。
	SMB1Backend string

	// Accounts 是允许登录的客户端账号表。空表 = 纯来宾模式。
	//
	// 为什么需要它：Windows 11 24H2 起 SMB 客户端默认强制签名，而来宾会话
	// 没有会话密钥、签不了名（微软原文：即使放开来宾回退，签名也会让它失败）。
	// 只有"真实账号 + 口令"的会话才派生得出签名密钥。
	//
	// 为什么是"表"而不是"一个账号"：每台客户端的名字都不一样。Windows 资源
	// 管理器拿当前登录用户（例如 example-user）来试，电视/手机则发匿名。
	// 表里没有的用户名会被明确拒绝（STATUS_LOGON_FAILURE），客户端因此弹出
	// 正常的"输入网络凭据"，而不是拿到一个注定被 24H2 否决的来宾会话。
	Accounts []Account

	// User / Password / NTHash：单一账号的旧写法，保留兼容。
	// 与 Accounts 同时存在时两边都会生效。
	User     string
	Password string
	// NTHash 是口令的 NT 哈希（十六进制），填了就优先用它，配置里无需留明文。
	NTHash string

	// ClientHints 让人工指定某台机器是什么客户端（见 client.go）。
	// 协议指纹认错时，一行配置就能纠正，不用改代码重发版。
	ClientHints []ClientHint
}

// Account 是一个允许登录的 SMB 客户端账号。
type Account struct {
	Name string // 用户名，不区分大小写
	// NTHash 是 NTOWFv1 = MD4(UTF-16LE(口令))，**不是** ResponseKeyNT。
	// 两者差一层 HMAC：ResponseKeyNT = HMAC_MD5(NTOWFv1, UTF16(UPPER(用户名)+域))，
	// 而域是客户端每轮报上来的，服务端无法预先算死，所以这里存 NTOWFv1。
	NTHash []byte
}

type Server struct {
	srv       *server.Server
	ln        net.Listener
	cancel    context.CancelFunc
	done      chan struct{}
	addr      string
	root      string            // 共享根，代理层用它统计真实的卷容量
	share     string            // 真实共享名，代理层按它纠正客户端发来的大小写
	accounts  map[string][]byte // 小写用户名 → NTOWFv1；代理层按用户名重算签名密钥要用
	hints     []ClientHint      // 人工指定的接入端类型，优先级高于协议指纹
	appleMeta string            // 列目录时怎么处理 macOS 元数据：hide / all / off
	smb1      string            // 纯 SMB1 客户端的兜底后端地址（空 = 用内置 SMB1 通道）
	readOnly  bool              // 共享是否只读；内置 SMB1 通道据此拒绝写
	once      sync.Once
}

// Start 绑定端口并开始服务。绑定失败会同步返回错误，方便上层如实报"445 被占用"。
func Start(o Options) (*Server, error) {
	if o.Addr == "" {
		o.Addr = ":445"
	}
	if o.Share == "" {
		return nil, fmt.Errorf("smbgo: 共享名不能为空")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	// 对外监听由我们自己持有：库只监听回环，我们在这层做 SMB1 协商兼容。
	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return nil, fmt.Errorf("SMB 监听 %s 失败（445 需要 root，且不能与 samba 同时占用）: %w", o.Addr, err)
	}

	backend, err := vfs.NewLocalBackend(o.Root)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("打开共享根失败: %w", err)
	}
	// 库把客户端的 SMB 路径（反斜杠）直接交给 filepath.FromSlash，
	// 在 Unix 上 "a\b" 会被当成一个文件名，导致嵌套目录全部 NOT_FOUND。
	// 在边界处统一转成 / 分隔，顺便把 .. 夹死在共享根内。
	var b vfs.Backend = backend
	if o.ReadOnly {
		b = &readOnlyBackend{root: o.Root, inner: &normalizeBackend{inner: b}}
	} else {
		// 可写模式下必须补两件事：新建文件的句柄得能写（见 createFixBackend），
		// 删除与改名得能被库认出来（库是按 Backend/Handle 的类型断言找 Remover /
		// SetInfoer / Renamer 的，包一层不转发就等于"这个共享不支持删除"）。
		b = &normalizeBackend{inner: &createFixBackend{root: o.Root, inner: b}}
	}

	accounts := buildAccounts(o)
	ctx, cancel := context.WithCancel(context.Background())

	// 内层监听端口**不能写死**。写死会有两种后果，都很脏：
	//  1. 同机第二个实例 bind 失败，但"就绪探测"却能连上第一个实例的端口，
	//     于是一个实例的请求被悄悄转给另一个进程的共享根（只读共享变成可写、
	//     A 目录看到 B 目录的内容），还完全看不出来；
	//  2. 启动报"就绪"而实际没在听。
	// 所以每次启动现取一个空闲端口，并且要求"端口归自己且内层没报错"才算就绪。
	var (
		s         *server.Server
		innerAddr string
		serveErr  chan error
	)
attempts:
	for attempt := 0; attempt < 5; attempt++ {
		addr, err := freeLoopbackAddr()
		if err != nil {
			cancel()
			ln.Close()
			return nil, err
		}
		// IPC$ 必须自己挂：库自带的 srvsvc 实现是坏的（列共享回 NACK / NDR 错位），
		// 客户端打不开 \\服务器 这一级。见 srvsvc.go。
		pb := vfs.NewPipeBackend()
		srv2, err := server.New(
			server.WithAddr(addr),
			server.WithShares(vfs.NewDiskShare(o.Share, b), registerSrvsvc(pb, o.Share)),
			server.WithAuth(authFactory(o.Log, accounts)),
			server.WithLogger(o.Log),
		)
		if err != nil {
			cancel()
			ln.Close()
			return nil, err
		}
		errCh := make(chan error, 1)
		go func() { errCh <- srv2.ListenAndServe(ctx) }()

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case err := <-errCh:
				// 取端口到监听之间被别的进程抢走（极小概率）：换一个端口重来。
				o.Log.Debug("内层监听失败，换端口重试", "addr", addr, "err", err)
				_ = srv2.Shutdown()
				continue attempts
			default:
			}
			if c, derr := net.DialTimeout("tcp", addr, 200*time.Millisecond); derr == nil {
				c.Close()
				s, innerAddr, serveErr = srv2, addr, errCh
				break attempts
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = srv2.Shutdown()
	}
	if s == nil {
		cancel()
		ln.Close()
		return nil, fmt.Errorf("SMB 服务在 3 秒内未就绪")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := <-serveErr; err != nil && ctx.Err() == nil {
			o.Log.Error("SMB 服务异常退出", "err", err)
		}
	}()
	srv := &Server{srv: s, ln: ln, cancel: cancel, done: done, addr: o.Addr, root: o.Root, share: o.Share, accounts: accounts, hints: o.ClientHints, appleMeta: o.AppleMeta, smb1: o.SMB1Backend, readOnly: o.ReadOnly}

	go srv.acceptLoop(o.Log, innerAddr)
	o.Log.Info("SMB 共享已就绪", "addr", o.Addr, "share", o.Share, "root", o.Root, "readonly", o.ReadOnly, "auth", authMode(accounts))
	return srv, nil
}

// freeLoopbackAddr 取一个当前空闲的回环端口。
//
// 从"取到"到"内层真正 bind"之间有个极小的窗口，所以调用方还必须在监听之后
// 回头确认端口确实可用、且服务没有报错，不能只信这个返回值。
func freeLoopbackAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("取空闲端口失败: %w", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return "", err
	}
	return addr, nil
}

// Stop 停止服务并释放 445。可重复调用。
func (s *Server) Stop() {
	s.once.Do(func() {
		if s.ln != nil {
			s.ln.Close()
		}
		s.cancel()
		_ = s.srv.Shutdown()
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
		}
	})
}

// ---------- 认证 ----------

// buildAccounts 把 Options 里的两种写法合并成一张表：小写用户名 → NTOWFv1。
// 账号表优先；旧的单账号写法在名字不冲突时一并合入。
func buildAccounts(o Options) map[string][]byte {
	out := make(map[string][]byte, len(o.Accounts)+1)
	add := func(name string, hash []byte) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || len(hash) == 0 {
			return
		}
		out[name] = hash
	}
	for _, ac := range o.Accounts {
		add(ac.Name, ac.NTHash)
	}
	if _, exists := out[strings.ToLower(o.User)]; !exists {
		if h, ok := ntHashFromHex(o.NTHash); ok {
			add(o.User, h)
		} else if o.User != "" && o.Password != "" {
			add(o.User, ntHashOf(o.Password))
		}
	}
	return out
}

// authFactory 每个会话新建一个认证器：握手形状按 Windows 的样子走。
// 账号表里的用户名必须验口令，匿名类用户名按来宾放行，其余明确拒绝（见 ntlmauth.go）。
func authFactory(log *slog.Logger, accounts map[string][]byte) auth.Factory {
	return func() auth.Authenticator {
		return &ntlmAuth{log: log, accounts: accounts}
	}
}

// authMode 只用于日志，让人一眼看出这台机器认哪些账号、还剩不剩来宾通道。
func authMode(accounts map[string][]byte) string {
	if len(accounts) == 0 {
		return "guest"
	}
	names := make([]string, 0, len(accounts))
	for n := range accounts {
		names = append(names, n)
	}
	sort.Strings(names)
	return "accounts:" + strings.Join(names, ",") + "+guest"
}

// ---------- 路径规范化 ----------

type normalizeBackend struct{ inner vfs.Backend }

func (b *normalizeBackend) Open(ctx context.Context, opts vfs.OpenOptions) (vfs.Handle, error) {
	opts.Path = normalizePath(opts.Path)
	h, err := b.inner.Open(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &stableHandle{inner: h}, nil
}

// Remove 把删除转发给内层，路径同样先规范化。
//
// 库在 CLOSE 处理"删除挂起"的文件时是这样找删除能力的：
//
//	if rm, ok := tr.share.Backend().(vfs.Remover); ok { rm.Remove(ctx, path) }
//
// 断言对象是**最外层**的 backend。以前 normalizeBackend 没实现 Remove，
// 断言必然失败、删除被静默跳过（客户端看到文件还在）。这里补上。
func (b *normalizeBackend) Remove(ctx context.Context, p string) error {
	rm, ok := b.inner.(vfs.Remover)
	if !ok {
		return ErrReadOnly
	}
	return rm.Remove(ctx, normalizePath(p))
}

// ---------- 可写视图：修掉库的"新建文件不可写" ----------

// createFixBackend 只做一件事：让新建出来的文件句柄是**可写**的。
//
// 库的 getFlags 对 FILE_CREATE 只给 os.O_CREATE|os.O_EXCL，没有 O_RDWR，
// 于是句柄是只读的；紧接着的 SMB2 WRITE 一定 EBADF，库再把它映射成
// STATUS_ACCESS_DENIED。外在表现非常迷惑：文件建出来了、大小 0 字节，
// 资源管理器报"目标文件夹访问被拒绝 / 你需要权限来执行此操作"，
// 而覆盖已有文件却完全正常（FILE_OVERWRITE_IF 走的是 O_RDWR）。
//
// 这里在建/截断之后把 Disposition 改成 OPEN_IF 交给库：库对已存在的普通文件
// 用 O_RDWR 打开，写就通了。FILE_CREATE 仍保留 O_EXCL，冲突照旧报已存在。
type createFixBackend struct {
	root  string
	inner vfs.Backend
}

func (b *createFixBackend) Open(ctx context.Context, opts vfs.OpenOptions) (vfs.Handle, error) {
	// 打开目录（CreateDir）与追加打开不动：目录必须只读句柄，追加由库自己处理。
	if opts.CreateDir || opts.Append {
		return b.inner.Open(ctx, opts)
	}
	switch opts.Disposition {
	case vfs.DispositionCreate, vfs.DispositionSupersede,
		vfs.DispositionOverwrite, vfs.DispositionOverwriteIf:
	default:
		return b.inner.Open(ctx, opts)
	}

	full := filepath.Join(b.root, filepath.FromSlash(normalizePath(opts.Path)))
	flags := os.O_CREATE | os.O_RDWR
	if opts.Disposition == vfs.DispositionCreate {
		flags |= os.O_EXCL // 语义不变：已存在就报 NAME_COLLISION
	} else {
		flags |= os.O_TRUNC // SUPERSEDE / OVERWRITE(_IF)：先截断再重写
	}
	f, err := os.OpenFile(full, flags, 0o644)
	if err != nil {
		return nil, err
	}
	_ = f.Close()

	opts.Disposition = vfs.DispositionOpenIf
	return b.inner.Open(ctx, opts)
}

func (b *createFixBackend) Remove(ctx context.Context, p string) error {
	rm, ok := b.inner.(vfs.Remover)
	if !ok {
		return ErrReadOnly
	}
	return rm.Remove(ctx, normalizePath(p))
}

// stableHandle 修正库在 Stat 上给的两处"不稳定"元数据。
//
//  1. ChangeTime：库的 vfs.statToFileInfo 把它写成了 time.Now()，于是同一个文件
//     每 Stat 一次"变更时间"就往前走一点。Windows 把 ChangeTime 当作元数据缓存
//     的失效依据——时间一直在变，它就认为目录随时在改，于是反复打开根目录查属性，
//     永远列不出内容（表现是资源管理器/Get-ChildItem 卡住不动）。这里改成与
//     LastWrite 一致：本地文件系统拿不到真正的 ctime，用 mtime 是唯一稳定的选择。
//  2. 目录的 Size：库把目录的 Size 直接当 AllocationSize / EndOfFile 报，
//     Linux 上目录大小是 4096，而 Windows/SMB 约定目录这两个值都是 0。
type stableHandle struct{ inner vfs.Handle }

func (h *stableHandle) Read(ctx context.Context, off int64, p []byte) (int, error) {
	return h.inner.Read(ctx, off, p)
}
func (h *stableHandle) Write(ctx context.Context, off int64, p []byte) (int, error) {
	return h.inner.Write(ctx, off, p)
}
func (h *stableHandle) Close(ctx context.Context) error { return h.inner.Close(ctx) }
func (h *stableHandle) Enumerate(ctx context.Context, pattern string) iter.Seq2[vfs.FileInfo, error] {
	return h.inner.Enumerate(ctx, pattern)
}

// SetInfo / Rename 必须显式转发：库是在**句柄**上做类型断言找 vfs.SetInfoer /
// vfs.Renamer 的，stableHandle 不实现这两个接口，等于把截断、改时间戳、
// 重命名全变成"不支持"。
func (h *stableHandle) SetInfo(ctx context.Context, req *vfs.SetInfoRequest) error {
	si, ok := h.inner.(vfs.SetInfoer)
	if !ok {
		return ErrReadOnly
	}
	return si.SetInfo(ctx, req)
}

func (h *stableHandle) Rename(ctx context.Context, newPath string, replaceIfExists bool) error {
	rn, ok := h.inner.(vfs.Renamer)
	if !ok {
		return ErrReadOnly
	}
	// 库的 localHandle.Rename 走的是 filepath.Base(filepath.FromSlash(newPath))：
	// Linux 上 FromSlash 原样返回，SMB 传来的 "\dir\b.txt" 会被当成"文件名里带反斜杠"，
	// 于是重命名后目录里多出一个畸形条目，紧接着的目录列举还会报
	// ERROR_BAD_NET_RESP（错误 58）。这里先规范化成 "/" 分隔的相对路径再交给它。
	return rn.Rename(ctx, normalizePath(newPath), replaceIfExists)
}

func (h *stableHandle) Stat(ctx context.Context) (vfs.FileInfo, error) {
	fi, err := h.inner.Stat(ctx)
	if err != nil {
		return fi, err
	}
	if fi.ChangeTime.IsZero() || !fi.ChangeTime.Equal(fi.LastWrite) {
		fi.ChangeTime = fi.LastWrite
	}
	if fi.IsDir {
		fi.Size = 0
	}
	return fi, nil
}

// normalizePath 把 SMB 的 "\a\b" 变成 "a/b"，并夹死任何跳到共享根外的尝试。
func normalizePath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = path.Clean("/" + strings.TrimLeft(p, "/"))
	p = strings.TrimPrefix(p, "/")
	if p == "." {
		return ""
	}
	return p
}

// ---------- 只读视图 ----------

type readOnlyBackend struct {
	root  string
	inner vfs.Backend
}

func (b *readOnlyBackend) Open(ctx context.Context, opts vfs.OpenOptions) (vfs.Handle, error) {
	full := filepath.Join(b.root, filepath.FromSlash(opts.Path))
	fi, statErr := os.Stat(full)

	// 客户端打开目录时会带 FILE_DIRECTORY_FILE（CreateDir=true），
	// 这并不代表要创建目录——已有目录必须放行，否则连列举都会被判成写操作。
	if opts.CreateDir {
		if statErr != nil || !fi.IsDir() {
			return nil, ErrReadOnly
		}
		opts.CreateDir = false
		opts.Disposition = vfs.DispositionOpen
	} else {
		switch opts.Disposition {
		case vfs.DispositionOpen:
			// 只读打开，放行
		case vfs.DispositionOpenIf:
			// "不存在就创建"在只读下退化成"必须已存在"
			if statErr != nil {
				return nil, ErrReadOnly
			}
		default:
			// create / overwrite / supersede 一律拒绝
			return nil, ErrReadOnly
		}
	}
	h, err := b.inner.Open(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &readOnlyHandle{inner: h}, nil
}

type readOnlyHandle struct{ inner vfs.Handle }

func (h *readOnlyHandle) Read(ctx context.Context, off int64, p []byte) (int, error) {
	return h.inner.Read(ctx, off, p)
}
func (h *readOnlyHandle) Write(ctx context.Context, off int64, p []byte) (int, error) {
	return 0, ErrReadOnly
}
func (h *readOnlyHandle) Close(ctx context.Context) error { return h.inner.Close(ctx) }
func (h *readOnlyHandle) Stat(ctx context.Context) (vfs.FileInfo, error) {
	return h.inner.Stat(ctx)
}
func (h *readOnlyHandle) Enumerate(ctx context.Context, pattern string) iter.Seq2[vfs.FileInfo, error] {
	return h.inner.Enumerate(ctx, pattern)
}
