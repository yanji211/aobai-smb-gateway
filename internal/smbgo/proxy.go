//go:build linux || windows

package smbgo

// 这一层是 SMB 协议边界上的"翻译/兼容"层，只做协议字节层面的等价替换，
// 其余字节一律原样转发。
//
//  1. Windows 的 SMB1 协商 → 合成等价的 SMB2 协商。
//     Windows 资源管理器 / net use 连 445 时，第一包常常仍是 SMB1 的
//     SMB_COM_NEGOTIATE（报文里列着 "NT LM 0.12"、"SMB 2.002"、"SMB 2.???"）。
//     纯 SMB2 服务端不回这一包，客户端会一直等到 15 秒超时（系统错误 121）。
//
//  2. 协商响应里补一个 SPNEGO NegTokenInit，并给会话打上来宾标记。
//     库的协商响应安全缓冲区长度为 0，Windows 会据此进入"裸 NTLM"模式——
//     它的 SESSION_SETUP 里塞的是裸 NTLMSSP type-1，但库回的 CHALLENGE 永远
//     是 SPNEGO 包装的，Windows 的 msv1_0 把它当 NTLMSSP 消息解析，签名对不上
//     就直接 RST（表现就是资源管理器报系统错误 53）。补上 NegTokenInit 后
//     Windows 改用 Negotiate/SPNEGO 通道，与 Linux 客户端走同一条路径。
//
//     会话成功响应里的 SessionFlags 必须置 SMB2_SESSION_FLAG_IS_GUEST：库里
//     只有 Identity、没有"来宾"这个概念，永远回 0。Windows 拿到 0 会当成
//     普通登录会话，于是按有会话密钥的路径走——它会给
//     FSCTL_VALIDATE_NEGOTIATE_INFO 这类请求签名并要求响应也签名，而免口令
//     会话根本导不出会话密钥，必然对不上。打上 IS_GUEST 后 Windows 自己就把
//     签名关掉了（samba 的 guest 会话就是这个效果，抓包可对照）。
//
//  3. 签名按会话类型分两种处理，这一点是 Win11 能不能连的关键。
//
//     来宾会话（匿名）：两个方向都抹掉 SMB2_FLAGS_SIGNED 与签名值，让签名
//     变成空操作。来宾没有双方共享的会话密钥，库会用空密钥派生的假密钥去
//     校验客户端签名，必然失败（TREE_CONNECT 被回 STATUS_ACCESS_DENIED）。
//     既然没有秘密可守，直接取消签名——正常客户端在 IS_GUEST 下也不会签名。
//
//     已认证会话（用账号口令登录）：反过来，签名必须保留。因为这一层要改写
//     响应（补 credit、重排目录项、替换卷容量…），改完原签名就失效了，所以
//     用会话密钥把改写过的报文重新签一遍（见 resignChain）。会话密钥由
//     AUTHENTICATE 里的 NTProofStr 现场算出，与内层认证器算的是同一个。
//
//     为什么必须有这条路：Windows 11 24H2 起 SMB 客户端默认强制签名，而签名
//     需要会话密钥、来宾又给不出密钥——微软的说明是「即使放开来宾回退，签名
//     也会让它失败」。所以服务端得提供一个能认证的账号，客户端才走得通。
//
//  4. 目录枚举的语义补全（QUERY_INFO 长度、IPC$ 共享类型、DFS 查询失败码、
//     目录项信息类布局、枚举分页），逐条见对应函数的注释。内层把 IPC$ 当磁盘
//     共享、把不认识的 FSCTL 当坏句柄、对同一句柄只肯枚举一次，这些都是
//     Windows 无法容忍的偏差。
//
// 库没有暴露 listener / 报文钩子，所以对外 445 由我们持有，库只在回环上监听。

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
)

const (
	nbHeaderLen   = 4
	smb2HeaderLen = 64

	smb2CmdNegotiate    = 0
	smb2CmdSessionSetup = 1
	smb2CmdTreeConnect  = 3
	smb2CmdCreate       = 5
	smb2CmdClose        = 6
	smb2CmdIoctl        = 11
	smb2CmdQueryDir     = 14
	smb2CmdQueryInfo    = 16
	smb2CmdSetInfo      = 17
	smb2DialectSMB311   = 0x0311
	smb2FlagSigned      = 0x00000008
	smb2FlagRelated     = 0x00000004
	smb2FlagResponse    = 0x00000001

	// SET_INFO 的 FileInfoClass。
	setInfoClassAllocation = 19 // FILE_ALLOCATION_INFORMATION

	// QUERY_DIRECTORY 的 Flags。
	dirFlagRestartScans      = 0x01 // SMB2_RESTART_SCANS：从头重扫
	dirFlagReturnSingleEntry = 0x02 // SMB2_RETURN_SINGLE_ENTRY：只要一条

	// qdFetchSize 是代理层向内层要目录列表时用的缓冲区长度。
	// 内层不会跳过已发出的条目，只会从第一个条目开始填到装不下为止，
	// 所以想要"全量"就得给一个足够大的数；分页由代理层自己切。
	qdFetchSize = 2 << 20

	// maxSMBFrame 是单帧上限（NetBIOS 长度字段本身允许到 16MB）。
	maxSMBFrame = 8 << 20

	statusBufferOverflow         = 0x80000005
	statusNoMoreFiles            = 0x80000006
	statusMoreProcessingRequired = 0xc0000016
	statusLogonFailure           = 0xc000006d

	// SMB2_SESSION_FLAG_IS_GUEST：告诉客户端"这是免口令的来宾会话"。
	// Windows 看到这一位就不再签名，也不再要求服务端签名。
	smb2SessionFlagGuest = 0x0001

	// TREE_CONNECT 响应里的共享类型。
	shareTypeDisk = 1
	shareTypePipe = 2

	// SMB 方言版本号分界：3.0 起才有 AES-128-CMAC 签名，
	// 2.0.2 / 2.1 只能是 HMAC-SHA256（见 signAlgo）。
	smb2DialectSMB30 = 0x0300

	// IPC$ 的 MaximalAccess。必须跟 Windows 一致用 0x011F01FF：
	// 基础位 0x001F01FF 之外还要带上 ACCESS_SYSTEM_SECURITY(0x01000000)
	// ——原生 Windows 给 IPC$ 的就是这个值（2026-11-10 在 88 上抓包核对）。
	// 列共享（srvsvc 的 NetrShareEnum）是"往命名管道里写请求"，少了
	// FILE_WRITE_DATA(0x2) 的 MaximalAccess 会让一部分客户端在 TREE_CONNECT
	// 成功后直接放弃，连 CREATE srvsvc 都不发——表现为"IPC$ 建树成功、
	// 然后静默"。小米电视（SMB 2.0.2）就是这样，2026-11-10 抓包确认。
	// samba 的历史值 0x001F00A9 在这点上偏保守，别照抄。
	ipcMaximalAccess = 0x011F01FF

	// QUERY_INFO 的 InfoType / FileInfoClass（只关心卷信息那一支）。
	infoTypeFilesystem         = 0x02
	infoTypeFile               = 0x01
	fileFsVolumeInformation    = 0x01 // FILE_FS_VOLUME_INFORMATION
	fileFsSizeInformation      = 0x03 // FILE_FS_SIZE_INFORMATION
	fileFsAttributeInfo        = 0x05 // FILE_FS_ATTRIBUTE_INFORMATION
	fileFsFullSizeInformation  = 0x07 // FILE_FS_FULL_SIZE_INFORMATION
	bytesPerSectorForReporting = 512

	// 下面这两类只有 Linux 内核 CIFS 与 macOS 会问，Windows 从不问。
	// 内层对它们一律回 STATUS_INVALID_PARAMETER，内核据此判"取根 inode 失败"。
	// 见 client.go 的 compat.fsProbe。
	fileFsDeviceInformation     = 0x04 // FILE_FS_DEVICE_INFORMATION
	fileFsSectorSizeInformation = 0x0b // FILE_FS_SECTOR_SIZE_INFORMATION

	// FILE_ALL_INFORMATION（MS-FSCC 2.4.2）。内核 CIFS 打开共享根目录时用它
	// 一次取回基本/标准/内部/EA/访问/位置/模式/对齐/文件名九段信息。
	fileAllInformation = 0x12

	// 内核要求这块缓冲至少 sizeof(FILE_ALL_INFO)=101 字节（结尾那个
	// FileName[1] 也算在内），不足就报 "buffer length %d smaller than
	// minimum size 101" 并放弃建根 inode。这里统一给 104 字节（4 字节对齐）。
	fileAllInfoLen = 104

	// FILE_FS_DEVICE_INFORMATION 的取值（MS-FSCC 2.4.10）。
	// FILE_DEVICE_DISK 是"这是一个磁盘设备"；FILE_DEVICE_IS_MOUNTED 告诉内核
	// 卷已经挂上（否则某些内核版本会把它当成未挂载的分区去看待）。
	fileDeviceDisk      = 0x00000007
	fileDeviceIsMounted = 0x00000020

	// 卷序列号：只用于"卷的序列号是 XXXX-XXXX"这行显示，取个固定值即可。
	// 不能用 0——有些客户端把 0 当成"没有卷信息"。
	reportedVolumeSerial = 0x5A17C3E4

	// 文件系统属性：区分大小写检索 + 保留大小写 + 盘上使用 Unicode。
	// 组件名长度上限按 255 报（内层把这一格错填成了文件系统名的长度）。
	fsAttrCaseSensitive    = 0x00000007
	maxComponentNameLen    = 255
	reportedFileSystemName = "NTFS"

	// FSCTL_DFS_GET_REFERRALS：Windows 连共享前后都会发一次，判断目标是不是 DFS 路径。
	fsctlDFSGetReferrals = 0x00060194

	// FSCTL_VALIDATE_NEGOTIATE_INFO：Linux 内核 CIFS 在 TREE_CONNECT 之后必发，
	// 要求服务端把协商结果原样复述一遍（Capabilities / ServerGuid / SecurityMode /
	// Dialect）。任何一项对不上，内核直接放弃挂载并报
	// "protocol revalidation - security settings mismatch"。
	fsctlValidateNegotiateInfo = 0x00140204

	statusInvalidHandle = 0xc0000008
	statusNotFound      = 0xc0000225
)

// smbTrace 打开后逐帧打印双向 SMB2 命令流（命令、MessageId、状态码、长度）。
//
// 只在现场排查"某个客户端连不上"时用：常态日志只记录被改写的帧，看不出
// "客户端到底在哪一步放弃"。用法：FSGW_SMB_TRACE=1 启动并开 DEBUG 日志。
var smbTrace = os.Getenv("FSGW_SMB_TRACE") != ""

var smbCmdNames = map[uint16]string{
	0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
	4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH", 8: "READ",
	9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "ECHO",
	14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY", 16: "QUERY_INFO",
	17: "SET_INFO", 18: "OPLOCK_BREAK",
}

// traceFrame 打印一帧的命令行摘要；非 SMB2 帧与关闭追踪时什么都不做。
func traceFrame(log *slog.Logger, dir string, frame []byte) {
	if !smbTrace || len(frame) < nbHeaderLen+smb2HeaderLen {
		return
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return
	}
	cmd := binary.LittleEndian.Uint16(hdr[12:])
	name, ok := smbCmdNames[cmd]
	if !ok {
		name = fmt.Sprintf("CMD%d", cmd)
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse == 0 {
		name += " →"
	} else {
		name = "← " + name
	}
	body := len(frame) - nbHeaderLen - smb2HeaderLen
	args := []any{
		"dir", dir, "cmd", name,
		"status", fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(hdr[8:])),
		"msgID", binary.LittleEndian.Uint64(hdr[24:]),
		"tree", binary.LittleEndian.Uint32(hdr[36:]),
		"bodyLen", body,
	}
	// 树名和文件名是最容易对不上的两个东西，光看 bodyLen 分不出差异
	// （mac 内核和 Windows 的 UNC 写法就不一样），所以请求方向带上原文。
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse == 0 {
		if p := tracePath(cmd, hdr); p != "" {
			args = append(args, "path", p)
		}
	}
	log.Debug("smb-trace", args...)
}

// tracePath 解出请求里的树名 / 文件名，只给 trace 用。
func tracePath(cmd uint16, hdr []byte) string {
	body := hdr[smb2HeaderLen:]
	pick := func(offField, lenField int, base int) string {
		if offField+2 > len(body) || lenField+2 > len(body) {
			return ""
		}
		off := int(binary.LittleEndian.Uint16(body[offField:]))
		n := int(binary.LittleEndian.Uint16(body[lenField:]))
		// 偏移从 SMB2 头起算；个别实现在这条上从 body 起算，两种都兜住
		for _, from := range []int{off - base, off} {
			if n > 0 && from >= 0 && from+n <= len(body) {
				return decodeUTF16LE(body[from : from+n])
			}
		}
		return ""
	}
	switch cmd {
	case smb2CmdTreeConnect:
		return pick(4, 6, smb2HeaderLen)
	case smb2CmdCreate:
		return pick(44, 46, smb2HeaderLen)
	}
	return ""
}

// decodeUTF16LE 只为日志服务：不可打印字符换成 '.'，不追求严格。
func decodeUTF16LE(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i:]))
		if r == 0 {
			break
		}
		if r < 0x20 || r > 0x7E {
			sb.WriteByte('.')
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// acceptLoop 接受外部连接并转发到内层服务端。
func (s *Server) acceptLoop(log *slog.Logger, upstream string) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.relay(c, upstream, log)
	}
}

func (s *Server) relay(c net.Conn, upstream string, log *slog.Logger) {
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	first, isSMB1, err := readFrame(c)
	if err != nil {
		// 客户端连上却不发报文（探测端口、或客户端自己放弃）会走到这里。
		// 日志里留一笔，排查"端口通但共享打不开"时能一眼分清是哪一步断的。
		if !errors.Is(err, io.EOF) {
			log.Debug("读取客户端首帧失败", "remote", c.RemoteAddr().String(), "err", err)
		}
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if len(first) > nbHeaderLen {
		log.Debug("收到客户端首帧", "remote", c.RemoteAddr().String(), "firstByte", int(first[nbHeaderLen]))
	}

	rawFirst := first // 识别要用客户端原包，下面 SMB1 会被替换成合成的 SMB2 协商
	if isSMB1 {
		// 纯 SMB1 客户端（只列 NT LM 0.12，没有任何 SMB 2.xxx）没法用内层服务：
		// 它是纯 SMB2/3 实现，把协商改写成 SMB2 之后，这类客户端会收到一份看不懂
		// 的响应然后静默放弃——现象就是"端口通、认证都没开始"。小米电视的 SMB
		// 客户端就是这样（2026-11-10 抓包确认）。
		dial := smb1Dialects(rawFirst)
		if smb1Only(dial) {
			if s.smb1 != "" {
				// 外部后端优先：整条 TCP 连接（含已经读出来的首帧）原样转交，
				// 网关不解析后续任何字节，也不做改写——SMB1 会话全程由后端负责。
				log.Info("接入端只支持 SMB1，转交兼容后端",
					"remote", c.RemoteAddr().String(), "backend", s.smb1, "dialects", dial)
				if err := relayToSMB1(c, first, s.smb1); err != nil {
					log.Warn("SMB1 兼容后端转发中断", "remote", c.RemoteAddr().String(), "err", err)
				}
				return
			}
			// 没配外部后端就用进程内的最小 SMB1 通道。Linux 上配了
			// smb1_backend 走 samba，Windows 上没 samba 就走这条——
			// 两端同一份代码、同一套行为，不靠平台分支。
			log.Info("接入端只支持 SMB1，使用内置 SMB1 通道",
				"remote", c.RemoteAddr().String(), "dialects", dial)
			if err := serveSMB1(c, first, s.root, s.share, !s.readOnly, log); err != nil {
				log.Warn("内置 SMB1 通道中断", "remote", c.RemoteAddr().String(), "err", err)
			}
			return
		}
		// 关键：合成的 SMB2 协商只能声明客户端真正声明过的方言。
		//
		// 之前这里硬编码 3.0.2 + 2.1，等于对整个世界说"我要 3.0.2"。老设备
		// （小米电视 192.0.2.105，2026-11-10 抓包）的 SMB1 探测包里只列
		// 到 `SMB 2.002`，服务端却回 DialectRevision=0x0302——按 MS-SMB2
		// 2.2.4 服务端必须选双方都支持的最高方言，回一个客户端没声明过的
		// 版本属于协议违例，电视直接丢弃连接（之后只发纯 ACK，一个字节的
		// 业务报文都没有）。所以按客户端能力"降级"来回。
		d2 := smb2DialectsFromSMB1(dial)
		if len(d2) == 0 {
			// 方言表解析不出来时按最保守的 2.0.2 回：会发 SMB1 探测又解析
			// 不出的基本都是老客户端，给它 3.x 只会重演同一个问题。
			d2 = []uint16{smb2Dialect202}
		}
		log.Debug("客户端首包是 SMB1 协商，改写为 SMB2 协商",
			"remote", c.RemoteAddr().String(), "dialects", dial, "offer", d2)
		first = smb2NegotiateRequest(d2)
	}

	// 接入端识别：SMB1 能从 NativeOS 直接读出系统名，SMB2 只能靠方言/能力位指纹。
	// 认完再决定要开哪些兼容补丁（见 client.go）。
	info := ClientInfo{Kind: ClientUnknown}
	if isSMB1 {
		// 方言表也放进识别结果：日志里能直接看出"它只到 2.0.2 还是到 3.1.1"，
		// 排查"协商后静默"这类问题时这是第一手信息（之前这条一直是空的）。
		info.Dialects = smb1Dialects(rawFirst)
		if ci := sniffSMB1(rawFirst); ci != nil {
			dial := info.Dialects
			info = *ci
			if len(info.Dialects) == 0 {
				info.Dialects = dial
			}
			info = *ci
		} else {
			// 首包是 SMB1 协商、但报文里没有 NativeOS 自报串——这就是 Windows。
			// 实测 Windows 10/11 的 SMB2 客户端仍会先发一条只列方言的
			// "NT LM 0.12 / SMB 2.002 / SMB 2.???" 探测包，拿到 SMB2 协商响应
			// 后才换成真正的 SMB2 请求；而 Linux 内核 cifs 与 macOS 都是
			// 直接发 SMB2，从不发这一包。所以"发了 SMB1"本身就是判据。
			info = ClientInfo{Kind: ClientWindows, Evidence: []string{"首包为 SMB1 探测包（Windows 特征）"}}
		}
	} else if ci, ok := sniffSMB2(rawFirst[nbHeaderLen:]); ok {
		info = *ci
	}
	if k, ok := matchHint(c.RemoteAddr().String(), s.hints); ok {
		info.Kind = k
		info.Label = k.Label()
		info.Hinted = true
		info.add("配置 client_hints 指定")
	}
	if info.Label == "" {
		info.Label = info.Kind.Label()
	}
	log.Info("SMB 接入端已识别",
		"remote", c.RemoteAddr().String(),
		"client", string(info.Kind), "label", info.Label,
		"dialects", strings.Join(info.Dialects, ","),
		"caps", fmt.Sprintf("0x%08x", info.Caps),
		"evidence", strings.Join(info.Evidence, "；"))

	up, err := net.DialTimeout("tcp", upstream, 3*time.Second)
	if err != nil {
		log.Warn("连接内层 SMB 服务失败", "err", err)
		return
	}
	defer up.Close()

	if _, err := up.Write(first); err != nil {
		return
	}

	st := newConnState(s.root, s.share, s.accounts, openSession(c.RemoteAddr().String()))
	st.client = info
	st.comp = compatFor(info.Kind)
	st.sawSMB1Probe = isSMB1
	st.appleMeta = s.appleMeta
	st.log = log
	st.sess.setClient(info)
	defer st.sess.close()
	done := make(chan struct{}, 2)
	go func() {
		pumpToServer(up, c, st)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		pumpToClient(c, up, log, st)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
}

// connState 记下"这条连接上每个请求问的是什么"，因为响应本身常常不带这些信息：
//   - TREE_CONNECT 响应不带共享名，而 IPC$ 需要区别对待（见 fixIPCTreeConnect）；
//   - IOCTL 的失败响应是 9 字节的 ERROR 体，不带 CtlCode，
//     要判断是不是 DFS 查询只能回头查请求（见 fixDFSReferral）；
//   - QUERY_DIRECTORY 的分页游标得按句柄记，见 fixQueryDirectory；
//   - QUERY_INFO 响应只有一块裸数据，是卷信息还是文件信息全靠请求区分。
type connState struct {
	mu      sync.Mutex
	trees   map[uint64]string   // MessageId → TREE_CONNECT 的 Path
	ioctls  map[uint64]ioctlReq // MessageId → IOCTL 的 CtlCode 与 FileId
	qdir    map[uint64]qdReq    // MessageId → QUERY_DIRECTORY 的请求参数
	qinfo   map[uint64]qinfoReq
	cursors map[string]int // 枚举游标：句柄+通配符 → 已经发给客户端的条目数
	root    string         // 共享根，用来取真实的卷容量
	share   string         // 真实共享名，用来纠正客户端发来的大小写

	// 认证状态：签了名的会话必须保持"字节透明"，凡是我们改写过的报文
	// 都得用会话密钥重新签名，否则客户端直接判 STATUS_INVALID_SIGNATURE。
	accounts  map[string][]byte // 允许登录的账号表：小写用户名 → NTOWFv1
	lastUser  string            // 本连接上客户端最后报上来的用户名（仅用于展示）
	challenge [8]byte
	haveChal  bool
	signKey   []byte       // 非空 = 已认证会话，需要重算 SMB2 签名
	sess      *liveSession // 在线会话登记（面板展示用，不参与鉴权）

	// 接入端识别结果与它对应的兼容画像（见 client.go）。
	client ClientInfo
	comp   compat
	// sawSMB1Probe 记这条连接的首包是不是 SMB1 探测包。Windows 发完探测
	// 就直接建会话，mac 则会再补一条 SMB2 协商——两者靠这个序列才能分开。
	sawSMB1Probe bool

	// appleMeta 是列目录时对 mac 影子文件（.DS_Store / ._xxx 等）的处理方式：
	// "" / "hide" 只对非 macOS 接入端隐藏，"all" 全隐藏，"off" 不过滤。
	// 见 applemeta.go。
	appleMeta string

	// 协商响应的四项自报值。VALIDATE_NEGOTIATE_INFO 必须原样回这几项，
	// 否则内核判"协商结果被篡改"。不能现场重算——内层的 guid 是启动时
	// 随机生成的，这里只有从响应里抄下来才对得上。
	negoCaps    uint32
	negoGuid    [16]byte
	negoSecMode uint16
	negoDialect uint16
	haveNego    bool

	log *slog.Logger // 本连接的日志器，逐帧追踪用（见 traceFrame）

	// 复合请求（SMB2_FLAGS_RELATED_OPERATIONS）的同步换手通道：
	// 代理层把一条复合请求拆成多条独立请求依次发给内层，再合并回一条复合响应。
	// MessageId → 该条响应的投递通道，见 exchangeCompound。
	waitMu  sync.Mutex
	waiters map[uint64]chan []byte
}

// qdReq 是 QUERY_DIRECTORY 请求里代理层关心的参数。
type qdReq struct {
	class   uint8  // FileInformationClass
	single  bool   // SMB2_RETURN_SINGLE_ENTRY
	restart bool   // SMB2_RESTART_SCANS
	outLen  int    // 客户端给的输出缓冲区长度（这一页最多能放多少字节）
	key     string // 分页游标键：FileId + 通配符
}

// qinfoReq 是 QUERY_INFO 请求里代理层关心的参数。
type qinfoReq struct {
	infoType uint8 // 1=文件 2=卷
	class    uint8 // FileInfoClass
}

func newConnState(root, share string, accounts map[string][]byte, sess *liveSession) *connState {
	return &connState{
		trees:    make(map[uint64]string),
		ioctls:   make(map[uint64]ioctlReq),
		qdir:     make(map[uint64]qdReq),
		qinfo:    make(map[uint64]qinfoReq),
		cursors:  make(map[string]int),
		root:     root,
		share:    share,
		accounts: accounts,
		sess:     sess,
		waiters:  make(map[uint64]chan []byte),
	}
}

// noteChallenge 记下服务端这次 SESSION_SETUP 挑战里的 8 字节随机数。
// 认证响应要用它验算 NTProofStr，重算签名也要用它派生的会话密钥。
func (s *connState) noteChallenge(nonce []byte) {
	if len(nonce) != 8 {
		return
	}
	s.mu.Lock()
	copy(s.challenge[:], nonce)
	s.haveChal = true
	s.mu.Unlock()
}

// noteAuthenticate 处理客户端的 AUTHENTICATE：确认它登录的账号在账号表里且口令正确，
// 通过则派生 SMB 签名密钥，之后这条连接上的改写都要重新签名。
//
// 这里只负责"能不能重签"，判定放不放行的是内层的 ntlmAuth——两边的推导必须
// 完全一致（同样从 NTOWFv1 派 ResponseKeyNT，同样是 RC4 解会话密钥），
// 否则会出现"内层放行了但这里没算出密钥"，于是响应不签名，客户端判非签名。
func (s *connState) noteAuthenticate(raw []byte) {
	if len(s.accounts) == 0 {
		return
	}
	am, err := ntlmssp.ParseAuthenticateMessage(raw)
	if err != nil {
		return
	}
	user := ntlmssp.UTF16String(am.UserName)
	domain := ntlmssp.UTF16String(am.DomainName)

	s.mu.Lock()
	s.lastUser = user
	s.mu.Unlock()

	ntHash, ok := s.accounts[strings.ToLower(strings.TrimSpace(user))]
	if !ok || len(ntHash) == 0 {
		return // 未登记的用户名：内层会拒绝，这里无事可做
	}

	s.mu.Lock()
	chal := s.challenge
	have := s.haveChal
	s.mu.Unlock()
	if !have || len(am.NtChallengeResponse) < 16 {
		return
	}
	key := responseKeyNT(ntHash, user, domain)
	proof := ntProof(key, chal[:], am.NtChallengeResponse[16:])
	if !hmac.Equal(proof, am.NtChallengeResponse[:16]) {
		return
	}
	sk := sessionKey(key, proof, am.EncryptedSessionKey, am.Flags)
	// 签名密钥按方言派生：2.0.2 / 2.1 直接用 SessionKey，3.x 才走 KDF（见 signAlgo）。
	var signKey []byte
	if s.signAlgo() == signing.AlgoAESCMAC {
		signKey = signing.DeriveSigningKey(sk)
	} else {
		signKey = append([]byte(nil), sk...)
	}
	s.mu.Lock()
	s.signKey = signKey
	s.mu.Unlock()
}

// noteNegotiate 把协商响应里服务端自报的四个值记下来。
//
// 为什么要抄而不是算：VALIDATE_NEGOTIATE_INFO 的语义是"把你在协商时说过的话
// 再说一遍"，客户端逐字段比对。ServerGuid 是内层启动时随机生成的，外面
// 拿不到也算不出，只能从响应里原样抄。
//
// 返回 true 表示这一帧确实是协商成功响应，且已记录。
func (s *connState) noteNegotiate(frame []byte) bool {
	if len(frame) < nbHeaderLen+smb2HeaderLen+64 {
		return false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdNegotiate {
		return false
	}
	if binary.LittleEndian.Uint32(hdr[8:]) != 0 {
		return false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 65 {
		return false
	}
	s.mu.Lock()
	s.negoSecMode = binary.LittleEndian.Uint16(body[2:])
	s.negoDialect = binary.LittleEndian.Uint16(body[4:])
	s.negoCaps = binary.LittleEndian.Uint32(body[24:])
	// ServerGuid 在响应体的 8..24（MS-SMB2 2.2.4：StructureSize(0) SecurityMode(2)
	// DialectRevision(4) NegotiateContextCount(6) ServerGuid(8) Capabilities(24)…）。
	// 曾经错取成 28..44，那是 MaxTransactSize/MaxReadSize/MaxWriteSize/SystemTime
	// 四段拼起来的垃圾值——内核 CIFS 不校验 GUID，所以挂载照样成；smbclient 会
	// 逐项比对，对不上直接把 TREE_CONNECT 判成 NT_STATUS_ACCESS_DENIED。
	copy(s.negoGuid[:], body[8:24])
	s.haveNego = true
	s.mu.Unlock()
	return true
}

// noteSessionResult 从 SESSION_SETUP 的最终响应里读出结果，记进"登录尝试"表。
//
// 只有代理层能同时知道"客户端报的用户名"（请求侧）和"这次到底成没成"（响应侧），
// 内层库把这两件事分别藏在认证器和分发逻辑里，外面看不见。
func (s *connState) noteSessionResult(frame []byte) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdSessionSetup {
		return
	}
	status := binary.LittleEndian.Uint32(hdr[8:])
	if status == statusMoreProcessingRequired {
		return // 挑战轮，还没有结论
	}
	s.mu.Lock()
	user := s.lastUser
	s.mu.Unlock()
	if user == "" {
		user = "guest"
	}
	remote := ""
	if s.sess != nil {
		remote = s.sess.remote
	}
	switch {
	case status == 0 && s.authed():
		s.sess.setUser(user, false)
		noteAttempt(user, remote, "ok")
	case status == 0:
		s.sess.setUser(user, true)
		noteAttempt(user, remote, "guest")
	case status == statusLogonFailure:
		noteAttempt(user, remote, "denied")
	}
}

// authed 报告这条连接是否已经建立"带会话密钥"的认证会话。
func (s *connState) authed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.signKey) > 0
}

// signAlgo 是本连接该用的 SMB2 签名算法，取决于协商到的方言。
//
// 只有 SMB 3.0 起才有 AES-128-CMAC；2.0.2 与 2.1 一律 HMAC-SHA256。
// 协商还没完成（negoDialect==0）时返回 HMAC——那种时候本来也不签名。
func (s *connState) signAlgo() signing.Algorithm {
	if s.negoDialect >= smb2DialectSMB30 {
		return signing.AlgoAESCMAC
	}
	return signing.AlgoHMACSHA256
}

func (s *connState) signingKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signKey
}

func (s *connState) noteTree(msgID uint64, tree string) {
	s.mu.Lock()
	s.trees[msgID] = tree
	s.mu.Unlock()
	s.sess.addTree(tree)
}

func (s *connState) tree(msgID uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trees[msgID]
}

// ioctlReq 记一次 IOCTL 请求的 CtlCode 与 FileId。
// FileId 必须一起记：内核的 VALIDATE_NEGOTIATE_INFO 响应出错时是 9 字节的
// ERROR 体，里面没有 FileId，重建响应只能回头查请求。
type ioctlReq struct {
	code   uint32
	fileID [16]byte
}

func (s *connState) noteIoctl(msgID uint64, r ioctlReq) {
	s.mu.Lock()
	s.ioctls[msgID] = r
	s.mu.Unlock()
}

func (s *connState) ioctl(msgID uint64) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioctls[msgID].code
}

func (s *connState) ioctlFileID(msgID uint64) [16]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioctls[msgID].fileID
}

func (s *connState) noteQueryDir(msgID uint64, r qdReq) {
	s.mu.Lock()
	s.qdir[msgID] = r
	s.mu.Unlock()
}

func (s *connState) queryDir(msgID uint64) (qdReq, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.qdir[msgID]
	return r, ok
}

func (s *connState) noteQueryInfo(msgID uint64, r qinfoReq) {
	s.mu.Lock()
	s.qinfo[msgID] = r
	s.mu.Unlock()
}

func (s *connState) queryInfo(msgID uint64) (qinfoReq, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.qinfo[msgID]
	return r, ok
}

// cursorBegin 返回本次要从第几条开始发。restart 为真时清零（客户端重新开始枚举）。
func (s *connState) cursorBegin(key string, restart bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if restart {
		s.cursors[key] = 0
		return 0
	}
	return s.cursors[key]
}

func (s *connState) advanceCursor(key string, n int) {
	s.mu.Lock()
	s.cursors[key] += n
	s.mu.Unlock()
}

// forgetCursors 在 CLOSE 时丢掉该句柄的所有游标，别让 map 随句柄无限增长。
func (s *connState) forgetCursors(fileID string) {
	if fileID == "" {
		return
	}
	prefix := fileID + "\x00"
	s.mu.Lock()
	for k := range s.cursors {
		if strings.HasPrefix(k, prefix) {
			delete(s.cursors, k)
		}
	}
	s.mu.Unlock()
}

// noteRequest 记下一条请求的参数。响应的改写全靠这里留下的记录——响应本身
// 往往不带"客户端问的是什么"（见 connState 的注释）。
//
// 常规转发与复合拆分（exchangeCompound）都要走这一步，否则拆出来的那条
// QUERY_INFO 在改写响应时查不到自己问的是哪一类信息。
// fixTreePath 把 TREE_CONNECT 里的共享名改成真实大小写。
//
// 内层库按字面比对共享名，`SHARE` 不等于 `share`，直接回
// STATUS_BAD_NETWORK_NAME(0xC00000CC)。Windows 和 Linux 都把用户输入原样
// 发过来（一般就是小写），只有 macOS 的 SMBFS 会把共享名统一转成大写再发：
//
//	mount -t smbfs //admin@host/share /mnt   →   "\\192.0.2.11\SHARE"
//
// 于是 mac 的表现极具迷惑性——TCP 通、协商通、账号口令认证都通过，服务端
// 只在树连接上留一条 BAD_NETWORK_NAME，客户端侧统一报
// "mount error: 目录: No such file or directory"（内核把树连失败折成了这个）。
//
// 只改共享名那一段字符的大小写，报文长度和所有偏移都不变，因此不需要重算
// 任何 NextCommand / 结构体偏移，也不影响签名（这里是请求方向，签名由内层
// 重算或由我们按会话密钥重签）。
func (st *connState) fixTreePath(frame []byte) {
	if st.share == "" || len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdTreeConnect {
		return
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse != 0 {
		return
	}
	body := hdr[smb2HeaderLen:]
	off := int(binary.LittleEndian.Uint16(body[4:]))
	n := int(binary.LittleEndian.Uint16(body[6:]))
	start := off - smb2HeaderLen
	if n <= 0 || start < 0 || start+n > len(body) {
		return
	}
	path := decodeUTF16LE(body[start : start+n])
	i := strings.LastIndex(path, "\\")
	if i < 0 || i+1 >= len(path) {
		return
	}
	name := path[i+1:]
	// IPC$ 与真实共享名走同一套判断：IPC$ 本来就大写，EqualFold 命中但
	// 与 st.share 不同名，会落到下面的"名字不同"分支直接返回。
	if name == st.share || !strings.EqualFold(name, st.share) {
		return
	}
	if len(name) != len(st.share) {
		return
	}
	tail := body[start+n-2*len(name) : start+n]
	for k := 0; k < len(st.share); k++ {
		tail[2*k] = st.share[k]
	}
	if st.log != nil {
		st.log.Debug("共享名大小写已归一化", "from", name, "to", st.share)
	}
}

// refineClient 用真正的 SMB2 NEGOTIATE 再认一次接入端。
//
// 首包认不准是常态：Windows 与 macOS 的第一包都是 SMB1 探测包，方言表一字
// 不差（"NT LM 0.12" / "SMB 2.002" / "SMB 2.???"），而且两边都不带
// NativeOS 自报串——只看这一包，mac 和 Windows 无从分辨（实测 macOS 11
// 的 SMBFS 3.6.2 就是这样）。
//
// 真正的指纹在紧跟其后的 SMB2 NEGOTIATE 里：macOS 整套声明到 3.1.1 且不带
// SMB2_GLOBAL_CAP_ENCRYPTION，Windows 带 MULTI_CHANNEL/PERSISTENT_HANDLES，
// Linux 内核只声明一个方言。这个时机足够早——TREE_CONNECT 在认证之后才发生，
// 兼容画像在这里修正来得及。
func (st *connState) refineClient(frame []byte) {
	if st.client.Hinted || len(frame) < nbHeaderLen+smb2HeaderLen {
		return
	}
	ci, ok := sniffSMB2After(frame[nbHeaderLen:], st.sawSMB1Probe)
	if !ok {
		return
	}
	old := st.client.Kind
	if st.log != nil {
		// 这条常驻 Debug：二次识别是"首包认不准"时的唯一补救点，出问题
		// 时得能看到它到底拿到了什么判据、结论是什么。
		st.log.Debug("接入端二次识别",
			"first", string(old), "now", string(ci.Kind),
			"dialects", strings.Join(ci.Dialects, ","),
			"caps", fmt.Sprintf("0x%08x", ci.Caps),
			"secmode", fmt.Sprintf("0x%04x", ci.SecMode),
			"evidence", strings.Join(ci.Evidence, "；"))
	}
	if old == ci.Kind {
		return
	}
	prev := st.client
	st.client = *ci
	st.comp = compatFor(ci.Kind)
	st.sess.setClient(*ci)
	if st.log != nil {
		st.log.Info("接入端识别已修正",
			"from", string(old), "from_label", prev.Label,
			"to", string(ci.Kind), "label", ci.Label,
			"dialects", strings.Join(ci.Dialects, ","),
			"caps", fmt.Sprintf("0x%08x", ci.Caps),
			"evidence", strings.Join(ci.Evidence, "；"))
	}
}

func (st *connState) noteRequest(frame []byte) {
	if msgID, tree, ok := parseTreeConnect(frame); ok {
		st.noteTree(msgID, tree)
	}
	if msgID, r, ok := parseIoctl(frame); ok {
		st.noteIoctl(msgID, r)
	}
	if msgID, r, ok := parseQueryDir(frame); ok {
		st.noteQueryDir(msgID, r)
	}
	if msgID, r, ok := parseQueryInfo(frame); ok {
		st.noteQueryInfo(msgID, r)
	}
	if fid, ok := parseClose(frame); ok {
		st.forgetCursors(fid)
	}
	if raw, ok := parseSessionAuth(frame); ok {
		st.noteAuthenticate(raw)
	}
}

// pumpToServer 逐帧转发客户端请求：补 QUERY_INFO 的填充字节、把每次目录枚举
// 改写成"从头全量拿"（分页由代理层自己做）；来宾连接还要抹掉签名，
// 已认证连接反过来——签名必须保留，改写过的报文要重算签名。
func pumpToServer(up net.Conn, c net.Conn, st *connState) {
	for {
		frame, _, err := readFrame(c)
		if err != nil {
			return
		}
		traceFrame(st.log, "to-server", frame)
		st.fixTreePath(frame) // 必须早于 noteRequest：树名会被登记成游标/树键
		st.refineClient(frame)
		st.noteRequest(frame)
		// 带 RELATED_OPERATIONS 的复合请求要拆开逐条换手（见 exchangeCompound）。
		// 必须放在登记之后：拆出来的每条都要能像普通请求一样被响应改写查到。
		if resp, ok := st.exchangeCompound(frame, up); ok {
			if resp != nil {
				if st.authed() {
					resignChain(resp, st.signingKey(), st.signAlgo())
				} else {
					stripSignatures(resp)
				}
				traceFrame(st.log, "to-client", resp)
				if _, err := c.Write(resp); err != nil {
					return
				}
			}
			continue
		}
		if _, _, ok := parseQueryDir(frame); ok {
			forceQueryDirRefresh(frame)
		}
		// 预占空间的 SET_INFO 在代理层直接答成功，不转给内层（内层不认这一类）。
		if ack, ok := ackAllocationSetInfo(frame); ok {
			if st.authed() {
				resignChain(ack, st.signingKey(), st.signAlgo())
			} else {
				stripSignatures(ack)
			}
			if _, err := c.Write(ack); err != nil {
				return
			}
			continue
		}
		frame = padQueryInfo(frame)
		if st.authed() {
			// 已认证：客户端签过名的请求原样保留，我们改过的字段要重新签，
			// 否则内层校验签名失败、整条链回 STATUS_ACCESS_DENIED。
			resignChain(frame, st.signingKey(), st.signAlgo())
		} else {
			stripSignatures(frame)
		}
		if _, err := up.Write(frame); err != nil {
			return
		}
	}
}

// ackAllocationSetInfo 把 SET_INFO 里的 FILE_ALLOCATION_INFORMATION 直接答成功。
//
// 内层的 handleSetInfo 只认四类：FileDispositionInformation / FileBasicInformation /
// FileEndOfFileInformation / FileRenameInformation，其余一律 STATUS_NOT_SUPPORTED。
// 而 Windows 的复制路径（CopyFile、.NET FileStream、资源管理器拖拽）在建好目标文件后
// 会先发一条 FileAllocationInformation 预占空间：
//
//   - 收到 NOT_SUPPORTED，.NET 直接当成致命错误，一个字节都不写 → 目标文件 0 字节，
//     资源管理器弹"目标文件夹访问被拒绝 / 你需要权限来执行此操作"；
//   - 资源管理器的大文件复制则表现为进度走完却报"出现了意外的网络错误"。
//
// 这一条对数据没有影响（只是空间预占的提示，EOF 不变），回成功即可；真正的数据
// 仍然走 SMB2 WRITE 落到同一个句柄上，落盘语义不变。
//
// 请求体布局（SMB2 SET_INFO Request）：StructureSize(2) InfoType(1) FileInfoClass(1)
// BufferLength(4) BufferOffset(2) Reserved(2) AdditionalInformation(4) Buffer。
func ackAllocationSetInfo(frame []byte) ([]byte, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+10 {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdSetInfo {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse != 0 {
		return nil, false // 已经是响应
	}
	if binary.LittleEndian.Uint32(hdr[20:]) != 0 {
		return nil, false // 复合报文交给内层原样处理
	}
	body := hdr[smb2HeaderLen:]
	if body[2] != infoTypeFile { // InfoType：1 = File
		return nil, false
	}
	if body[3] != setInfoClassAllocation {
		return nil, false
	}

	out := make([]byte, nbHeaderLen+smb2HeaderLen+4)
	copy(out, frame[:nbHeaderLen+smb2HeaderLen])
	h := out[nbHeaderLen:]
	binary.LittleEndian.PutUint16(h[4:], smb2HeaderLen) // StructureSize
	binary.LittleEndian.PutUint32(h[8:], 0)             // STATUS_SUCCESS
	binary.LittleEndian.PutUint16(h[12:], smb2CmdSetInfo)
	binary.LittleEndian.PutUint16(h[14:], 32) // 一次给足 credit
	binary.LittleEndian.PutUint32(h[16:], smb2FlagResponse|smb2FlagSigned)
	binary.LittleEndian.PutUint32(h[20:], 0) // 没有 NextCommand
	// SET_INFO Response 只有 StructureSize(2) + Reserved(2)
	binary.LittleEndian.PutUint16(h[smb2HeaderLen:], 2)

	n := len(out) - nbHeaderLen
	out[0] = 0
	out[1] = byte(n >> 16)
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	return out, true
}

// parseSessionAuth 取出 SESSION_SETUP 请求里客户端发来的 NTLMSSP AUTHENTICATE
// （已经剥掉 SPNEGO 外壳）。第一轮的 NEGOTIATE 和收尾确认都会返回 false。
func parseSessionAuth(frame []byte) ([]byte, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdSessionSetup {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagSigned != 0 {
		return nil, false // 已签名的是收尾轮，不会再带新的 AUTHENTICATE
	}
	body := hdr[smb2HeaderLen:]
	if len(body) < 24 {
		return nil, false
	}
	off := int(binary.LittleEndian.Uint16(body[12:]))
	n := int(binary.LittleEndian.Uint16(body[14:]))
	if n == 0 || off < smb2HeaderLen || off+n > len(hdr) {
		return nil, false
	}
	raw, err := ntlmssp.UnwrapSPNEGOToken(hdr[off : off+n])
	if err != nil {
		return nil, false
	}
	if len(raw) < 12 || string(raw[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(raw[8:]) != 3 {
		return nil, false
	}
	return raw, true
}

// forceQueryDirRefresh 把 QUERY_DIRECTORY 请求改写成"从头全量枚举"。
//
// 内层的 handleQueryDirectory 对同一个句柄只会枚举一次：成功返回后立刻置
// enumDone，之后再问一律回 STATUS_NO_MORE_FILES（它没有续页、没有游标）。
// 于是必须反过来用——每次请求都置 SMB2_RESTART_SCANS（内层看到这一位就把
// enumDone 归零重扫），并把 OutputBufferLength 放大到 qdFetchSize，让它把
// 整份目录一次吐出来。客户端真正要的"这一页回多少条"由 fixQueryDirectory
// 按游标切。
//
// 内层不读 FileIndex、也不读 SMB2_RETURN_SINGLE_ENTRY，所以客户端原有的
// 这两个语义完全由代理层负责，不用在这里清零（清了反而丢信息）。
func forceQueryDirRefresh(frame []byte) bool {
	if len(frame) < nbHeaderLen+smb2HeaderLen+32 {
		return false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdQueryDir {
		return false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 33 { // QUERY_DIRECTORY 请求固定体
		return false
	}
	body[3] |= dirFlagRestartScans
	binary.LittleEndian.PutUint32(body[28:], qdFetchSize)
	return true
}

// parseClose 取出 CLOSE 请求的 FileId，用来回收枚举游标。
// 请求体：StructureSize(2) Flags(2) Reserved(4) FileId(16)。
func parseClose(frame []byte) (string, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+24 {
		return "", false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return "", false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdClose {
		return "", false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 24 { // CLOSE 请求固定体
		return "", false
	}
	return string(body[8:24]), true
}

// parseQueryInfo 取出 QUERY_INFO 的 InfoType 与 FileInfoClass。
// 请求体：StructureSize(2) InfoType(1) FileInfoClass(1) OutputBufferLength(4) ...
func parseQueryInfo(frame []byte) (uint64, qinfoReq, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return 0, qinfoReq{}, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return 0, qinfoReq{}, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdQueryInfo {
		return 0, qinfoReq{}, false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 41 { // QUERY_INFO 请求固定体
		return 0, qinfoReq{}, false
	}
	return binary.LittleEndian.Uint64(hdr[24:]), qinfoReq{infoType: body[2], class: body[3]}, true
}

// padQueryInfo 给"最简" QUERY_INFO 请求补 1 字节填充。
//
// 库的 wire.QueryInfoRequest.Parse 要求报文至少有 createBody+41 字节，而
// MS-SMB2 2.2.37 的 QUERY_INFO 请求固定体是 40 字节（StructureSize=41 这个
// 数字把 StructureSize 字段自己也算了进去）。于是 Windows 发来的"不带输入
// 缓冲区"的请求正好是 64+40=104 字节，差 1 字节被判长度不足，库回
// STATUS_INVALID_PARAMETER。
//
// Windows 每次打开文件/目录后都会先问一次 FileNetworkOpenInformation
// （类 0x22，输出 56 字节，无输入），正好落在这个坑里：资源管理器与 Get-ChildItem
// 拿到 INVALID_PARAMETER 就停住不动，10 秒后放弃，报"路径不存在"。
//
// 补一个字节不影响任何字段——SMB2 报文长度由外层承载，库解析时只看前 40 字节。
func padQueryInfo(frame []byte) []byte {
	if len(frame) != nbHeaderLen+smb2HeaderLen+40 {
		return frame
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return frame
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdQueryInfo {
		return frame
	}
	if binary.LittleEndian.Uint16(hdr[smb2HeaderLen:]) != 41 {
		return frame
	}
	out := make([]byte, len(frame)+1)
	copy(out, frame)
	fixNBLength(out)
	return out
}

// pumpToClient 逐帧转发服务端响应，顺便做几处改写。
//
// 已认证会话里这些改写都会让原来的签名失效，所以最后统一重签一次；
// 来宾会话没有密钥，签不了名，只能把签名位抹掉（见 stripSignatures）。
func pumpToClient(c net.Conn, up net.Conn, log *slog.Logger, st *connState) {
	for {
		frame, _, err := readFrame(up)
		if err != nil {
			return
		}
		traceFrame(log, "to-client", frame)
		// 复合请求拆开后是逐条换手的，响应归对应的等待者，不走这里的改写。
		if ch, ok := st.claimWaiter(frame); ok {
			// 复合拆开后的单条响应：改写由 exchangeCompound 负责（它和这里
			// 走的是同一个 patchResponse，行为一致）。
			select {
			case ch <- patchResponse(frame, st, log):
			default: // 等待者已经超时离开，丢掉这条迟到响应
			}
			continue
		}
		frame = patchResponse(frame, st, log)
		if st.authed() {
			resignChain(frame, st.signingKey(), st.signAlgo())
		} else {
			stripSignatures(frame)
		}
		if _, err := c.Write(frame); err != nil {
			return
		}
	}
}

// patchResponse 是一条服务端响应要过的全部字节级改写。
//
// 抽出来是因为有两条路径：常规的逐帧转发，以及复合请求拆开后的同步换手
// （exchangeCompound）。两条路径看到的响应必须是同一个处理结果，否则
// "复合里问的卷容量"和"单独问的卷容量"会得到不同的答案。
func patchResponse(frame []byte, st *connState, log *slog.Logger) []byte {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if out, ok := addSpnegoToNegotiate(frame); ok {
		log.Debug("协商响应已补 SPNEGO NegTokenInit")
		frame = out
	}
	if st.noteNegotiate(frame) {
		log.Debug("协商结果已记下（供 VALIDATE_NEGOTIATE_INFO 复述）",
			"dialect", fmt.Sprintf("0x%04x", st.negoDialect), "caps", fmt.Sprintf("0x%08x", st.negoCaps))
	}
	if nonce, ok := parseSessionChallenge(frame); ok {
		st.noteChallenge(nonce)
	}
	st.noteSessionResult(frame)
	if !st.authed() && markGuestSession(frame) {
		log.Debug("会话成功响应已标记为来宾会话（SessionFlags=IS_GUEST）")
	}
	if tree, ok := fixIPCTreeConnect(frame, st); ok {
		log.Debug("IPC$ 的 TREE_CONNECT 响应已改为命名管道共享", "tree", tree)
	}
	if fixDFSReferral(frame, st) {
		log.Debug("FSCTL_DFS_GET_REFERRALS 的失败码已改为 STATUS_NOT_FOUND")
	}
	if out, ok := fixValidateNegotiateInfo(frame, st); ok {
		// 只有内核 CIFS 会走到这里（Windows 不发或容错）。
		log.Debug("VALIDATE_NEGOTIATE_INFO 响应已按协商结果重建",
			"client", string(st.client.Kind))
		frame = out
	}
	if out, ok := fixQueryDirectory(frame, st); ok {
		log.Debug("QUERY_DIRECTORY 响应已按客户端信息类重排并切页")
		frame = out
	}
	patchedQueryInfo := false
	if out, ok := fixVolumeInfo(frame, st); ok {
		req, _, _ := queryInfoMissed(frame, st)
		log.Debug("QUERY_INFO 响应已重填",
			"infoType", req.infoType, "class", fmt.Sprintf("0x%02x", req.class))
		frame = out
		patchedQueryInfo = true
	}
	if out, ok := fixFileAllInfo(frame, st); ok {
		log.Debug("FILE_ALL_INFORMATION 已按规范补全（内层只给到标准信息）")
		frame = out
		patchedQueryInfo = true
	}
	if !patchedQueryInfo {
		if req, status, ok := queryInfoMissed(frame, st); ok {
			// 排查用：客户端问了我们没接管的信息类，或者接管了但没能答出来。
			log.Debug("QUERY_INFO 响应未改写",
				"infoType", req.infoType,
				"class", fmt.Sprintf("0x%02x", req.class),
				"status", fmt.Sprintf("0x%08x", status))
		}
	}
	if code, status, ok := ioctlMissed(frame, st); ok {
		log.Debug("IOCTL 响应按内层原样转发",
			"code", fmt.Sprintf("0x%08x", code),
			"status", fmt.Sprintf("0x%08x", status))
	}
	grantCredits(frame)
	return frame
}

// exchangeCompound 处理带 SMB2_FLAGS_RELATED_OPERATIONS 的复合请求。
//
// 复合请求里，第二条及之后的消息"沿用上一条 CREATE 打开的句柄"：FileId 字段
// 填的是保留值 0xFFFFFFFFFFFFFFFF（MS-SMB2 3.3.5.2.7）。内层库没有复合语义，
// 把每条消息当成独立请求解析，拿保留 FileId 去查句柄必然 STATUS_INVALID_HANDLE。
//
// 而 Linux 内核 CIFS 与 macOS 打开共享根目录时，正好是这样一个三连击：
//
//	CREATE("") + QUERY_INFO(FileAllInformation) + CLOSE     （一条复合报文）
//
// Windows 拆成三条独立请求发，所以共享在 Windows 上一切正常；内核 CIFS 拿不到
// FileAllInformation 就报 "cifs_read_super: get root inode failed"，挂载失败
// （mount error(9)）。macOS 的资源管理器同样重度使用复合请求，也是这个原因打不开。
//
// 处理办法：拆成独立请求逐条换手——把保留 FileId 替换成上一条 CREATE 响应里
// 返回的真 FileId——再把响应合回一条复合响应。客户端看到的仍是它发出去的那条
// 复合请求应有的结果，语义不变。
//
// 返回 ok=true 表示这条请求由本函数接管（resp 可能为 nil，表示中途出错已放弃）。
func (st *connState) exchangeCompound(frame []byte, up net.Conn) ([]byte, bool) {
	msgs := splitMessages(frame)
	if len(msgs) < 2 {
		return nil, false
	}
	// 没有 RELATED 标志的复合请求内层库能自己处理（实测它会照原样回一条复合
	// 响应），不必插手，免得平白多几次往返。
	related := false
	for _, m := range msgs[1:] {
		if binary.LittleEndian.Uint32(m[nbHeaderLen+16:])&smb2FlagRelated != 0 {
			related = true
			break
		}
	}
	if !related {
		return nil, false
	}

	var lastFileID []byte
	responses := make([][]byte, 0, len(msgs))
	for i, msg := range msgs {
		// 先把保留 FileId 换成上一条 CREATE 返回的真句柄，再做登记。
		// 顺序不能反：登记里要用 FileId 算目录枚举的游标键，拿 0xFF..FF 去算
		// 会跟真句柄分成两个桶，同一个目录就会被整份返回两次（客户端看到
		// 每条目重复一遍）。
		if i > 0 {
			h := msg[nbHeaderLen:]
			// 拆开之后这就是一条普通请求，RELATED 标志必须抹掉，
			// 否则内层库仍会按"句柄沿用上一条"去解释。
			flags := binary.LittleEndian.Uint32(h[16:])
			binary.LittleEndian.PutUint32(h[16:], flags&^smb2FlagRelated)
			if off := fileIDOffset(binary.LittleEndian.Uint16(h[12:])); off > 0 && len(lastFileID) == 16 {
				body := h[smb2HeaderLen:]
				if off+16 <= len(body) && isReservedFileID(body[off:off+16]) {
					copy(body[off:off+16], lastFileID)
				}
			}
		}
		// 内层解析 QUERY_INFO 要求报文至少有 41 字节请求体（StructureSize=41 的
		// 那个尾字节缓冲）。复合请求里的这一条往往正好卡在 40 字节，不补一个
		// 填充字节就会回 STATUS_INVALID_PARAMETER——与常规路径走 padQueryInfo 同理。
		msg = padQueryInfo(msg)
		h := msg[nbHeaderLen:]

		// 拆出来的每条都要单独登记，响应改写才能查到"这条问的是什么"。
		st.noteRequest(msg)
		if _, _, ok := parseQueryDir(msg); ok {
			forceQueryDirRefresh(msg)
		}

		if st.authed() {
			resignChain(msg, st.signingKey(), st.signAlgo())
		} else {
			stripSignatures(msg)
		}

		msgID := binary.LittleEndian.Uint64(h[24:])
		if st.log != nil {
			cmd := binary.LittleEndian.Uint16(h[12:])
			name, ok := smbCmdNames[cmd]
			if !ok {
				name = fmt.Sprintf("CMD%d", cmd)
			}
			st.log.Debug("复合子请求换手", "i", i, "cmd", name, "msgID", msgID, "len", len(msg))
		}
		ch := st.addWaiter(msgID)
		if _, err := up.Write(msg); err != nil {
			st.dropWaiter(msgID)
			return nil, true
		}
		select {
		case resp := <-ch:
			st.dropWaiter(msgID)
			if st.log != nil {
				st.log.Debug("复合子请求已收到响应", "i", i, "msgID", msgID, "len", len(resp))
			}
			// 响应在 pumpToClient 里已经被 patchResponse 改造过（那里是唯一的
			// 改写点），这里只取用，不要再改第二遍——目录分页游标会被推两次。
			responses = append(responses, resp)
			if binary.LittleEndian.Uint16(resp[nbHeaderLen+12:]) == smb2CmdCreate &&
				binary.LittleEndian.Uint32(resp[nbHeaderLen+8:]) == 0 &&
				len(resp) >= nbHeaderLen+smb2HeaderLen+80 {
				lastFileID = append([]byte(nil), resp[nbHeaderLen+smb2HeaderLen+64:nbHeaderLen+smb2HeaderLen+80]...)
			}
		case <-time.After(10 * time.Second):
			// 内层没回，放弃这条复合请求，让客户端自己超时重试。
			st.dropWaiter(msgID)
			if st.log != nil {
				st.log.Debug("复合请求换手超时", "msgID", msgID)
			}
			return nil, true
		}
	}

	return mergeMessages(responses), true
}

// splitMessages 把一条复合报文拆成若干条独立报文（各自带 NetBIOS 头）。
// 每条都清掉 NextCommand，变成可以单独发出去的请求。
func splitMessages(frame []byte) [][]byte {
	if len(frame) < nbHeaderLen+smb2HeaderLen {
		return [][]byte{frame}
	}
	body := frame[nbHeaderLen:]
	if body[0] != 0xFE || string(body[1:4]) != "SMB" {
		return [][]byte{frame}
	}
	var out [][]byte
	off := 0
	for off+smb2HeaderLen <= len(body) {
		h := body[off:]
		next := int(binary.LittleEndian.Uint32(h[20:]))
		end := len(h)
		if next != 0 && next <= len(h) {
			end = next
		}
		msg := make([]byte, nbHeaderLen+end)
		copy(msg[nbHeaderLen:], h[:end])
		binary.LittleEndian.PutUint32(msg[nbHeaderLen+20:], 0)
		fixNBLength(msg)
		out = append(out, msg)
		if next == 0 || next < smb2HeaderLen {
			break
		}
		off += next
	}
	return out
}

// mergeMessages 把若干条独立响应合回一条复合响应。
//
// 第二段起要补上 SMB2_FLAGS_RELATED_OPERATIONS：客户端是按复合报文逐段解析的，
// 缺了这个标志它会把后续段当成"另起一条无关请求"的响应直接丢掉。
//
// 另外 NextCommand 必须是 8 的整数倍（MS-SMB2 3.2.5.1.1）。内层单条响应长度
// 经常不是 8 的倍数——CREATE 响应固定 64+89=153 字节——把 153 直接写进
// NextCommand，客户端就会在 153 这个错位位置读下一条报文的头，解出来的
// ProtocolId 不是 0xFE534D42，于是整条复合响应作废、连接立刻 RST。
// 小米电视（SMB 2.0.2）点开共享就断，就是卡在这里：它把
// CREATE("") + QUERY_INFO + CLOSE 打成一个复合请求发过来，我们回了 153。
//
// 补的零字节属于本条消息（客户端按 NextCommand 切段），签名由调用方在
// 合并之后统一 resignChain 重算，所以这里可以直接改长度。
func mergeMessages(responses [][]byte) []byte {
	total := 0
	for _, r := range responses {
		if len(r) > nbHeaderLen {
			total += len(r) - nbHeaderLen
		}
	}
	out := make([]byte, nbHeaderLen, nbHeaderLen+total)
	last := len(responses) - 1
	for i, r := range responses {
		if len(r) <= nbHeaderLen {
			continue
		}
		m := append([]byte(nil), r[nbHeaderLen:]...)
		if len(m) >= smb2HeaderLen && m[0] == 0xFE {
			if i > 0 {
				flags := binary.LittleEndian.Uint32(m[16:])
				binary.LittleEndian.PutUint32(m[16:], flags|smb2FlagRelated)
			}
			if i == last {
				binary.LittleEndian.PutUint32(m[20:], 0)
			} else {
				for len(m)%8 != 0 {
					m = append(m, 0)
				}
				binary.LittleEndian.PutUint32(m[20:], uint32(len(m)))
			}
		}
		out = append(out, m...)
	}
	fixNBLength(out)
	return out
}

// fileIDOffset 返回各命令请求体里 FileId 字段的偏移。
// 只列会出现在复合请求尾部的那些命令；CREATE / TREE_CONNECT 之类没有 FileId，
// 返回 0 表示"无需替换"。
func fileIDOffset(cmd uint16) int {
	switch cmd {
	case smb2CmdClose, 7 /* FLUSH */, 8 /* READ */, 9 /* WRITE */, 10, /* LOCK */
		smb2CmdIoctl, smb2CmdQueryDir:
		return 8
	case smb2CmdSetInfo:
		return 16
	case smb2CmdQueryInfo:
		return 24
	}
	return 0
}

// isReservedFileID 判断是不是"沿用上一条 CREATE 的句柄"的保留值。
func isReservedFileID(b []byte) bool {
	if len(b) < 16 {
		return false
	}
	for _, c := range b[:16] {
		if c != 0xFF {
			return false
		}
	}
	return true
}

// addWaiter 登记"这条 MessageId 的响应由我同步等待"，返回投递通道。
func (st *connState) addWaiter(msgID uint64) chan []byte {
	ch := make(chan []byte, 1)
	st.waitMu.Lock()
	st.waiters[msgID] = ch
	st.waitMu.Unlock()
	return ch
}
func (st *connState) dropWaiter(msgID uint64) {
	st.waitMu.Lock()
	delete(st.waiters, msgID)
	st.waitMu.Unlock()
}

// claimWaiter 取走这条响应对应的等待者（如果有）。取走后就不再由常规路径
// 改写与转发，避免同一帧既交给等待者又写给客户端。
func (st *connState) claimWaiter(frame []byte) (chan []byte, bool) {
	// 只要够 SMB2 头就够判断。这里不能多要字节：SET_INFO 的响应体只有 2 字节
	// （整帧 70 字节），一旦按"+8"卡长度，它会被判成"不是响应"直接转给客户端，
	// 等待换手的那边只能干等满 10 秒超时——表现就是 Linux 客户端删目录必然失败。
	if len(frame) < nbHeaderLen+smb2HeaderLen {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse == 0 {
		return nil, false
	}
	msgID := binary.LittleEndian.Uint64(hdr[24:])
	st.waitMu.Lock()
	ch, ok := st.waiters[msgID]
	delete(st.waiters, msgID)
	n := len(st.waiters)
	var waiting []uint64
	if !ok && n > 0 {
		waiting = make([]uint64, 0, n)
		for k := range st.waiters {
			waiting = append(waiting, k)
		}
	}
	st.waitMu.Unlock()
	if st.log != nil {
		switch {
		case ok:
			st.log.Debug("复合响应已交给等待者", "msgID", msgID)
		case n > 0:
			// 有人等着换手却对不上号：内层改了 MessageId，或者等待者被后一条
			// 子请求顶掉了。抓 trace 时这行是最直接的线索。
			st.log.Debug("响应 MessageId 与等待者不匹配", "msgID", msgID, "waiting", waiting)
		}
	}
	return ch, ok
}

// parseSessionChallenge 从 SESSION_SETUP 的挑战响应里取出 8 字节 ServerChallenge。
// 响应体：StructureSize(2) SessionFlags(2) SecurityBufferOffset(2) SecurityBufferLength(2)。
func parseSessionChallenge(frame []byte) ([]byte, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+9 {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdSessionSetup {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[8:]) != statusMoreProcessingRequired {
		return nil, false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 9 {
		return nil, false
	}
	off := int(binary.LittleEndian.Uint16(body[4:]))
	n := int(binary.LittleEndian.Uint16(body[6:]))
	if n == 0 || off < smb2HeaderLen || off+n > len(hdr) {
		return nil, false
	}
	raw, err := ntlmssp.UnwrapSPNEGOToken(hdr[off : off+n])
	if err != nil || len(raw) < 32 {
		return nil, false
	}
	if string(raw[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(raw[8:]) != 2 {
		return nil, false
	}
	return raw[24:32], true // CHALLENGE 的 ServerChallenge 固定在 24..32
}

// resignChain 给报文里"我们改写过的、原本带 SIGNED 标志的"SMB2 消息重算签名。
//
// 复合报文要逐段算：签名只覆盖本条消息（到 NextCommand 为止），把后面几条
// 一起算进去必然对不上。
//
// algo 必须与协商方言匹配：SMB 2.0.2 / 2.1 是 HMAC-SHA256，3.0 以上才是
// AES-128-CMAC（见 signAlgo）。用错算法的表现是服务端看着一切正常，客户端
// 却在第一个签名响应上判 STATUS_INVALID_SIGNATURE 然后静默断开。
func resignChain(frame []byte, key []byte, algo signing.Algorithm) {
	if len(key) == 0 {
		return
	}
	off := nbHeaderLen
	for {
		if off+smb2HeaderLen > len(frame) {
			return
		}
		h := frame[off:]
		if h[0] != 0xFE || string(h[1:4]) != "SMB" {
			return
		}
		next := int(binary.LittleEndian.Uint32(h[20:]))
		sub := h
		if next != 0 && next <= len(h) {
			sub = h[:next]
		}
		if binary.LittleEndian.Uint32(h[16:])&smb2FlagSigned != 0 {
			if err := signing.Sign(sub, key, algo); err != nil {
				return
			}
		}
		if next == 0 {
			return
		}
		off += next
	}
}

// parseTreeConnect 从 TREE_CONNECT 请求里取出 MessageId 与目标路径。
//
// 请求体：StructureSize(2) Reserved(1) PathOffset(2) PathLength(2)，
// 路径是 UTF-16LE，偏移相对 SMB2 报文头。
func parseTreeConnect(frame []byte) (uint64, string, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return 0, "", false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return 0, "", false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdTreeConnect {
		return 0, "", false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 9 {
		return 0, "", false
	}
	off := int(binary.LittleEndian.Uint16(body[4:]))
	n := int(binary.LittleEndian.Uint16(body[6:]))
	if n == 0 || off < smb2HeaderLen || off+n > len(hdr) {
		return 0, "", false
	}
	return binary.LittleEndian.Uint64(hdr[24:]), utf16le(hdr[off : off+n]), true
}

// utf16le 把 UTF-16LE 字节串解码成字符串（奇数长度时丢掉最后半个码元）。
func utf16le(raw []byte) string {
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(raw[i:]))
	}
	return string(utf16.Decode(u))
}

// utf16leBytes 把字符串编码成不带 BOM 的 UTF-16LE 字节串。
func utf16leBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			r = '?'
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// fixIPCTreeConnect 把「IPC$」的 TREE_CONNECT 响应改成命名管道共享。
//
// 库里只有一个 DiskShare，任何共享名（包括 IPC$）都按磁盘共享回应：
// ShareType=DISK、MaximalAccess=0x001F01FF。Windows 每次 net use 都会先连
// IPC$，再在 IPC$ 上发 FSCTL_DFS_GET_REFERRALS 判断目标是不是 DFS 路径、
// 之后才连真正的共享。IPC$ 被回成磁盘共享时这个流程走不下去——客户端既不
// 发 DFS 查询也不再往下走，本地干等 10 秒后拆连接，net use 报系统错误 53
// （找不到网络路径）。改成 samba 的回应（PIPE / 0x001F00A9）后客户端照常继续。
func fixIPCTreeConnect(frame []byte, st *connState) (string, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+16 {
		return "", false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return "", false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdTreeConnect || binary.LittleEndian.Uint32(hdr[8:]) != 0 {
		return "", false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 16 { // TREE_CONNECT 响应固定体
		return "", false
	}
	tree := st.tree(binary.LittleEndian.Uint64(hdr[24:]))
	name := tree
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	if !strings.EqualFold(name, "IPC$") {
		return "", false
	}
	body[2] = shareTypePipe
	body[3] = 0
	// ShareFlags 保留内层给的 0x00000030（AUTO_CACHING|VDO_CACHING），
	// 这也是原生 Windows 对 IPC$ 回的值。曾经在这里清零，等于凭空把
	// 一个"和 Windows 不一样"的响应塞给客户端，没必要冒这个险。
	binary.LittleEndian.PutUint32(body[4:], 0x00000030) // ShareFlags
	binary.LittleEndian.PutUint32(body[8:], 0)          // Capabilities
	binary.LittleEndian.PutUint32(body[12:], ipcMaximalAccess)
	return tree, true
}

// markGuestSession 在成功的 SESSION_SETUP 响应上置 SMB2_SESSION_FLAG_IS_GUEST。
//
// 库里没有来宾概念（auth.Identity 只有用户名/域/SID/组），SessionFlags 永远是 0，
// 于是 Windows 把免口令会话当成普通登录会话：它会给防降级校验（FSCTL_VALIDATE_
// NEGOTIATE_INFO）之类的请求签名，并要求响应同样带签名。而本方案不校验口令、
// 拿不到会话密钥，签不出合法的签名，客户端只能判失败并重连。
//
// 补上这一位之后，Windows 与连 samba 的 guest 共享时行为一致：不签名、不要求签名。
func markGuestSession(frame []byte) bool {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdSessionSetup || binary.LittleEndian.Uint32(hdr[8:]) != 0 {
		return false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 9 { // SESSION_SETUP 响应固定体
		return false
	}
	if flags := binary.LittleEndian.Uint16(body[2:]); flags&smb2SessionFlagGuest != 0 {
		return false
	}
	binary.LittleEndian.PutUint16(body[2:], binary.LittleEndian.Uint16(body[2:])|smb2SessionFlagGuest)
	return true
}

// parseIoctl 从 IOCTL 请求里取出 MessageId 与 CtlCode。
// 请求体：StructureSize(2) Reserved(1) CtlCode(4) FileId(16) ...
func parseIoctl(frame []byte) (uint64, ioctlReq, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return 0, ioctlReq{}, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return 0, ioctlReq{}, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdIoctl {
		return 0, ioctlReq{}, false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 57 { // IOCTL 请求固定体
		return 0, ioctlReq{}, false
	}
	var r ioctlReq
	r.code = binary.LittleEndian.Uint32(body[4:])
	copy(r.fileID[:], body[8:24])
	return binary.LittleEndian.Uint64(hdr[24:]), r, true
}

// fixDFSReferral 把 FSCTL_DFS_GET_REFERRALS 的 STATUS_INVALID_HANDLE 改成 STATUS_NOT_FOUND。
//
// Windows 每次 net use 都会问一次"这个 UNC 是不是 DFS 路径"：先问 IPC$，连上
// 共享后再问一次。库对任何自己不认识的 FSCTL 都回 STATUS_INVALID_HANDLE
// （它要求带一个已打开的 FileId，而这类请求的 FileId 全是 0xFFFFFFFF）。
// Windows 拿到 INVALID_HANDLE 会当成句柄层面的严重错误，既不重试也不往下走，
// 本地干等 10 秒后拆连接——表现就是 net use "命令成功完成"，但接着列目录报
// 路径不存在。samba 对同一请求回 STATUS_NOT_FOUND，Windows 就正常理解为
// "不是 DFS 路径，继续往下走"。
//
// 失败响应是 9 字节的 ERROR 体，里面没有 CtlCode，所以只能按 MessageId 回查请求。
func fixDFSReferral(frame []byte, st *connState) bool {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdIoctl {
		return false
	}
	if binary.LittleEndian.Uint32(hdr[8:]) != statusInvalidHandle {
		return false
	}
	if st.ioctl(binary.LittleEndian.Uint64(hdr[24:])) != fsctlDFSGetReferrals {
		return false
	}
	binary.LittleEndian.PutUint32(hdr[8:], statusNotFound)
	return true
}

// fixValidateNegotiateInfo 重建 FSCTL_VALIDATE_NEGOTIATE_INFO 的成功响应。
//
// 这个 ioctl 的语义很直白：客户端问"你刚才协商时说的方言/能力/安全模式/GUID
// 分别是多少"，服务端照原样复述，客户端逐项比对。Linux 内核在每次 TREE_CONNECT
// 之后都会发一次，对不上就直接放弃挂载。
//
// 内层那份应答是错的——它把 24 字节实参当成**输入**填（InputOffset/InputCount
// 有值、OutputCount=0），StructureSize 还写着请求的 57。结果内核读到的输出
// 长度为 0，四项比分全是空，于是：
//
//	CIFS: VFS: \\host\share protocol revalidation - security settings mismatch
//	CIFS: VFS: cifs_mount failed w/return code = -5
//
// 这里按 MS-SMB2 2.2.32 重建：48 字节固定体 + 紧跟 24 字节输出（偏移 112 =
// SMB2 头 64 + 固定体 48）。四项值全部来自协商响应本身（noteNegotiate 记的），
// 所以比对必然一致。
//
// 顺带说明为什么对 Windows 也无害：它只在重连时才发这个 ioctl，且原本收到
// 空输出也只是不校验；换成正确答案不会让它改变行为。
func fixValidateNegotiateInfo(frame []byte, st *connState) ([]byte, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdIoctl {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse == 0 {
		return nil, false // 只处理响应
	}
	if binary.LittleEndian.Uint32(hdr[20:]) != 0 {
		return nil, false // 复合报文里不是最后一段就不碰
	}
	msgID := binary.LittleEndian.Uint64(hdr[24:])
	if st.ioctl(msgID) != fsctlValidateNegotiateInfo {
		return nil, false
	}

	st.mu.Lock()
	have := st.haveNego
	caps, guid := st.negoCaps, st.negoGuid
	sec, dialect := st.negoSecMode, st.negoDialect
	comp := st.comp
	st.mu.Unlock()
	if !comp.validateNego || !have {
		return nil, false
	}
	fileID := st.ioctlFileID(msgID)

	// 输出固定 24 字节：Capabilities(4) ServerGuid(16) SecurityMode(2) Dialect(2)，
	// 方言直接放在偏移 22。
	//
	// 这个长度是被客户端钉死的，不能"多给一点"：
	//   - Linux 内核按 sizeof(struct validate_negotiate_info_rsp)=24 校验，多一个
	//     字节就报 "Invalid protocol negotiate response size: 26" 并直接放弃
	//     挂载（cifs_mount failed w/return code = -5）；
	//   - smbclient 在请求里把 MaxOutputResponse 写成 24，超出的输出同样会被判
	//     畸形响应（NT_STATUS_INVALID_NETWORK_RESPONSE）。
	//
	// 注意 Samba 客户端在**请求**里用的是扩展布局（Capabilities/Guid/SecurityMode/
	// DialectCount/Dialects[]），但**响应**要的仍是这 24 字节——两者不要混。
	const fixedLen = 48
	out := make([]byte, nbHeaderLen+smb2HeaderLen+fixedLen+24)
	copy(out, frame[:nbHeaderLen+smb2HeaderLen])
	h := out[nbHeaderLen:]
	binary.LittleEndian.PutUint32(h[8:], 0)  // STATUS_SUCCESS
	binary.LittleEndian.PutUint32(h[20:], 0) // 不再是复合报文

	b := h[smb2HeaderLen:]
	binary.LittleEndian.PutUint16(b[0:], 49) // StructureSize
	binary.LittleEndian.PutUint32(b[4:], fsctlValidateNegotiateInfo)
	copy(b[8:24], fileID[:])
	binary.LittleEndian.PutUint32(b[24:], 0)   // InputOffset
	binary.LittleEndian.PutUint32(b[28:], 0)   // InputCount
	binary.LittleEndian.PutUint32(b[32:], 112) // OutputOffset（相对 SMB2 头）
	binary.LittleEndian.PutUint32(b[36:], 24)  // OutputCount
	binary.LittleEndian.PutUint32(b[40:], 1)   // SMB2_0_IOCTL_IS_FSCTL
	binary.LittleEndian.PutUint32(b[44:], 0)   // Reserved2

	data := b[fixedLen:]
	binary.LittleEndian.PutUint32(data[0:], caps)
	copy(data[4:20], guid[:])
	binary.LittleEndian.PutUint16(data[20:], sec)
	binary.LittleEndian.PutUint16(data[22:], dialect)

	fixNBLength(out)
	return out, true
}

// parseQueryDir 取出 QUERY_DIRECTORY 请求的完整参数。
//
// 请求体（MS-SMB2 2.2.33）：
//
//	StructureSize(2) FileInformationClass(1) Flags(1) FileIndex(4)
//	FileId(16) FileNameOffset(2) FileNameLength(2) OutputBufferLength(4) Buffer
func parseQueryDir(frame []byte) (uint64, qdReq, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+32 {
		return 0, qdReq{}, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return 0, qdReq{}, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdQueryDir {
		return 0, qdReq{}, false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 33 {
		return 0, qdReq{}, false
	}
	fileID := string(body[8:24])

	// 通配符是 UTF-16LE，空串等价于 "*"。它参与游标键：
	// 同一个句柄换通配符就是另一次枚举，不能共用游标。
	pattern := "*"
	if off, n := int(binary.LittleEndian.Uint16(body[24:])), int(binary.LittleEndian.Uint16(body[26:])); n > 0 &&
		off >= smb2HeaderLen && off+n <= len(hdr) {
		if s := utf16le(hdr[off : off+n]); s != "" {
			pattern = s
		}
	}

	return binary.LittleEndian.Uint64(hdr[24:]), qdReq{
		class:   body[2],
		single:  body[3]&dirFlagReturnSingleEntry != 0,
		restart: body[3]&dirFlagRestartScans != 0,
		outLen:  int(binary.LittleEndian.Uint32(body[28:])),
		key:     fileID + "\x00" + pattern,
	}, true
}

// dirNameOffset 是「客户端请求的信息类」对应的 FileName 在条目内的偏移，
// 也就是该结构体的固定部分长度（MS-FSCC 2.4.x）：
//
//	0x01 FileDirectoryInformation        64
//	0x02 FileFullDirectoryInformation    68   + EaSize(4)
//	0x03 FileBothDirectoryInformation    94   + EaSize(4) ShortNameLength(1) Reserved(1) ShortName(24)
//	0x25 FileIdBothDirectoryInformation 104   在上面 94 之后补 2 字节对齐 + FileId(8)
//	0x26 FileIdFullDirectoryInformation  80   + EaSize(4) 补 4 字节对齐 + FileId(8)
//
// 这些数字不是推算出来的：对照 samba 的 0x25 响应，名字确实从 104 开始；
// 对照我们自己 0x03 的响应，名字确实从 94 开始（抓包逐字节核对过）。
var dirNameOffset = map[uint8]int{0x01: 64, 0x02: 68, 0x03: 94, 0x25: 104, 0x26: 80}

// dirEnt 是把任意形状的目录项归一化之后的样子：
// 前 64 字节是各信息类共有的固定字段，name 是 UTF-16LE 文件名。
type dirEnt struct {
	base [64]byte
	name []byte
}

// parseDirEntries 按给定名字偏移解析目录项链表。
func parseDirEntries(src []byte, nameOff int) []dirEnt {
	var out []dirEnt
	for pos := 0; pos+nameOff <= len(src); {
		e := src[pos:]
		nameLen := int(binary.LittleEndian.Uint32(e[60:]))
		if nameOff+nameLen > len(e) {
			break
		}
		var d dirEnt
		copy(d.base[:], e[:64])
		d.name = append([]byte(nil), e[nameOff:nameOff+nameLen]...)
		out = append(out, d)
		next := int(binary.LittleEndian.Uint32(e[0:]))
		if next <= 0 || pos+next > len(src) {
			break
		}
		pos += next
	}
	return out
}

// encodeDirEntry 把归一化条目按目标信息类的布局重新编码，并按 8 字节对齐。
// 顺手修正两处元数据：目录的 EndOfFile/AllocationSize 必须是 0；
// ChangeTime 必须等于 LastWriteTime（内层给的是 time.Now()，会让客户端
// 认为目录一直在变、反复重查）。
func encodeDirEntry(d *dirEnt, nameOff int) []byte {
	f := d.base
	if attrs := binary.LittleEndian.Uint32(f[56:]); attrs&fileAttrDirectory != 0 {
		copy(f[40:48], zero8[:]) // AllocationSize
		copy(f[48:56], zero8[:]) // EndOfFile
	}
	copy(f[32:40], f[24:32]) // ChangeTime = LastWriteTime

	buf := make([]byte, 0, nameOff+len(d.name)+8)
	buf = append(buf, f[:]...)
	buf = append(buf, make([]byte, nameOff-64)...)
	buf = append(buf, d.name...)
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

// fixQueryDirectory 把内层吐出的全量目录按客户端的请求切成"这一页"。
//
// 内层只肯每次从头枚举、且没有续页能力（见 forceQueryDirRefresh），所以分页
// 只能在代理层做：请求侧已经强制成"从头全量"，响应侧按句柄游标切出客户端
// 要的那一段，游标走到末尾就回 STATUS_NO_MORE_FILES。
//
// 客户端的两种枚举方式都能覆盖：
//   - 一次要全量（samba 抓包里 Windows 就是 outlen=65536、flags=0 一把要走），
//     游标 0 → 末尾，一页发完；
//   - 先要一条探针（flags=0x02 单条、outlen 刚好一条），游标推到 1，随后
//     flags=0 的"继续"请求拿到剩下的，客户端自己把两段拼起来。
//
// 另外三处必须修（任何一项不做，Windows 都会把整条响应判为非法，报错误 58
// ERROR_BAD_NET_RESP"指定的服务器无法运行请求的操作"——此时 SMB 状态码仍是 0，
// 抓包里完全看不出异常）：信息类布局、单条语义、目录项元数据（见 encodeDirEntry）。
func fixQueryDirectory(frame []byte, st *connState) ([]byte, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+9 {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdQueryDir {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[20:]) != 0 { // 复合报文里不是最后一段就不碰
		return nil, false
	}
	req, known := st.queryDir(binary.LittleEndian.Uint64(hdr[24:]))
	if !known {
		return nil, false
	}
	nameOff, ok := dirNameOffset[req.class]
	if !ok {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[8:]) != 0 { // 内层自己报的错（非枚举成功）不重写
		return nil, false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 9 {
		return nil, false
	}
	outOff := int(binary.LittleEndian.Uint16(body[2:]))
	outLen := int(binary.LittleEndian.Uint32(body[4:]))
	if outOff < smb2HeaderLen || nbHeaderLen+outOff+outLen > len(frame) {
		return nil, false
	}

	// 内层只会产出 0x01 形状，除非客户端正好要 0x25（那时它自己按 0x25 编码）。
	srcNameOff := 64
	if req.class == 0x25 {
		srcNameOff = 104
	}
	entries := parseDirEntries(frame[nbHeaderLen+outOff:], srcNameOff)

	// Apple 元数据过滤必须在游标之前：分页游标记的是"已经发给客户端的条目数"，
	// 只有对同一份过滤后的列表计数，切页才不会错位、NO_MORE_FILES 才不会早到
	// 或迟到一条。过滤后列表可能变短，restart 之外的续页请求自然收敛到末尾。
	if st.hidesAppleMeta() {
		var dropped int
		entries, dropped = filterAppleMeta(entries)
		if dropped > 0 && smbTrace && st.log != nil {
			st.log.Debug("smb-dir", "已过滤 Apple 元数据", dropped, "剩余", len(entries))
		}
	}

	start := st.cursorBegin(req.key, req.restart)
	if smbTrace && st.log != nil {
		st.log.Debug("smb-dir", "class", fmt.Sprintf("0x%02x", req.class),
			"restart", req.restart, "single", req.single, "outLen", req.outLen,
			"key", fmt.Sprintf("%x", req.key), "entries", len(entries), "start", start)
	}
	if start > len(entries) {
		start = len(entries)
	}
	if start == len(entries) {
		return buildQueryDirResponse(frame, statusNoMoreFiles, nil), true
	}

	page := entries[start:]
	if req.single && len(page) > 1 {
		page = page[:1]
	}

	var buf []byte
	sizes := make([]int, 0, len(page))
	for i := range page {
		enc := encodeDirEntry(&page[i], nameOff)
		if len(sizes) == 0 {
			// 单条都放不下：MS-SMB2 要求回 STATUS_BUFFER_OVERFLOW 且不推进游标，
			// 客户端会换更大的缓冲区再来。
			if len(enc) > req.outLen {
				return buildQueryDirResponse(frame, statusBufferOverflow, nil), true
			}
		} else if len(buf)+len(enc) > req.outLen {
			break
		}
		buf = append(buf, enc...)
		sizes = append(sizes, len(enc))
	}
	if len(sizes) == 0 {
		return buildQueryDirResponse(frame, statusNoMoreFiles, nil), true
	}

	// 除最后一条外都要填 NextEntryOffset（指向下一条的起始偏移）。
	for i, off := 0, 0; i < len(sizes); i++ {
		var next uint32
		if i+1 < len(sizes) {
			next = uint32(sizes[i])
		}
		binary.LittleEndian.PutUint32(buf[off:], next)
		off += sizes[i]
	}

	st.advanceCursor(req.key, len(sizes))
	return buildQueryDirResponse(frame, 0, buf), true
}

// buildQueryDirResponse 用给定的状态码和目录项缓冲区重建整条响应。
// 只保留 SMB2 头（MessageId/CreditResponse 等原样带回），其余部分全新生成。
func buildQueryDirResponse(frame []byte, status uint32, buf []byte) []byte {
	out := make([]byte, nbHeaderLen+smb2HeaderLen, nbHeaderLen+smb2HeaderLen+len(buf)+8)
	copy(out, frame[:nbHeaderLen+smb2HeaderLen])
	binary.LittleEndian.PutUint32(out[nbHeaderLen+8:], status)
	if status != 0 {
		// 错误体：StructureSize(9) Reserved(0) ByteCount(0)，内层也是这个形状。
		out = append(out, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		fixNBLength(out)
		return out
	}
	var body [8]byte
	binary.LittleEndian.PutUint16(body[0:], 9)
	binary.LittleEndian.PutUint16(body[2:], smb2HeaderLen+8)  // OutputBufferOffset
	binary.LittleEndian.PutUint32(body[4:], uint32(len(buf))) // OutputBufferLength
	out = append(out, body[:]...)
	out = append(out, buf...)
	fixNBLength(out)
	return out
}

var zero8 [8]byte

// fileAttrDirectory 对应 FILE_ATTRIBUTE_DIRECTORY。
const fileAttrDirectory = 0x10

// fixVolumeInfo 用真实的 statfs 数据回答"卷有多大、剩多少"。
//
// 内层对这块的处理有两处不能忍：
//   - FILE_FS_FULL_SIZE_INFORMATION（0x07）根本没实现，直接回
//     STATUS_INVALID_PARAMETER。Windows 资源管理器与 smbclient 都用这一类问
//     剩余空间，失败后它们会显示 0（smbclient 打印 "blocks of size 0"）。
//   - FILE_FS_SIZE_INFORMATION（0x03）把 BytesPerSector 写在了错误的偏移上，
//     容量恒等于硬编码的 1TB/512GB，与实际磁盘（1.8T ext4）无关。
//
// 这里两种类都自己造：数值来自共享根的 statfs，Windows 与 Linux 客户端从此
// 看到的就是这块盘的真实容量。拿不到 statfs 时保持原样，不做假数据。
func fixVolumeInfo(frame []byte, st *connState) ([]byte, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdQueryInfo {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[20:]) != 0 { // 复合报文里不是最后一段就不碰
		return nil, false
	}
	req, known := st.queryInfo(binary.LittleEndian.Uint64(hdr[24:]))
	if !known || req.infoType != infoTypeFilesystem {
		return nil, false
	}

	var info []byte
	switch req.class {
	case fileFsFullSizeInformation, fileFsSizeInformation:
		units, sectors, bps, ok := diskUnits(st.root)
		if !ok {
			return nil, false
		}
		if req.class == fileFsFullSizeInformation {
			info = make([]byte, 32)
			binary.LittleEndian.PutUint64(info[0:], units.total)
			binary.LittleEndian.PutUint64(info[8:], units.avail)  // CallerAvailableAllocationUnits
			binary.LittleEndian.PutUint64(info[16:], units.avail) // ActualAvailableAllocationUnits
			binary.LittleEndian.PutUint32(info[24:], sectors)
			binary.LittleEndian.PutUint32(info[28:], bps)
		} else {
			info = make([]byte, 24)
			binary.LittleEndian.PutUint64(info[0:], units.total)
			binary.LittleEndian.PutUint64(info[8:], units.avail)
			binary.LittleEndian.PutUint32(info[16:], sectors)
			binary.LittleEndian.PutUint32(info[20:], bps)
		}
	case fileFsVolumeInformation:
		// FILE_FS_VOLUME_INFORMATION（MS-FSCC 2.4.9）：
		//	VolumeCreationTime(8) VolumeSerialNumber(4) VolumeLabelLength(4)
		//	SupportsObjects(1) Reserved(1) VolumeLabel(variable)
		// 卷标从偏移 18 开始，不是 16——内层漏了 SupportsObjects 与保留字节，
		// 卷标整体前移 2 字节，cmd 的 dir 取卷标时校验结构失败，报 58 号错
		// （“指定的服务器无法运行请求的操作”），连目录都不枚举。
		// 这里按规范重建，卷标留空（Windows 显示"卷没有标签"）。
		info = make([]byte, 18)
		binary.LittleEndian.PutUint32(info[8:], reportedVolumeSerial)
		// info[12:16] = VolumeLabelLength = 0
		// info[16] = SupportsObjects = 0，info[17] = 保留
	case fileFsAttributeInfo:
		name := utf16leBytes(reportedFileSystemName)
		info = make([]byte, 12+len(name))
		binary.LittleEndian.PutUint32(info[0:], fsAttrCaseSensitive)
		binary.LittleEndian.PutUint32(info[4:], maxComponentNameLen)
		binary.LittleEndian.PutUint32(info[8:], uint32(len(name)))
		copy(info[12:], name)
	case fileFsDeviceInformation:
		// 只有内核 CIFS / macOS 会问（见 client.go 的 compat.fsProbe）。
		// 内层对这类回 STATUS_INVALID_PARAMETER，而 Linux 内核把"取不到设备信息"
		// 当成致命错误：cifs_read_super: get root inode failed，挂载直接 abort。
		if !st.comp.fsProbe {
			return nil, false
		}
		// FILE_FS_DEVICE_INFORMATION：DeviceType(4) Characteristics(4)。
		info = make([]byte, 8)
		binary.LittleEndian.PutUint32(info[0:], fileDeviceDisk)
		binary.LittleEndian.PutUint32(info[4:], fileDeviceIsMounted)
	case fileFsSectorSizeInformation:
		if !st.comp.fsProbe {
			return nil, false
		}
		// FILE_FS_SECTOR_SIZE_INFORMATION：7 个 ULONG，共 28 字节。
		// 512 逻辑扇区 + 4096 物理扇区是最通用的组合（samba 也这么报），
		// 后面三项是"物理扇区用于原子性/性能"的提示与磁盘请求计数，
		// 客户端只用它们做对齐优化，填 0 不会影响读写。
		info = make([]byte, 28)
		binary.LittleEndian.PutUint32(info[0:], bytesPerSectorForReporting)
		binary.LittleEndian.PutUint32(info[4:], 4096)
		binary.LittleEndian.PutUint32(info[8:], 4096)
		binary.LittleEndian.PutUint32(info[12:], 4096)
	default:
		return nil, false
	}

	// 不做"客户端缓冲区小就截断"。
	//
	// 曾经按 SMB 约定截断过，结果 cmd 的 dir 必然报“指定的服务器无法运行请求的
	// 操作”（ERROR_BAD_NET_RESP，58 号）：它问 FILE_FS_ATTRIBUTE_INFORMATION 时
	// 只给 18 字节输出缓冲，而结构体是 12 字节固定头 + 8 字节 "NTFS"，截到 18
	// 就变成 FileSystemNameLength=8、实际只有 6 字节，客户端一验证结构就判畸形，
	// 连后面的 QUERY_DIRECTORY 都不发了（资源管理器与 .NET 的枚举不走这条路，
	// 所以之前只表现为“dir 不行、其它都行”）。
	//
	// 这几个卷信息结构的长度是固定的（class 5 的名字也恒为 "NTFS"），整体返回
	// 不会超出客户端能力；Windows 与 samba 服务端也是整体回。
	out := buildQueryInfoResponse(frame, info)
	return out, true
}

// buildQueryInfoResponse 用给定数据重建一条成功的 QUERY_INFO 响应。
func buildQueryInfoResponse(frame []byte, info []byte) []byte {
	out := make([]byte, nbHeaderLen+smb2HeaderLen)
	copy(out, frame[:nbHeaderLen+smb2HeaderLen])
	binary.LittleEndian.PutUint32(out[nbHeaderLen+8:], 0) // Status
	var body [8]byte
	binary.LittleEndian.PutUint16(body[0:], 9)
	binary.LittleEndian.PutUint16(body[2:], smb2HeaderLen+8)   // OutputBufferOffset
	binary.LittleEndian.PutUint32(body[4:], uint32(len(info))) // OutputBufferLength
	out = append(out, body[:]...)
	out = append(out, info...)
	fixNBLength(out)
	return out
}

// queryInfoMissed 用于诊断：如果这条 QUERY_INFO 响应没被改写，把客户端问的
// 信息类与内层的原始状态码报出来。现场排查"某个客户端挂不上"时，一眼就能看出
// 是问到了没接管的信息类，还是接管了但数据取不到（比如 statfs 失败）。
func queryInfoMissed(frame []byte, st *connState) (qinfoReq, uint32, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen {
		return qinfoReq{}, 0, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return qinfoReq{}, 0, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdQueryInfo {
		return qinfoReq{}, 0, false
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse == 0 {
		return qinfoReq{}, 0, false
	}
	req, ok := st.queryInfo(binary.LittleEndian.Uint64(hdr[24:]))
	if !ok {
		return qinfoReq{}, 0, false
	}
	return req, binary.LittleEndian.Uint32(hdr[8:]), true
}

// ioctlMissed 同理：把没改写的 IOCTL 响应连同 CtlCode 与状态码报出来。
// VALIDATE_NEGOTIATE_INFO 在日志里"查无此物"，往往是客户端根本没发到这个 ioctl。
func ioctlMissed(frame []byte, st *connState) (uint32, uint32, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen {
		return 0, 0, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return 0, 0, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdIoctl {
		return 0, 0, false
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse == 0 {
		return 0, 0, false
	}
	code := st.ioctl(binary.LittleEndian.Uint64(hdr[24:]))
	if code == 0 {
		return 0, 0, false
	}
	return code, binary.LittleEndian.Uint32(hdr[8:]), true
}

// fixFileAllInfo 把 FILE_ALL_INFORMATION 补齐到规范长度。
//
// 内层只写了两段半：Basic(40) + Standard(24) + 20 字节的"空 Access/Mode/
// Position/EA"，一共 84 字节，而且这 20 字节里的字段顺序与规范不一致（规范要求
// Standard 之后紧跟 Internal(8)/Ea(4)/Access(4)/Position(8)/Mode(4)/Alignment(4)/
// FileName(4+N)）。内核 CIFS 打开共享根目录时按 sizeof(FILE_ALL_INFO)=101 校验：
//
//	CIFS: VFS: buffer length 84 smaller than minimum size 101
//	CIFS: VFS: bogus file nlink value 0        （校验失败后 fattr 全零的连带症状）
//
// 于是根 inode 建不出来，挂载以 mount error(20) Not a directory 收场。
//
// 这里按 MS-FSCC 2.4.2 重建：Basic 与 Standard 的前 64 字节内层是对的，原样搬；
// 之后 Internal/Ea/Access/Position/Mode/Alignment 补零（都是可选信息，Linux 与
// macOS 都不拿它们做判断），文件名给空串，尾部补到 104 字节越过最小长度判据。
func fixFileAllInfo(frame []byte, st *connState) ([]byte, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+8 {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdQueryInfo {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[16:])&smb2FlagResponse == 0 {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[20:]) != 0 { // 复合报文里不是最后一段就不碰
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[8:]) != 0 { // 只改成功响应
		return nil, false
	}
	req, known := st.queryInfo(binary.LittleEndian.Uint64(hdr[24:]))
	if !known || req.infoType != infoTypeFile || req.class != fileAllInformation {
		return nil, false
	}

	body := hdr[smb2HeaderLen:]
	off := int(binary.LittleEndian.Uint16(body[2:]))
	n := int(binary.LittleEndian.Uint32(body[4:]))
	if off < smb2HeaderLen || off+n > len(hdr) || n < 64 {
		return nil, false
	}
	src := hdr[off : off+n]

	info := make([]byte, fileAllInfoLen)
	copy(info[0:40], src[0:40])   // BasicInformation：时间戳与属性都原样保留
	copy(info[40:56], src[40:56]) // AllocationSize / EndOfFile
	nlinks := binary.LittleEndian.Uint32(src[56:])
	if nlinks == 0 {
		// 目录/文件的链接数至少是 1，0 会让内核报 "bogus file nlink value 0"。
		nlinks = 1
	}
	binary.LittleEndian.PutUint32(info[56:], nlinks)
	info[60] = src[60] // DeletePending
	info[61] = src[61] // Directory
	// 62..63 保留；64..72 Internal(IndexNumber)=0；72..76 Ea=EaSize=0；
	binary.LittleEndian.PutUint32(info[76:], 0x001F01FF) // Access: FILE_ALL_ACCESS
	// 80..88 CurrentByteOffset=0；88..92 Mode=0；92..96 Alignment=0；
	// 96..100 FileNameLength=0，其后 4 字节为补齐，不含文件名。
	return buildQueryInfoResponse(frame, info), true
}

// fsUnits 是分配单元口径的容量，避免一次乘法溢出。
type fsUnits struct {
	total, avail uint64
}

// diskUnits 由各平台分别实现：
//   - diskfs_unix.go 用 statfs 取共享根所在文件系统；
//   - diskfs_windows.go 用 GetDiskFreeSpaceExW 取共享根所在卷。
// 取不到时返回 ok=false，代理层会退回库自己的报数。

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// relayToSMB1 把一条"纯 SMB1"的客户端连接整条转交给 SMB1 后端（见 Options.SMB1Backend）。
//
// 为什么要先写 first：首帧已经被 readFrame 读出来了，后端必须拿到完整字节流才能
// 正常工作（它就是靠这条 NEGOTIATE 开始会话的）。之后两个方向都是裸字节转发，
// 网关不解析、不改写——SMB1 会话的方言、认证、路径全部由后端负责。
//
// 不设空闲超时：电视播放视频时这条连接可能几十分钟没有控制命令，设了会把
// 正在播的流掐断。连接的生命周期交给两端自己（任一侧关闭即收尾）。
func relayToSMB1(c net.Conn, first []byte, backend string) error {
	up, err := net.DialTimeout("tcp", backend, 3*time.Second)
	if err != nil {
		return fmt.Errorf("连接 SMB1 后端 %s 失败（服务没起？）: %w", backend, err)
	}
	defer up.Close()
	if _, err := up.Write(first); err != nil {
		return fmt.Errorf("回放首帧给 SMB1 后端失败: %w", err)
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, c)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, up)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	return nil
}

// readFrame 读出一个完整的 NetBIOS 帧（含 4 字节头），并判断它是不是 SMB1。
func readFrame(r io.Reader) ([]byte, bool, error) {
	var hdr [nbHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n <= 0 || n > maxSMBFrame {
		return nil, false, errors.New("smbgo: NetBIOS 帧长度异常")
	}
	out := make([]byte, nbHeaderLen+n)
	copy(out, hdr[:])
	if _, err := io.ReadFull(r, out[nbHeaderLen:]); err != nil {
		return nil, false, err
	}
	// SMB1 报文头是 0xFF 'S' 'M' 'B'；SMB2 是 0xFE 'S' 'M' 'B'。
	isSMB1 := n >= 4 && out[nbHeaderLen] == 0xFF
	return out, isSMB1, nil
}

// addSpnegoToNegotiate 在成功的 SMB2 NEGOTIATE 响应里补 SPNEGO NegTokenInit。
// 已经带安全缓冲区、或方言是 3.1.1（走协商上下文）时不动。
//
// 注意不要动 SecurityMode：库给的是 SigningEnabled（0x0001），与 samba 一致。
// 曾经把它清零过（想着"免口令就不签名"），结果 Windows 认为签名能力被降级，
// 反而触发防降级校验并给请求加签名，把简单问题变成了死结。签名是否真正启用
// 由会话层的 IS_GUEST 决定，与这里的协商位无关。
func addSpnegoToNegotiate(frame []byte) ([]byte, bool) {
	if len(frame) < nbHeaderLen+smb2HeaderLen+64 {
		return nil, false
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(hdr[12:]) != smb2CmdNegotiate {
		return nil, false
	}
	if binary.LittleEndian.Uint32(hdr[8:]) != 0 { // 只改成功响应
		return nil, false
	}
	body := hdr[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 65 { // NEGOTIATE 响应固定体 64 字节
		return nil, false
	}
	if binary.LittleEndian.Uint16(body[4:]) >= smb2DialectSMB311 {
		return nil, false
	}
	if binary.LittleEndian.Uint16(body[58:]) != 0 { // 已有安全缓冲区，尊重服务端
		return nil, false
	}

	blob := spnegoNegTokenInit()
	offset := smb2HeaderLen + len(body) // 固定体之后紧随安全缓冲区
	binary.LittleEndian.PutUint16(body[56:], uint16(offset))
	binary.LittleEndian.PutUint16(body[58:], uint16(len(blob)))

	out := make([]byte, 0, nbHeaderLen+offset+len(blob))
	out = append(out, frame[:nbHeaderLen+offset]...)
	out = append(out, blob...)
	fixNBLength(out)
	return out, true
}

// stripSignatures 清掉响应上的 SIGNED 标志并抹零签名值，复合报文逐段处理。
func stripSignatures(frame []byte) {
	off := nbHeaderLen
	for {
		if off+smb2HeaderLen > len(frame) {
			return
		}
		h := frame[off:]
		if h[0] != 0xFE || string(h[1:4]) != "SMB" {
			return
		}
		if flags := binary.LittleEndian.Uint32(h[16:]); flags&smb2FlagSigned != 0 {
			binary.LittleEndian.PutUint32(h[16:], flags&^smb2FlagSigned)
			for i := 48; i < 64; i++ {
				h[i] = 0
			}
		}
		next := binary.LittleEndian.Uint32(h[20:])
		if next == 0 {
			return
		}
		off += int(next)
	}
}

// grantCredits 给响应补足 SMB2 credit 额度。
//
// 库对每个响应只批 1 个 credit（CreditResponse=1），而客户端每个请求都在要
// 32 个（CreditRequest=0x21）——它显然被饿着。credit 是 SMB2 的流控额度：
// 客户端手里的额度不够，就不敢发"要一次性拿回 64KB 目录列表"这类大请求，
// 于是卡在本地干等（抓包里表现为连开 4 次根目录、查完属性后静默 20 余秒，
// 而一个字节都不再发）。批足额度后客户端立刻正常往下发 QUERY_DIRECTORY。
//
// 每个响应都批 64 个是常见做法（Windows 服务端按需动态批，samba 默认批 32 起），
// 对局域网单用户共享没有副作用。
func grantCredits(frame []byte) {
	if len(frame) < nbHeaderLen+smb2HeaderLen {
		return
	}
	hdr := frame[nbHeaderLen:]
	if hdr[0] != 0xFE || string(hdr[1:4]) != "SMB" {
		return
	}
	if binary.LittleEndian.Uint32(hdr[8:]) != 0 { // 只批成功响应，错误响应保持原样
		return
	}
	if binary.LittleEndian.Uint16(hdr[14:]) >= 64 {
		return
	}
	binary.LittleEndian.PutUint16(hdr[14:], 64)
}

func fixNBLength(frame []byte) {
	n := len(frame) - nbHeaderLen
	frame[0] = 0x00
	frame[1] = byte(n >> 16)
	frame[2] = byte(n >> 8)
	frame[3] = byte(n)
}

// SMB2 方言号，与 MS-SMB2 2.2.3 一致。
const (
	smb2Dialect202 = 0x0202 // SMB 2.0.2
	smb2Dialect210 = 0x0210 // SMB 2.1
)

// smb2DialectsFromSMB1 把 SMB1 探测包里的方言名换算成 SMB2 方言号，从高到低。
//
// 为什么必须换算：客户端在 SMB1 探测包里列出的 SMB2 方言，就是它这一轮愿意
// 接受的最高版本。服务端回超过它的版本属于协议违例（MS-SMB2 2.2.4：服务端
// MUST 选双方都支持的最高方言），客户端会直接丢弃连接。
//
// 映射规则（MS-SMB2 4.2.1 的方言字符串）：
//
//	"SMB 2.1"   → 0x0210
//	"SMB 2.002" → 0x0202
//	"SMB 2.???" → 0x0202   // 2.0.2 的 wildcard 写法（0x02FF），内层库只认 0x0202
//
// 认不出的项一律忽略：宁可少声明一个方言（只会让协商落在更低的版本上，
// 仍然可用），也不能多声明（会直接把客户端打掉）。
func smb2DialectsFromSMB1(dialects []string) []uint16 {
	var out []uint16
	for _, s := range dialects {
		var d uint16
		switch {
		case strings.HasPrefix(s, "SMB 2.1"):
			d = smb2Dialect210
		case strings.HasPrefix(s, "SMB 2.0"), strings.HasPrefix(s, "SMB 2.?"):
			d = smb2Dialect202
		default:
			continue // "NT LM 0.12"、PC NETWORK PROGRAM 之类，是 SMB1 自己的方言
		}
		dup := false
		for _, x := range out {
			if x == d {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] > out[j] })
	return out
}

// smb2NegotiateRequest 造一个最小的 SMB2 NEGOTIATE 请求，方言列表由调用方给定
// （从高到低）。留空按 2.0.2 处理——最保守的一档。
func smb2NegotiateRequest(dialects []uint16) []byte {
	if len(dialects) == 0 {
		dialects = []uint16{smb2Dialect202}
	}
	bodyLen := 36 + 2*len(dialects)
	pkt := make([]byte, 64+bodyLen)

	// SMB2 头
	copy(pkt[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[4:], 64) // StructureSize
	binary.LittleEndian.PutUint16(pkt[6:], 1)  // CreditCharge
	binary.LittleEndian.PutUint16(pkt[12:], 0) // Command = NEGOTIATE
	binary.LittleEndian.PutUint16(pkt[14:], 1) // CreditRequest

	body := pkt[64:]
	binary.LittleEndian.PutUint16(body[0:], 36)                    // StructureSize
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(body[4:], 1)                     // SecurityMode = signing enabled
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+2*i:], d)
	}

	out := make([]byte, nbHeaderLen+len(pkt))
	copy(out[nbHeaderLen:], pkt)
	fixNBLength(out)
	return out
}
