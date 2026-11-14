package smbgo

// 内置 SMB1 服务端：给"只认 NT LM 0.12"的老设备（老电视、老投影、老播放器）
// 提供一条不依赖 samba 的通道。
//
// 为什么需要它：本服务端主体是纯 SMB2/3 实现。Linux 上原来靠一个额外的 samba
// 实例（/etc/fsgw/smb1.conf，只监听 127.0.0.1:4450）兜底，Windows 上没有这个
// 组件，于是老设备连 Windows 版时必然被拒。把最小的 SMB1 服务端放进进程内，
// 两个平台的行为就一致了，也不用再要求用户装 samba。
//
// 范围（刻意做窄）：
//   - 协商 / 匿名会话 / 建树 / 列目录 / 打开 / 读 / 关闭 / 共用枚举
//   - 写、删、改名、设属性：一律 STATUS_ACCESS_DENIED
//   - 不实现签名、DFS、EA、压缩、Unix 扩展
//
// 安全模型与主服务端一致：能连上局域网就能读，边界靠"共享开关"而不是口令。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	smb1HeaderLen = 32

	// 命令字
	smb1CmdCreateDirectory  = 0x00
	smb1CmdDeleteDirectory  = 0x01
	smb1CmdClose            = 0x04
	smb1CmdFlush            = 0x05
	smb1CmdDelete           = 0x06
	smb1CmdRename           = 0x07
	smb1CmdQueryInformation = 0x08
	smb1CmdCheckDirectory   = 0x10
	smb1CmdDiskSize         = 0x80
	smb1CmdTransaction      = 0x25
	smb1CmdEcho             = 0x2B
	smb1CmdReadAndX         = 0x2E
	smb1CmdWriteAndX        = 0x2F
	smb1CmdTransaction2     = 0x32
	smb1CmdTreeDisconnect   = 0x71
	smb1CmdNegotiate        = 0x72
	smb1CmdSessionSetupAndX = 0x73
	smb1CmdLogoffAndX       = 0x74
	smb1CmdTreeConnectAndX  = 0x75
	smb1CmdNTCreateAndX     = 0xA2
	smb1CmdOpenAndX         = 0x2D // 老式 SMB1 客户端（小米电视等）常用它打开文件
)

// NTSTATUS
const (
	smb1StatusSuccess            = 0x00000000
	smb1StatusBufferOverflow     = 0x80000005
	smb1StatusNoMoreFiles        = 0x80000006
	smb1StatusInvalidParameter   = 0xC000000D
	smb1StatusAccessDenied       = 0xC0000022
	smb1StatusObjectNameInvalid  = 0xC0000033
	smb1StatusObjectNameNotFound = 0xC0000034
	smb1StatusObjectPathNotFound = 0xC000003A
	smb1StatusNotSupported       = 0xC00000BB
	smb1StatusBadNetName         = 0xC00000CC
	smb1StatusFileIsADirectory   = 0xC00000BA
	smb1StatusNotADirectory      = 0xC0000103
)

// flags2
const (
	smb1Flags2LongNames = 0x0001
	smb1Flags2NTStatus  = 0x4000
	smb1Flags2Unicode   = 0x8000
)

// TRANS2 子命令
const (
	trans2FindFirst2    = 0x0001
	trans2FindNext2     = 0x0002
	trans2QueryFSInfo   = 0x0003 // TRANS2_QUERY_FS_INFO（0x000E 是 SESSION_SETUP，不是 FS_INFO）
	trans2QueryPathInfo = 0x0005
	trans2QueryFileInfo = 0x0007
)

// FIND_FIRST2 / FIND_NEXT2 的信息级别（MS-CIFS 2.2.6.1.1）。
//
// 这套编号和 QUERY_PATH_INFO / QUERY_FILE_INFO 用的是**两套**，同一个数值含义不同：
// 0x0101 在 FIND 里是 SMB_FIND_FILE_DIRECTORY_INFO（64 字节前缀），在 QUERY 里
// 却是 FILE_BASIC_INFO（40 字节）。曾经按 QUERY 的理解把 0x0101 当成"老式 8.3
// 固定 26 字节"，结果只发 0x0101 的老小米电视进去后目录全乱（显示 5 个同名条目）。
// 前缀长度同时用 samba 的 smbclient 实测校准过（0x0104 → 94、0x0105 → 76）。
const (
	infoFindDir     = 0x0101 // SMB_FIND_FILE_DIRECTORY_INFO：64 字节前缀
	infoFindFullDir = 0x0102 // SMB_FIND_FILE_FULL_DIRECTORY_INFO：68
	infoFindNames   = 0x0103 // SMB_FIND_FILE_NAMES_INFO：12（只有名字）
	infoFindBothDir = 0x0104 // SMB_FIND_FILE_BOTH_DIRECTORY_INFO：94（含 24 字节短名区）
	infoFindIDFull  = 0x0105 // SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO：76
	infoFindIDBoth  = 0x0106 // SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO：102
)

// QUERY_PATH_INFO / QUERY_FILE_INFO 的信息级别（另一套，别和上面混用）
const (
	infoFileBasic    = 0x0101
	infoFileStandard = 0x0102
	infoFileInternal = 0x0103
	infoFileEa       = 0x0104
)

type smb1OpenFile struct {
	f      *os.File
	rel    string
	isDir  bool
	closed bool
	pipe   string // 非空 = IPC$ 上的命名管道（srvsvc 等）
	buf    []byte // 管道未读走的输出
}

type smb1Find struct {
	entries []smb1FindEntry
	idx     int
	pattern string
	level   uint16
}

type smb1FindEntry struct {
	name  string
	size  int64
	isDir bool
	mtime time.Time
	attr  uint32
}

type smb1Session struct {
	c        net.Conn
	root     string
	share    string
	writable bool
	log      *slog.Logger

	unicode  bool
	uid      uint16
	tid      uint16
	nextTID  uint16
	treeRoot string
	ipcTree  bool

	nextFID uint16
	files   map[uint16]*smb1OpenFile
	nextSID uint16
	finds   map[uint16]*smb1Find
}

// serveSMB1 在已经读出的首帧（含 NetBIOS 头）基础上接管整条连接。
// first 一定是 SMB_COM_NEGOTIATE。
func serveSMB1(c net.Conn, first []byte, root, share string, writable bool, log *slog.Logger) error {
	s := &smb1Session{
		c:        c,
		root:     root,
		share:    share,
		writable: writable,
		log:      log,
		uid:      1,
		files:    make(map[uint16]*smb1OpenFile),
		finds:    make(map[uint16]*smb1Find),
		nextFID:  1,
		nextSID:  1,
	}
	defer s.closeAll()

	if len(first) > nbHeaderLen {
		s.unicode = binary.LittleEndian.Uint16(first[10:12])&smb1Flags2Unicode != 0
		if out := s.handle(first[nbHeaderLen:]); out != nil {
			if err := writeSMB1Frame(c, out); err != nil {
				return err
			}
		}
	}
	for {
		frame, _, err := readFrame(c)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(frame) <= nbHeaderLen {
			continue
		}
		req := frame[nbHeaderLen:]
		s.unicode = binary.LittleEndian.Uint16(req[10:12])&smb1Flags2Unicode != 0
		out := s.handle(req)
		if out == nil {
			continue
		}
		if err := writeSMB1Frame(c, out); err != nil {
			return err
		}
	}
}

func writeSMB1Frame(w io.Writer, msg []byte) error {
	hdr := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func (s *smb1Session) closeAll() {
	for _, of := range s.files {
		if of.f != nil {
			_ = of.f.Close()
		}
	}
	s.files = map[uint16]*smb1OpenFile{}
}

// ---------- 报文构造 ----------

// reply 组一条 SMB1 响应。params 是 WordParameters（长度必须是偶数），data 是 ByteCount 区。
func (s *smb1Session) reply(req []byte, status uint32, params, data []byte) []byte {
	out := make([]byte, smb1HeaderLen, smb1HeaderLen+1+len(params)+2+len(data))
	copy(out[:4], req[:4])
	if len(req) > 4 {
		out[4] = req[4]
	}
	binary.LittleEndian.PutUint32(out[5:], status)
	out[9] = 0x80 // SMB_FLAGS_REPLY
	flags2 := uint16(smb1Flags2NTStatus | smb1Flags2LongNames)
	if s.unicode {
		flags2 |= smb1Flags2Unicode
	}
	binary.LittleEndian.PutUint16(out[10:], flags2)
	copy(out[12:14], req[12:14]) // PIDHigh
	binary.LittleEndian.PutUint16(out[24:], s.tid)
	copy(out[26:28], req[26:28]) // PID
	binary.LittleEndian.PutUint16(out[28:], s.uid)
	copy(out[30:32], req[30:32]) // MID

	out = append(out, byte(len(params)/2))
	out = append(out, params...)
	var bc [2]byte
	binary.LittleEndian.PutUint16(bc[:], uint16(len(data)))
	out = append(out, bc[:]...)
	out = append(out, data...)
	return out
}

// errReply 只回状态码，无参数无数据。
func (s *smb1Session) errReply(req []byte, status uint32) []byte {
	return s.reply(req, status, nil, nil)
}

// replyTrans 组一条 TRANSACTION / TRANSACTION2 响应。
//
// 这两条命令的响应不能走 reply()：WordCount 固定 10（20 字节），真正的
// Trans2 参数区与数据区要按 ParameterOffset / DataOffset 放到字节数据区里，
// 而且两者都从 SMB 头起点算偏移。字节数据区开头补 1 个 pad 字节让参数区落在
// 偏移 56——这是 samba / Windows 的固定写法（2026-11-11 抓 110 的 samba 4450
// 逐字节核对过），客户端解析时按偏移取，不依赖这个 pad，但补上最省事。
func (s *smb1Session) replyTrans(req []byte, status uint32, params, data []byte) []byte {
	const transRespWords = 10
	paramOff := smb1HeaderLen + 1 + transRespWords*2 + 2 // 55
	pad := paramOff % 2                                  // 补到 56
	paramOff += pad
	if len(params)%2 == 1 {
		params = append(params, 0)
	}
	dataOff := paramOff + len(params)
	// 数据区要 4 字节对齐：FIND_FIRST2 的 10 字节参数区结束后是 66，不补到 68
	// 客户端会报"解析不出名字"（samba 实测就是 68）。
	if r := dataOff % 4; r != 0 {
		dataOff += 4 - r
	}

	w := make([]byte, transRespWords*2)
	binary.LittleEndian.PutUint16(w[0:], uint16(len(params))) // TotalParameterCount
	binary.LittleEndian.PutUint16(w[2:], uint16(len(data)))   // TotalDataCount
	binary.LittleEndian.PutUint16(w[6:], uint16(len(params))) // ParameterCount
	binary.LittleEndian.PutUint16(w[8:], uint16(paramOff))    // ParameterOffset
	binary.LittleEndian.PutUint16(w[12:], uint16(len(data)))  // DataCount
	binary.LittleEndian.PutUint16(w[14:], uint16(dataOff))    // DataOffset
	w[18] = 0                                                 // SetupCount
	body := make([]byte, 0, dataOff-paramOff+len(data))
	body = append(body, make([]byte, pad)...)
	body = append(body, params...)
	body = append(body, make([]byte, dataOff-paramOff-len(params))...)
	body = append(body, data...)
	return s.reply(req, status, w, body)
}

func (s *smb1Session) encStr(v string) []byte {
	if s.unicode {
		u := utf16.Encode([]rune(v))
		b := make([]byte, (len(u)+1)*2)
		for i, r := range u {
			binary.LittleEndian.PutUint16(b[i*2:], r)
		}
		return b
	}
	return append([]byte(v), 0)
}

func (s *smb1Session) decStr(b []byte) (string, int) {
	if s.unicode {
		for i := 0; i+1 < len(b); i += 2 {
			if b[i] == 0 && b[i+1] == 0 {
				return decodeUTF16Strict(b[:i]), i + 2
			}
		}
		return decodeUTF16Strict(b), len(b)
	}
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return string(b[:i]), i + 1
		}
	}
	return string(b), len(b)
}

func decodeUTF16Strict(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(u))
}

func smb1Filetime(t time.Time) uint64 {
	if t.IsZero() {
		t = time.Unix(0, 0)
	}
	// 1601-01-01 到 1970-01-01 之间是 11644473600 秒
	return uint64(t.Unix()+11644473600)*10000000 + uint64(t.Nanosecond()/100)
}

// nameAfterAlign 去掉文件名前面的 1 字节对齐填充。
//
// SMB1 里字符串要从偶数偏移开始，而 NT_CREATE 的字节数据区起点是
// 33+WordCount*2+2，WordCount=24 时是 83（奇数），客户端就会先补一个 0x00
// 再写名字。不跳过这个字节，UTF-16 名字整体错位成 0x5C00（"尀"），
// 于是所有中文/英文文件名都变成"路径不存在"。
func nameAfterAlign(raw []byte, unicode bool) []byte {
	if unicode && len(raw) >= 2 && raw[0] == 0 && raw[1] != 0 {
		return raw[1:]
	}
	return raw
}

// ---------- 分发 ----------

// dbg 是 nil 安全的 debug 日志：测试里的 session 可能没有初始化 log，
// 直接 s.log.Debug 会空指针 panic。生产环境 s.log 必然有值。
var noopLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func (s *smb1Session) dbg(msg string, args ...any) {
	l := s.log
	if l == nil {
		l = noopLog
	}
	l.Debug(msg, args...)
}

func (s *smb1Session) handle(req []byte) []byte {
	if len(req) < smb1HeaderLen+1 {
		return nil
	}
	// 命令轨迹：电视等老 SMB1 客户端可能只发 OPEN_ANDX / QUERY_PATH_INFO 这类
	// 老命令，掉进 default 回 NOT_SUPPORTED 就会断链（broken pipe）。把这行日志
	// 开着便于抓到"到底发了哪个命令还没实现"。debug 级别，开启配置 Log.Level=debug
	// 才会落盘，生产环境不受影响。
	s.log.Debug("SMB1 cmd", "cmd", req[4], "ipc", s.ipcTree)
	var resp []byte
	switch req[4] {
	case smb1CmdNegotiate:
		resp = s.onNegotiate(req)
	case smb1CmdSessionSetupAndX:
		resp = s.onSessionSetup(req)
	case smb1CmdTreeConnectAndX:
		resp = s.onTreeConnect(req)
	case smb1CmdTreeDisconnect:
		resp = s.onTreeDisconnect(req)
	case smb1CmdLogoffAndX:
		resp = s.onLogoff(req)
	case smb1CmdEcho:
		resp = s.onEcho(req)
	case smb1CmdNTCreateAndX:
		resp = s.onNTCreate(req)
	case smb1CmdOpenAndX:
		// 老式 SMB1 客户端（小米电视等）打开文件常用 SMB_COM_OPEN_ANDX，
		// 之前没实现，落到 default 回 NOT_SUPPORTED，电视打开文件即断链。
		resp = s.onOpenAndX(req)
	case smb1CmdReadAndX:
		resp = s.onRead(req)
	case smb1CmdClose:
		resp = s.onClose(req)
	case smb1CmdTransaction2:
		resp = s.onTransaction2(req)
	case smb1CmdTransaction:
		resp = s.onTransaction(req)
	case smb1CmdCheckDirectory:
		resp = s.onCheckDirectory(req)
	case smb1CmdWriteAndX:
		resp = s.onWrite(req)
	case smb1CmdDelete, smb1CmdRename,
		smb1CmdCreateDirectory, smb1CmdDeleteDirectory:
		resp = s.errReply(req, smb1StatusAccessDenied)
	case smb1CmdFlush:
		resp = s.reply(req, smb1StatusSuccess, nil, nil)
	case smb1CmdDiskSize:
		resp = s.onDiskSize(req)
	case smb1CmdQueryInformation:
		// SMB_COM_QUERY_INFORMATION 是老的 8.3 属性查询，老设备偶尔用。
		resp = s.onQueryInformation(req)
	default:
		s.log.Debug("SMB1 未实现的命令", "cmd", req[4])
		resp = s.errReply(req, smb1StatusNotSupported)
	}
	if resp != nil && len(resp) >= 9 {
		st := binary.LittleEndian.Uint32(resp[5:9])
		s.dbg("SMB1 reply", "cmd", req[4], "status", fmt.Sprintf("0x%08X", st), "ipc", s.ipcTree)
	}
	return resp
}

// ---------- NEGOTIATE ----------

func (s *smb1Session) onNegotiate(req []byte) []byte {
	bc := readByteCount(req)
	body := readDataArea(req, bc)
	idx, ok := pickDialect(body, "NT LM 0.12")
	if !ok {
		// 0xFFFF 表示"没有客户端能接受的方言"
		p := make([]byte, 2)
		binary.LittleEndian.PutUint16(p, 0xFFFF)
		return s.reply(req, smb1StatusSuccess, p, nil)
	}

	caps := uint32(0x00000004 | 0x00000008 | 0x00000010 | 0x00000040 | 0x00000200 | 0x00002000)
	// CAP_UNICODE | LARGE_FILES | NT_SMBS | STATUS32 | NT_FIND | INFOLEVEL_PASSTHRU

	p := make([]byte, 34)
	binary.LittleEndian.PutUint16(p[0:], uint16(idx)) // DialectIndex
	p[2] = 0x03                                       // SecurityMode: USER_SECURITY | ENCRYPT_PASSWORDS
	// 这两个 bit 缺一不可：只给 0x01 表示"用户级安全但不加密口令"，
	// 于是 samba 客户端会拒连并报 "Server requested PLAINTEXT password"
	// （samba 自己回的是 0x03，2026-11-11 抓包核对）。我们的会话不校验
	// 凭据，但必须让客户端按正常流程走 NTLMSSP / 加密响应，而不是要求它
	// 发明文口令。
	binary.LittleEndian.PutUint16(p[3:], 50)                        // MaxMpxCount
	binary.LittleEndian.PutUint16(p[5:], 1)                         // MaxNumberVcs
	binary.LittleEndian.PutUint32(p[7:], 16644)                     // MaxBufferSize
	binary.LittleEndian.PutUint32(p[11:], 65536)                    // MaxRawSize
	binary.LittleEndian.PutUint32(p[15:], 0)                        // SessionKey
	binary.LittleEndian.PutUint32(p[19:], caps)                     // Capabilities
	binary.LittleEndian.PutUint64(p[23:], smb1Filetime(time.Now())) // SystemTime
	binary.LittleEndian.PutUint16(p[31:], 0)                        // ServerTimeZone (UTC)
	p[33] = 8                                                       // ChallengeLength

	challenge := make([]byte, 8)
	binary.LittleEndian.PutUint64(challenge, uint64(time.Now().UnixNano()))
	return s.reply(req, smb1StatusSuccess, p, challenge)
}

func pickDialect(body []byte, want string) (int, bool) {
	idx := 0
	for i := 0; i < len(body); {
		bufType := body[i]
		if bufType != 0x02 {
			i++
			continue
		}
		j := i + 1
		for j < len(body) && body[j] != 0 {
			j++
		}
		name := string(body[i+1 : j])
		if strings.EqualFold(name, want) {
			return idx, true
		}
		idx++
		i = j + 1
	}
	return 0, false
}

// ---------- SESSION_SETUP ----------

func (s *smb1Session) onSessionSetup(req []byte) []byte {
	// 不校验凭据：安全模型是"局域网内可见即可读"，与主服务端一致。
	// 老设备的 NTLMSSP blob 原样忽略，直接授予 guest 会话。
	s.uid = 1
	// WordCount 必须是 3（AndXCommand/AndXReserved/AndXOffset/Action），
	// 字节区跟 NativeOS / NativeLanMan / PrimaryDomain 三个字符串。
	//
	// 写成 wc=4 再带一个长度为 0 的 SecurityBlobLength 是不行的：那是
	// "扩展安全"的格式，而我们没有声明 CAP_EXTENDED_SECURITY，samba 客户端
	// 会直接判 NT_STATUS_INVALID_NETWORK_RESPONSE（2026-11-11 实测）。
	// 正确形状按 samba 自己的应答核对：ff 00 00 00 01 00 + 三段串。
	p := make([]byte, 6)
	p[0] = 0xFF // AndXCommand: none
	binary.LittleEndian.PutUint16(p[2:], 0)
	binary.LittleEndian.PutUint16(p[4:], 1) // Action: guest
	data := make([]byte, 0, 64)
	data = append(data, s.encStr("Windows 6.1")...)
	data = append(data, s.encStr("FSGW")...)
	data = append(data, s.encStr("WORKGROUP")...)
	return s.reply(req, smb1StatusSuccess, p, data)
}

// ---------- TREE_CONNECT ----------

func (s *smb1Session) onTreeConnect(req []byte) []byte {
	wc := int(req[32])
	// 参数：AndX(4) Flags(2) PasswordLength(2)
	var pwLen int
	if wc >= 4 {
		pwLen = int(binary.LittleEndian.Uint16(req[33+6:]))
	}
	body := readDataArea(req, readByteCount(req))
	if pwLen > len(body) {
		pwLen = len(body)
	}
	tail := body[pwLen:]
	unc, _ := s.decStr(tail)

	name := shareNameFromUNC(unc)
	switch {
	case name == "" || strings.EqualFold(name, s.share):
		s.treeRoot = s.root
		s.ipcTree = false
	case strings.EqualFold(name, "IPC$"):
		s.treeRoot = ""
		s.ipcTree = true
	default:
		return s.errReply(req, smb1StatusBadNetName)
	}
	s.nextTID++
	if s.nextTID == 0 {
		s.nextTID = 1
	}
	s.tid = s.nextTID

	p := make([]byte, 6)
	p[0] = 0xFF // AndXCommand: none
	binary.LittleEndian.PutUint16(p[2:], 0)
	binary.LittleEndian.PutUint16(p[4:], 0x0001) // OptionalSupport: search bits

	// Service 是固定的 ASCII 串（"A:"），只有 NativeFileSystem 跟着 Unicode
	// 标志走——samba 的报文就是这样（41 3a 00 后面才是 UTF-16 的 NTFS）。
	data := append([]byte("A:\x00"), s.encStr("NTFS")...)
	return s.reply(req, smb1StatusSuccess, p, data)
}

// shareNameFromUNC 从 \\host\share[\sub] 里取出共享名。
func shareNameFromUNC(unc string) string {
	t := strings.TrimPrefix(unc, `\\`)
	if t == unc {
		t = strings.TrimPrefix(strings.TrimPrefix(unc, `\`), `\`)
	}
	parts := strings.Split(t, `\`)
	if len(parts) < 2 {
		return ""
	}
	name := parts[1]
	if strings.HasSuffix(name, "$") && strings.EqualFold(name, "IPC$") {
		return "IPC$"
	}
	return name
}

func (s *smb1Session) onTreeDisconnect(req []byte) []byte {
	s.tid = 0
	s.treeRoot = ""
	s.ipcTree = false
	return s.reply(req, smb1StatusSuccess, nil, nil)
}

func (s *smb1Session) onLogoff(req []byte) []byte {
	p := make([]byte, 4)
	p[0] = 0xFF
	binary.LittleEndian.PutUint16(p[2:], 0)
	return s.reply(req, smb1StatusSuccess, p, nil)
}

func (s *smb1Session) onEcho(req []byte) []byte {
	body := readDataArea(req, readByteCount(req))
	return s.reply(req, smb1StatusSuccess, make([]byte, 2), body)
}

// ---------- NT_CREATE ----------

func (s *smb1Session) onNTCreate(req []byte) []byte {
	if s.ipcTree {
		return s.onPipeOpen(req)
	}
	if s.treeRoot == "" {
		return s.errReply(req, smb1StatusAccessDenied)
	}
	wc := int(req[32])
	if wc < 24 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	params := req[33:]
	// NT_CREATE_ANDX 请求参数区布局（MS-CIFS 2.2.4.9.1，按 2 字节字对齐）：
	//   [0:2]   AndXCommand/Reserved  [2:4]   AndXOffset
	//   [4]     OplockLevel   [5]     Reserved
	//   [6:8]   FID           [8:12]  CreateFlags        [12:16] RootDirectory
	//   [16:20] DesiredAccess [20:28] AllocationSize     [28:32] FileAttributes
	//   [32:36] ShareAccess   [36:40] CreateDisposition  [40:44] CreateOptions
	//   [44:46] NameLength    [46:48] SecurityDescriptorLength …
	// NameLength 是文件名在字节数据区里的真实长度。早先错放在 params[5:7]，
	// 等于把 FID 的低字节当成了名字长度，于是解出的文件名是乱的——表现为
	// "列目录正常、但打不开（找不到）具体的文件"。
	nameLen := int(binary.LittleEndian.Uint16(params[44:]))
	desired := binary.LittleEndian.Uint32(params[16:])
	disp := binary.LittleEndian.Uint32(params[36:])
	opts := binary.LittleEndian.Uint32(params[40:])

	raw := nameAfterAlign(readDataArea(req, readByteCount(req)), s.unicode)
	name := ""
	// NameLength 是字节数。开了 Unicode 就必须按 UTF-16LE 严格解码——不能用
	// proxy.go 里那个 decodeUTF16LE（它只为写日志、非 ASCII 一律换成 '.'，
	// 中文文件名会变成一串点，然后报"路径不存在"）。
	if nameLen > 0 && nameLen <= len(raw) {
		if s.unicode {
			name = decodeUTF16Strict(raw[:nameLen])
		} else {
			name = string(raw[:nameLen])
		}
		name = strings.Trim(strings.TrimSpace(name), "\x00")
	} else {
		name, _ = s.decStr(raw)
	}

	rel, full, err := s.resolve(name)
	s.dbg("NTCREATE", "name", name, "full", full, "err", err != nil, "nameLen", nameLen, "unicode", s.unicode)
	if err != nil {
		return s.errReply(req, smb1StatusObjectPathNotFound)
	}
	wantDir := opts&0x00000001 != 0
	wantFile := opts&0x00000040 != 0

	st, statErr := os.Stat(full)
	if statErr != nil {
		if disp == 1 { // FILE_OPEN，不存在就报错
			return s.errReply(req, smb1StatusObjectNameNotFound)
		}
		if desired&0x00000002 != 0 || !s.writable {
			// 只读通道不接受创建；需要写的情况一律拒绝。
			return s.errReply(req, smb1StatusAccessDenied)
		}
		return s.errReply(req, smb1StatusAccessDenied)
	}
	if wantDir && !st.IsDir() {
		return s.errReply(req, smb1StatusNotADirectory)
	}
	if wantFile && st.IsDir() {
		return s.errReply(req, smb1StatusFileIsADirectory)
	}

	f, err := os.Open(full)
	if err != nil && st.IsDir() {
		f, err = os.Open(full)
	}
	if err != nil && !st.IsDir() {
		return s.errReply(req, smb1StatusAccessDenied)
	}
	fid := s.nextFID
	s.nextFID++
	if s.nextFID == 0 {
		s.nextFID = 1
	}
	s.files[fid] = &smb1OpenFile{f: f, rel: rel, isDir: st.IsDir()}
	s.dbg("NTCREATE-OPEN", "fid", fid, "name", name, "isDir", st.IsDir())

	return s.ntCreateReply(req, fid, st.Size(), st.IsDir(), st.ModTime())
}

// onOpenAndX 处理 SMB_COM_OPEN_ANDX（0x2D）：老式 SMB1 客户端（小米电视、早期
// 播放器）打开文件时常用它，而不是 NT_CREATE_ANDX。请求参数区 WordCount=15（30
// 字节），文件名落在 ByteCount 数据区（与 NT_CREATE 一样要处理 Unicode 对齐 pad）。
// 之前没实现这个命令，电视一发 OPEN_ANDX 就掉进 default 回 NOT_SUPPORTED，进而
// 断链（broken pipe）。
func (s *smb1Session) onOpenAndX(req []byte) []byte {
	if s.ipcTree {
		// IPC$ 上的打开走命名管道，OPEN_ANDX 不支持，直接拒绝。
		return s.errReply(req, smb1StatusNotSupported)
	}
	if s.treeRoot == "" {
		return s.errReply(req, smb1StatusAccessDenied)
	}
	wc := int(req[32])
	if wc < 15 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	// OPEN_ANDX 请求参数区（MS-CIFS 2.2.4.1.1）：
	//   [0] AndXCommand [1] AndXReserved [2:4] AndXOffset
	//   [4:6]   FID(保留=0xFFFF)  [6:8]   SearchAttributes
	//   [8:10]  FileAttributes    [10:14] CreationTime
	//   [14:16] OpenFunction      [16:20] AllocationSize
	//   [20:22] FileNameLen       [22:30] Reserved
	// 文件名在 ByteCount 数据区，null 结尾。
	raw := nameAfterAlign(readDataArea(req, readByteCount(req)), s.unicode)
	name := ""
	if s.unicode {
		name = decodeUTF16Strict(raw)
	} else {
		name = string(raw)
	}
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)

	rel, full, err := s.resolve(name)
	if err != nil {
		return s.errReply(req, smb1StatusObjectPathNotFound)
	}
	st, statErr := os.Stat(full)
	if statErr != nil {
		return s.errReply(req, smb1StatusObjectNameNotFound)
	}
	f, err := os.Open(full)
	if err != nil {
		return s.errReply(req, smb1StatusAccessDenied)
	}
	fid := s.nextFID
	s.nextFID++
	if s.nextFID == 0 {
		s.nextFID = 1
	}
	s.files[fid] = &smb1OpenFile{f: f, rel: rel, isDir: st.IsDir()}

	return s.openAndXReply(req, fid, st)
}

// openAndXReply 组 SMB_COM_OPEN_ANDX 响应（MS-CIFS 2.2.4.1.2，WordCount=15 / 30 字节）。
// FID 必须落在参数区偏移 4（p[4:6]），FileSize 在偏移 12；老客户端从这个位置取 FID
// 去发 READ_ANDX，写错偏移就会整条断链。
func (s *smb1Session) openAndXReply(req []byte, fid uint16, st os.FileInfo) []byte {
	p := make([]byte, 30) // WordCount=15
	p[0] = 0xFF           // AndXCommand = 无后续 AndX
	// p[2:4] AndXOffset = 0
	binary.LittleEndian.PutUint16(p[4:], fid) // FID @ offset 4
	attr := uint32(0x0080)
	if st.IsDir() {
		attr = 0x0010
	}
	binary.LittleEndian.PutUint16(p[6:], uint16(attr)) // FileAttributes @ 6
	ft := smb1Filetime(st.ModTime())
	binary.LittleEndian.PutUint32(p[8:], uint32(ft))       // CreationTime(low) @ 8
	binary.LittleEndian.PutUint32(p[12:], uint32(st.Size())) // FileSize @ 12
	access := uint16(0x0001) // FILE_READ_DATA
	if s.writable {
		access |= 0x0002
	}
	binary.LittleEndian.PutUint16(p[16:], access) // GrantedAccess @ 16
	// p[18:20] FileType = 0 (disk)   p[20:22] IPCState = 0
	binary.LittleEndian.PutUint16(p[22:], 1) // Action/OpenResults @ 22：文件已存在并打开
	// p[24:28] ServerFid = 0   p[28:30] Reserved = 0
	return s.reply(req, smb1StatusSuccess, p, nil)
}

// resolve 把客户端的相对路径映射到共享根内的绝对路径，并挡住 .. 越界。
func (s *smb1Session) resolve(name string) (string, string, error) {
	n := strings.ReplaceAll(name, `\`, "/")
	n = strings.TrimPrefix(n, "/")
	n = strings.TrimPrefix(n, "./")
	if n == "" {
		return "", s.treeRoot, nil
	}
	clean := path.Clean(n)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", "", errors.New("smbgo: 路径越界")
	}
	full := filepath.Join(s.treeRoot, filepath.FromSlash(clean))
	rootAbs, err := filepath.Abs(s.treeRoot)
	if err != nil {
		return "", "", err
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", "", err
	}
	if fullAbs != rootAbs && !strings.HasPrefix(fullAbs, rootAbs+string(os.PathSeparator)) {
		return "", "", errors.New("smbgo: 路径越界")
	}
	return filepath.ToSlash(clean), fullAbs, nil
}

// ---------- READ / CLOSE ----------

func (s *smb1Session) onRead(req []byte) []byte {
	wc := int(req[32])
	if wc < 10 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	params := req[33:]
	// READ_ANDX 请求：AndXCommand/Reserved/AndXOffset 占前 4 字节，FID 在 4，
	// Offset 在 6，MaxCountOfBytesToReturn 在 10。少算前面这 4 字节会把 FID
	// 读成 AndXOffset（恒为 0），表现是"能列目录、一打开文件就报参数错误"。
	fid := binary.LittleEndian.Uint16(params[4:])
	offset := binary.LittleEndian.Uint32(params[6:])
	maxCount := int(binary.LittleEndian.Uint16(params[10:]))
	if maxCount <= 0 || maxCount > 65536 {
		maxCount = 65536
	}
	of, ok := s.files[fid]
	if !ok {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	if of.pipe != "" {
		return s.pipeRead(req, of, maxCount)
	}
	if of.f == nil {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	if of.isDir {
		return s.errReply(req, smb1StatusFileIsADirectory)
	}

	buf := make([]byte, maxCount)
	n, err := of.f.ReadAt(buf, int64(offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return s.errReply(req, smb1StatusAccessDenied)
	}
	buf = buf[:n]

	return s.readReply(req, buf)
}

// readReply 组 READ_ANDX 响应（读文件与读管道共用）。
//
// WordCount = 12（24 字节）：AndXCommand(1) AndXReserved(1) AndXOffset(2)
// Available(2) DataCompactionMode(2) Reserved(2) DataLength(2) DataOffset(2)
// DataLengthHigh(2) Reserved2(8)
func (s *smb1Session) readReply(req []byte, data []byte) []byte {
	n := len(data)
	p := make([]byte, 24)
	p[0] = 0xFF
	binary.LittleEndian.PutUint16(p[4:], uint16(n))  // Available
	binary.LittleEndian.PutUint16(p[10:], uint16(n)) // DataLength
	dataOffset := smb1HeaderLen + 1 + len(p) + 2
	binary.LittleEndian.PutUint16(p[12:], uint16(dataOffset)) // DataOffset
	binary.LittleEndian.PutUint16(p[14:], uint16(n>>16))      // DataLengthHigh
	return s.reply(req, smb1StatusSuccess, p, data)
}

// ntCreateReply 组 NT_CREATE_ANDX 响应（文件、目录、管道共用）。
func (s *smb1Session) ntCreateReply(req []byte, fid uint16, size int64, isDir bool, mtime time.Time) []byte {
	p := make([]byte, 68)
	p[0] = 0xFF // AndXCommand: none
	p[4] = 0    // OplockLevel
	// NT_CREATE_ANDX 响应参数区（MS-CIFS 2.2.4.9.2）。注意：响应里 OplockLevel(1 字节)
	// 之后【没有】Reserved 字节，FID 从偏移 5 开始——这一点和请求区不同，极易搞错。
	//   [0] AndXCommand [1] AndXReserved [2:4] AndXOffset
	//   [4] OplockLevel
	//   [5:7]   FID           [7:11]  CreateAction
	//   [11:19] CreateTime    [19:27] LastAccessTime
	//   [27:35] LastWriteTime [35:43] ChangeTime
	//   [43:47] FileAttributes [47:55] AllocationSize [55:63] EndOfFile
	//   [63:65] FileType       [65:67] DeviceState      [67] Directory
	// 之前的版本把 FID 写在 p[6:8]（整体 +1 偏移），客户端按 p[5:7] 读到的是
	// [0x00,0x01]=256 而不是 1，于是拿错 FID 发 QUERY_FILE_INFO / READ_ANDX，
	// 服务端查不到句柄→INVALID_PARAMETER / 断链（电视 broken pipe）。
	binary.LittleEndian.PutUint16(p[5:], fid)
	binary.LittleEndian.PutUint32(p[7:], 1) // CreateAction: FILE_OPENED
	for off := 11; off <= 35; off += 8 {
		binary.LittleEndian.PutUint64(p[off:], smb1Filetime(mtime))
	}
	attr := uint32(0x0080)
	if isDir {
		attr = 0x0010
	}
	binary.LittleEndian.PutUint32(p[43:], attr)
	binary.LittleEndian.PutUint64(p[47:], uint64(size)) // AllocationSize（必须 >= EndOfFile，置 0 会让客户端误判文件不可用）
	binary.LittleEndian.PutUint64(p[55:], uint64(size)) // EndOfFile
	binary.LittleEndian.PutUint16(p[63:], 0)            // FileType: disk
	binary.LittleEndian.PutUint16(p[65:], 0)            // DeviceState
	if isDir {
		p[67] = 1 // Directory 标志
	}
	return s.reply(req, smb1StatusSuccess, p, nil)
}

func (s *smb1Session) onClose(req []byte) []byte {
	wc := int(req[32])
	if wc >= 3 {
		fid := binary.LittleEndian.Uint16(req[33:])
		if of, ok := s.files[fid]; ok {
			if of.f != nil {
				_ = of.f.Close()
			}
			delete(s.files, fid)
		}
	}
	return s.reply(req, smb1StatusSuccess, nil, nil)
}

func (s *smb1Session) onCheckDirectory(req []byte) []byte {
	body := readDataArea(req, readByteCount(req))
	name, _ := s.decStr(body)
	if _, full, err := s.resolve(name); err == nil {
		if st, serr := os.Stat(full); serr == nil && st.IsDir() {
			return s.errReply(req, smb1StatusSuccess)
		}
	}
	return s.errReply(req, smb1StatusObjectPathNotFound)
}

func (s *smb1Session) onQueryInformation(req []byte) []byte {
	body := readDataArea(req, readByteCount(req))
	name, _ := s.decStr(body)
	_, full, err := s.resolve(name)
	if err != nil {
		return s.errReply(req, smb1StatusObjectPathNotFound)
	}
	st, serr := os.Stat(full)
	if serr != nil {
		return s.errReply(req, smb1StatusObjectNameNotFound)
	}
	// SMB_COM_QUERY_INFORMATION 回复：FileAttributes(2) LastWriteTime(4) FileSize(4) + name
	d := make([]byte, 10)
	attr := uint16(0x0080)
	if st.IsDir() {
		attr = 0x0010
	}
	binary.LittleEndian.PutUint16(d[0:], attr)
	binary.LittleEndian.PutUint32(d[2:], uint32(st.ModTime().Unix()))
	binary.LittleEndian.PutUint32(d[6:], uint32(st.Size()))
	return s.reply(req, smb1StatusSuccess, nil, d)
}

// ---------- TRANS2 ----------

func (s *smb1Session) onTransaction2(req []byte) []byte {
	wc := int(req[32])
	if wc < 14 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	params := req[33:]

	totalParam := int(binary.LittleEndian.Uint16(params[0:]))
	paramCount := int(binary.LittleEndian.Uint16(params[18:]))
	paramOffset := int(binary.LittleEndian.Uint16(params[20:]))
	dataCount := int(binary.LittleEndian.Uint16(params[22:]))
	dataOffset := int(binary.LittleEndian.Uint16(params[24:]))
	setupCount := int(params[26])

	setup := params[28:]
	if setupCount < 1 || len(setup) < 2 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	sub := binary.LittleEndian.Uint16(setup[0:])
	s.dbg("TRANS2", "sub", fmt.Sprintf("0x%04X", sub), "paramCnt", paramCount, "dataCnt", dataCount,
		"paramOff", paramOffset, "dataOff", dataOffset, "reqLen", len(req))

	paramArea := sliceAbs(req, paramOffset, paramCount)
	dataArea := sliceAbs(req, dataOffset, dataCount)

	switch sub {
	case trans2FindFirst2:
		return s.onFindFirst2(req, paramArea, dataArea)
	case trans2FindNext2:
		return s.onFindNext2(req, paramArea)
	case trans2QueryPathInfo:
		s.log.Debug("TRANS2 QUERY_PATH_INFO", "wc", wc, "paramCnt", paramCount, "dataCnt", dataCount, "paramOff", paramOffset, "dataOff", dataOffset, "reqLen", len(req))
		return s.onQueryPathInfo(req, paramArea, dataArea)
	case trans2QueryFileInfo:
		return s.onQueryFileInfo(req, paramArea)
	case trans2QueryFSInfo:
		return s.onQueryFSInfo(req, paramArea)
	default:
		_ = totalParam
		return s.errReply(req, smb1StatusNotSupported)
	}
}

func (s *smb1Session) onFindFirst2(req []byte, params, data []byte) []byte {
	if s.treeRoot == "" {
		return s.errReply(req, smb1StatusAccessDenied)
	}
	if len(params) < 8 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	searchAttr := binary.LittleEndian.Uint16(params[0:])
	count := int(binary.LittleEndian.Uint16(params[2:]))
	level := binary.LittleEndian.Uint16(params[6:])
	if count <= 0 || count > 512 {
		count = 512
	}

	// 搜索路径在 Trans2 参数区尾部（前 12 字节是属性/数量/标志/级别/存储类型），
	// 不在数据区。读错位置就等于每次都在枚举共享根目录——"ls sub" 会列出根目录。
	pattern := ""
	if len(params) > 12 {
		pattern, _ = s.decStr(params[12:])
	}
	if pattern == "" && len(data) > 0 {
		pattern, _ = s.decStr(data)
	}
	pattern = strings.TrimRight(pattern, "\x00")
	pattern = strings.ReplaceAll(pattern, `\`, "/")
	dirPart, filePart := path.Split(strings.TrimPrefix(pattern, "/"))
	if filePart == "" {
		filePart = "*"
	}
	dirRel, dirFull, err := s.resolve(strings.TrimSuffix(dirPart, "/"))
	if err != nil {
		return s.errReply(req, smb1StatusObjectPathNotFound)
	}
	st, serr := os.Stat(dirFull)
	if serr != nil {
		return s.errReply(req, smb1StatusObjectPathNotFound)
	}
	if !st.IsDir() {
		return s.errReply(req, smb1StatusNotADirectory)
	}

	entries, allErr := os.ReadDir(dirFull)
	if allErr != nil {
		return s.errReply(req, smb1StatusAccessDenied)
	}
	list := make([]smb1FindEntry, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !matchLoose(filePart, name) {
			continue
		}
		if IsAppleMetaName(name) && s.hideAppleMeta() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		isDir := e.IsDir()
		attr := uint32(0x0080)
		if isDir {
			attr = 0x0010
		} else if info.Mode()&0o444 == 0 {
			attr = 0x0001
		}
		// SearchAttributes：客户端只想要目录时（0x10），过滤掉文件
		if searchAttr == 0x0010 && !isDir {
			continue
		}
		list = append(list, smb1FindEntry{
			name: name, size: info.Size(), isDir: isDir,
			mtime: info.ModTime(), attr: attr,
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	_ = dirRel

	sid := s.nextSID
	s.nextSID++
	if s.nextSID == 0 {
		s.nextSID = 1
	}
	s.finds[sid] = &smb1Find{entries: list, idx: 0, pattern: filePart, level: level}

	return s.findReply(req, sid, count, level, true)
}

func (s *smb1Session) onFindNext2(req []byte, params []byte) []byte {
	if len(params) < 4 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	sid := binary.LittleEndian.Uint16(params[0:])
	count := int(binary.LittleEndian.Uint16(params[2:]))
	level := binary.LittleEndian.Uint16(params[4:])
	if count <= 0 || count > 512 {
		count = 512
	}
	if _, ok := s.finds[sid]; !ok {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	return s.findReply(req, sid, count, level, false)
}

func (s *smb1Session) findReply(req []byte, sid uint16, count int, level uint16, first bool) []byte {
	fd := s.finds[sid]
	var recs [][]byte
	for fd.idx < len(fd.entries) && len(recs) < count {
		rec := encodeFindEntry(fd.entries[fd.idx], level)
		if rec == nil {
			// 不支持的级别：停止，让客户端自己降级
			break
		}
		if len(rec) > 60000 {
			break
		}
		recs = append(recs, rec)
		fd.idx++
	}
	end := uint16(0)
	if fd.idx >= len(fd.entries) {
		end = 1
	}

	// 每个条目要写 NextEntryOffset，且必须 8 字节对齐（MS-CIFS 2.2.4.46.2：
	// FindFirst2 返回的每条 entry 起点按 8 对齐）。末条 NextEntryOffset = 0。
	var data []byte
	for i, rec := range recs {
		pad := (8 - len(rec)%8) % 8
		next := 0
		if i != len(recs)-1 {
			next = len(rec) + pad
		}
		binary.LittleEndian.PutUint32(rec[0:], uint32(next))
		data = append(data, rec...)
		data = append(data, make([]byte, pad)...)
	}

	// Trans2 参数区：SID(2) SearchCount(2) EndOfSearch(2) ErrorOffset(2) LastNameOffset(2)
	// 搜完就把 SID 回报成 0xFFFF（"无需再取下一页、也不必 FindClose2"），
	// 这和 samba/Windows 的做法一致；还有下一页时用真实 SID 等客户端来 FindNext2。
	outSID := sid
	if end == 1 {
		outSID = 0xFFFF
		delete(s.finds, sid)
	}
	p := make([]byte, 10)
	binary.LittleEndian.PutUint16(p[0:], outSID)
	binary.LittleEndian.PutUint16(p[2:], uint16(len(recs)))
	binary.LittleEndian.PutUint16(p[4:], end)
	binary.LittleEndian.PutUint16(p[6:], 0) // ErrorOffset
	binary.LittleEndian.PutUint16(p[8:], 0) // LastNameOffset
	return s.replyTrans(req, smb1StatusSuccess, p, data)
}

func encodeFindEntry(e smb1FindEntry, level uint16) []byte {
	nameUTF16 := utf16.Encode([]rune(e.name))
	nameLen := len(nameUTF16) * 2

	// 条目前缀长度按 MS-CIFS 的结构定义，并用 samba 实测校准：
	//   0x0101 DIRECTORY_INFO        64
	//   0x0102 FULL_DIRECTORY_INFO   68（64 + EaSize）
	//   0x0103 NAMES_INFO            12（只有名字）
	//   0x0104 BOTH_DIRECTORY_INFO   94（68 + 1+1 + ShortName[24]）
	//   0x0105 ID_FULL_DIRECTORY     76（68 + FileId[8]）
	//   0x0106 ID_BOTH_DIRECTORY    102（94 + FileId[8]）
	// 公共字段固定：NextEntryOffset@0、FileIndex@4、四个时间@8..40、
	// EndOfFile@40、AllocationSize@48、FileAttributes@56、FileNameLength@60，
	// 文件名紧随前缀（UTF-16LE）。带 FileId 的级别把它放在前缀最后 8 字节。
	base := 0
	hasShort, hasID, hasEa := false, false, false
	switch level {
	case infoFindNames: // 0x0103：只有名字
		b := make([]byte, 12+nameLen)
		binary.LittleEndian.PutUint32(b[8:], uint32(nameLen))
		for i, u := range nameUTF16 {
			binary.LittleEndian.PutUint16(b[12+i*2:], u)
		}
		return b
	case infoFindDir: // 0x0101
		base = 64
	case infoFindFullDir: // 0x0102
		base, hasEa = 68, true
	case infoFindBothDir: // 0x0104
		base, hasEa, hasShort = 94, true, true
	case infoFindIDFull: // 0x0105
		base, hasEa, hasID = 76, true, true
	case infoFindIDBoth: // 0x0106
		base, hasEa, hasShort, hasID = 102, true, true, true
	default:
		return nil
	}

	b := make([]byte, base+nameLen)
	binary.LittleEndian.PutUint32(b[4:], 0) // FileIndex
	ft := smb1Filetime(e.mtime)
	binary.LittleEndian.PutUint64(b[8:], ft)              // CreationTime
	binary.LittleEndian.PutUint64(b[16:], ft)             // LastAccessTime
	binary.LittleEndian.PutUint64(b[24:], ft)             // LastWriteTime
	binary.LittleEndian.PutUint64(b[32:], ft)             // ChangeTime
	binary.LittleEndian.PutUint64(b[40:], uint64(e.size)) // EndOfFile
	binary.LittleEndian.PutUint64(b[48:], uint64(e.size)) // AllocationSize
	binary.LittleEndian.PutUint32(b[56:], e.attr)         // FileAttributes
	binary.LittleEndian.PutUint32(b[60:], uint32(nameLen))
	if hasEa {
		binary.LittleEndian.PutUint32(b[64:], 0) // EaSize
	}
	if hasShort {
		b[68] = 0 // ShortNameLength
		b[69] = 0 // Reserved
		// ShortName[24] 留空：偏移 70..93
	}
	if hasID {
		// FileId 固定在前缀的最后 8 字节（0x0105 → 68、0x0106 → 94）。
		binary.LittleEndian.PutUint64(b[base-8:], 0)
	}
	for i, u := range nameUTF16 {
		binary.LittleEndian.PutUint16(b[base+i*2:], u)
	}
	return b
}

func (s *smb1Session) onQueryPathInfo(req []byte, params, data []byte) []byte {
	if len(params) < 4 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	level := binary.LittleEndian.Uint16(params[0:])
	// QUERY_PATH_INFO 的文件名位置有两种做法：
	//   - 标准 MS-CIFS 2.2.6.4：放在 Trans2 的 Data 区；
	//   - 部分老客户端（小米电视、smbclient -m NT1）：把文件名塞进 Parameter 区，
	//     紧跟在 Level(2)+Reserved(2) 之后，Data 区为空（实测 paramCnt=60、dataCnt=0）。
	// 两种都兼容：Data 区非空就优先用 Data，否则退回到 Parameter 区跳过前 4 字节。
	// 之前只读 Data 区（恒为空），文件名解析成空串 → 永远返回共享根目录的信息 →
	// 电视拿到错误的文件大小/属性后断链（broken pipe）。
	nameBytes := data
	if len(nameBytes) == 0 {
		// 老客户端（小米电视、smbclient -m NT1）把文件名放进 Parameter 区。
		// 抓包实测头部是 Level(2)+Reserved(4)=6 字节（不是标准 MS-CIFS 说的
		// Level(2)+Reserved(2)=4），文件名从偏移 6 开始。之前固定按 4 取，
		// 读到的是两个 0x00 → 解析成空名 → 返回共享根目录的属性 → 电视拿到
		// 错误的文件大小/属性后断链。这里按 params[4:6] 是否全 0 自适应：
		// 全 0 说明保留区是 4 字节（偏移 6）；否则退回 4 字节保留（偏移 4）。
		off := 4
		if len(params) >= 6 && params[4] == 0 && params[5] == 0 {
			off = 6
		}
		if len(params) > off {
			nameBytes = params[off:]
		}
	}
	raw := nameAfterAlign(nameBytes, s.unicode)
	name, _ := s.decStr(raw)
	name = strings.Trim(strings.TrimSpace(name), "\x00")
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	_, full, err := s.resolve(name)
	s.dbg("QPINFO", "level", fmt.Sprintf("0x%04X", level), "unicode", s.unicode,
		"dataLen", len(data), "paramLen", len(params), "name", name, "full", full, "err", err != nil,
		"paramsHex", fmt.Sprintf("%x", params), "dataHex", fmt.Sprintf("%x", data))
	if err != nil {
		return s.errReply(req, smb1StatusObjectPathNotFound)
	}
	st, serr := os.Stat(full)
	if serr != nil {
		return s.errReply(req, smb1StatusObjectNameNotFound)
	}
	return s.replyWithInfo(req, level, st)
}

func (s *smb1Session) onQueryFileInfo(req []byte, params []byte) []byte {
	if len(params) < 4 {
		s.dbg("QFILEINFO", "err", "paramShort", "paramLen", len(params), "paramsHex", fmt.Sprintf("%x", params))
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	fid := binary.LittleEndian.Uint16(params[0:])
	level := binary.LittleEndian.Uint16(params[2:])
	of, ok := s.files[fid]
	s.dbg("QFILEINFO", "fid", fid, "level", fmt.Sprintf("0x%04X", level), "found", ok,
		"paramLen", len(params), "paramsHex", fmt.Sprintf("%x", params), "openFidCount", len(s.files))
	if !ok {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	st, err := os.Stat(of.relPath(s))
	if err != nil {
		return s.errReply(req, smb1StatusObjectNameNotFound)
	}
	return s.replyWithInfo(req, level, st)
}

func (of *smb1OpenFile) relPath(s *smb1Session) string {
	return filepath.Join(s.treeRoot, filepath.FromSlash(of.rel))
}

func (s *smb1Session) replyWithInfo(req []byte, level uint16, st os.FileInfo) []byte {
	attr := uint32(0x0080)
	if st.IsDir() {
		attr = 0x0010
	}
	// 老客户端（电视/播放器）有时发的是非 passthrough 的 SMB_INFO_* 级别
	//（0x0001~0x0004），而不是 0x0101~0x0107。直接返回 NOT_SUPPORTED 会让它
	//拿不到文件大小/属性而放弃读取。这里把它们映射到等价的 passthrough 级别，
	//用现代布局回，客户端通常能正常解析。
	switch level {
	case 0x0001:
		level = 0x0101 // SMB_QUERY_FILE_BASIC_INFO → FILE_BASIC_INFO
	case 0x0002:
		level = 0x0102 // SMB_QUERY_FILE_STANDARD_INFO → FILE_STANDARD_INFO
	case 0x0003:
		level = 0x0104 // SMB_QUERY_FILE_EA_INFO → FILE_EA_INFO
	case 0x0004:
		level = 0x0106 // SMB_QUERY_FILE_NAME_INFO → FILE_NAME_INFO
	}
	switch level {
	case 0x0101: // FILE_BASIC_INFO
		b := make([]byte, 40)
		binary.LittleEndian.PutUint64(b[0:], smb1Filetime(st.ModTime()))
		binary.LittleEndian.PutUint64(b[8:], smb1Filetime(st.ModTime()))
		binary.LittleEndian.PutUint64(b[16:], smb1Filetime(st.ModTime()))
		binary.LittleEndian.PutUint64(b[24:], smb1Filetime(st.ModTime()))
		binary.LittleEndian.PutUint32(b[32:], attr)
		binary.LittleEndian.PutUint32(b[36:], 0)
		return s.replyTrans(req, smb1StatusSuccess, nil, b)
	case 0x0102: // FILE_STANDARD_INFO
		b := make([]byte, 24)
		binary.LittleEndian.PutUint64(b[0:], 0)
		binary.LittleEndian.PutUint64(b[8:], uint64(st.Size()))
		binary.LittleEndian.PutUint32(b[16:], 1) // NumberOfLinks
		b[20] = 0
		if st.IsDir() {
			b[20] = 1
		}
		return s.replyTrans(req, smb1StatusSuccess, nil, b)
	case 0x0103: // FILE_INTERNAL_INFO
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, 1)
		return s.replyTrans(req, smb1StatusSuccess, nil, b)
	case 0x0104: // FILE_EA_INFO
		b := make([]byte, 4)
		return s.replyTrans(req, smb1StatusSuccess, nil, b)
	case 0x0105: // FILE_FULL_EA_INFO
		b := make([]byte, 4)
		return s.replyTrans(req, smb1StatusSuccess, nil, b)
	case 0x0106: // FILE_NAME_INFO
		n := st.Name()
		return s.replyTrans(req, smb1StatusSuccess, nil, s.encStrRaw(n))
	case 0x0107: // FILE_ALL_INFO（68 字节，客户端拿它算下载尺寸）
		// 字段顺序不能凭感觉：AllocationSize 在 40，EndOfFile 在 48。
		// 把 EOF 写到 40 会让客户端认为文件大小是 0，于是连 READ 都不发。
		b := make([]byte, 68)
		binary.LittleEndian.PutUint64(b[0:], smb1Filetime(st.ModTime()))
		binary.LittleEndian.PutUint64(b[8:], smb1Filetime(st.ModTime()))
		binary.LittleEndian.PutUint64(b[16:], smb1Filetime(st.ModTime()))
		binary.LittleEndian.PutUint64(b[24:], smb1Filetime(st.ModTime()))
		binary.LittleEndian.PutUint32(b[32:], attr)
		binary.LittleEndian.PutUint64(b[40:], uint64(st.Size())) // AllocationSize
		binary.LittleEndian.PutUint64(b[48:], uint64(st.Size())) // EndOfFile
		binary.LittleEndian.PutUint32(b[56:], 1)                 // NumberOfLinks
		binary.LittleEndian.PutUint16(b[60:], 0)                 // DeletePending
		if st.IsDir() {
			b[61] = 1
		}
		return s.replyTrans(req, smb1StatusSuccess, nil, b)
	}
	return s.errReply(req, smb1StatusNotSupported)
}

// encStrRaw 编码一个不带结束符的字符串（NAME_INFO 用的是长度前缀）。
func (s *smb1Session) encStrRaw(v string) []byte {
	var b []byte
	if s.unicode {
		u := utf16.Encode([]rune(v))
		b = make([]byte, len(u)*2)
		for i, r := range u {
			binary.LittleEndian.PutUint16(b[i*2:], r)
		}
		return b
	}
	return []byte(v)
}

func (s *smb1Session) onQueryFSInfo(req []byte, params []byte) []byte {
	if len(params) < 2 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	level := binary.LittleEndian.Uint16(params[0:])
	switch level {
	case 0x0101: // SMB_QUERY_FS_SIZE_INFO (24 bytes)
		b := make([]byte, 24)
		binary.LittleEndian.PutUint64(b[0:], 1<<40) // TotalAllocationUnits
		binary.LittleEndian.PutUint64(b[8:], 1<<39) // FreeAllocationUnits
		binary.LittleEndian.PutUint32(b[16:], 4096) // SectorsPerAllocationUnit
		binary.LittleEndian.PutUint32(b[20:], 512)  // BytesPerSector
		return s.replyTrans(req, smb1StatusSuccess, nil, b)
	case 0x0102: // SMB_QUERY_FS_ATTRIBUTE_INFO
		b := make([]byte, 12+len(s.encStrRaw("NTFS")))
		binary.LittleEndian.PutUint32(b[0:], 0x00000002|0x00000004) // FILE_CASE_PRESERVED_NAMES
		binary.LittleEndian.PutUint32(b[4:], 255)
		binary.LittleEndian.PutUint32(b[8:], uint32(len(s.encStrRaw("NTFS"))))
		copy(b[12:], s.encStrRaw("NTFS"))
		return s.replyTrans(req, smb1StatusSuccess, nil, b)
	}
	return s.errReply(req, smb1StatusNotSupported)
}

// ---------- TRANSACTION ----------

// transNMPipe 是 SMB_COM_TRANSACTION 里"在命名管道 FID 上收发"的功能码
// （MS-CIFS TransactNmPipe）。带它的请求把 FID 放在第二个 SetupWord 里，
// Name 只是 "\PIPE\"，真正的目标靠 FID 认。
const transNMPipe = 0x0026

func (s *smb1Session) onTransaction(req []byte) []byte {
	wc := int(req[32])
	if wc < 14 {
		return s.errReply(req, smb1StatusNotSupported)
	}
	params := req[33:]
	paramCount := int(binary.LittleEndian.Uint16(params[18:]))
	paramOffset := int(binary.LittleEndian.Uint16(params[20:]))
	dataCount := int(binary.LittleEndian.Uint16(params[22:]))
	dataOffset := int(binary.LittleEndian.Uint16(params[24:]))
	setupCount := int(params[26])

	// 报文顺序（逐字节核对过 samba 客户端，2026-11-11）：
	//   [0:28]      14 个固定字
	//   [28:28+2n]  SetupWords（n = SetupCount，计入 WordCount：wc = 14 + n）
	//   +0           ByteCount（2 字节）
	//   +2           字节数据区：可选 1 个对齐 pad → Name（NUL 结尾，Unicode 时 UTF-16）
	//                → pad → Trans_Parameters → pad → Trans_Data
	// ParameterOffset / DataOffset 是从 SMB 头起点算的绝对偏移。
	setup := make([]uint16, 0, setupCount)
	for i := 0; i < setupCount; i++ {
		off := 28 + i*2
		if off+2 > len(params) {
			break
		}
		setup = append(setup, binary.LittleEndian.Uint16(params[off:]))
	}
	bcPos := 28 + setupCount*2
	txName := ""
	if bcPos+2 <= len(params) {
		byteArea := params[bcPos+2:]
		if s.unicode && len(byteArea) >= 2 && byteArea[0] == 0 && byteArea[1] != 0 {
			byteArea = byteArea[1:] // Unicode 名字前的对齐 pad
		}
		txName, _ = s.decStr(byteArea)
	}
	txName = strings.TrimRight(txName, "\x00")

	paramArea := sliceAbs(req, paramOffset, paramCount)
	dataArea := sliceAbs(req, dataOffset, dataCount)
	upper := strings.ToUpper(txName)

	// 命名管道收发：SetupWords = {TRANS_NMPIPE, FID}
	if len(setup) >= 2 && setup[0] == transNMPipe {
		if of, ok := s.files[setup[1]]; ok && of.pipe != "" {
			return s.replyPipeTransaction(req, of, dataArea)
		}
		return s.errReply(req, smb1StatusInvalidParameter)
	}

	switch {
	case strings.Contains(upper, "LANMAN"):
		return s.onRAPShareEnum(req, paramArea, dataArea)
	case strings.Contains(upper, "SRVSVC"):
		// srvsvc 的 RPC 请求直接放在数据区，回包也放数据区。
		return s.replyTrans(req, smb1StatusSuccess, nil, handleSrvsvcRPC(dataArea, srvsvcShares(s.share)))
	}
	return s.errReply(req, smb1StatusNotSupported)
}

// replyPipeTransaction 处理在命名管道 FID 上发来的事务：请求数据喂给管道
// 处理器，输出原样回填到响应的数据区。
func (s *smb1Session) replyPipeTransaction(req []byte, of *smb1OpenFile, in []byte) []byte {
	out := s.pipeCall(of, in)
	return s.replyTrans(req, smb1StatusSuccess, nil, out)
}

// pipeCall 把一次 RPC 请求交给对应管道的处理器。
//
// 管道名统一在 pipeKey 里规范化（小写 + 去 \ 与结尾 NUL），这里只用规范化后的键。
func (s *smb1Session) pipeCall(of *smb1OpenFile, in []byte) []byte {
	switch of.pipe {
	case "srvsvc":
		return handleSrvsvcRPC(in, srvsvcShares(s.share))
	}
	return nil
}

// pipeKey 把管道名规范化成比较用的键：小写、去目录前缀、去结尾 NUL。
//
// NT_CREATE 的 NameLength 含结束 NUL，直接转小写会得到 "srvsvc\x00"，
// 与处理器名永远匹配不上——srvsvc 的事务因此全部回空，客户端报
// "rpc_pipe_bind for pipe srvsvc failed with error NT_STATUS_CONNECTION_DISCONNECTED"。
func pipeKey(name string) string {
	k := strings.TrimRight(name, "\x00")
	k = strings.ReplaceAll(k, `\`, "/")
	if i := strings.LastIndex(k, "/"); i >= 0 {
		k = k[i+1:]
	}
	return strings.ToLower(strings.TrimSpace(k))
}

// onRAPShareEnum 回答 MS-RAP 的 NetShareEnum（opcode 0）。老设备靠它列出共享名。
//
// 报文形状（MS-RAP 2.5.4.1 ShareInfo1，20 字节/项）：
//
//	参数区：Status(2)
//	数据区：EntryCount(2) + 每项 { NetName[13] + Type(2) + pad(1) + RemarkOffset(4) }
//
// 这块没法用现成客户端在本机复验（smbclient 走的是 SMB2 的 srvsvc），所以
// 只保证：结构自洽、不越界、老客户端拿不到共享时能干净地失败而不是断连。
func (s *smb1Session) onRAPShareEnum(req []byte, params, data []byte) []byte {
	_ = data
	// 参数区第一个 word 是 RAP 操作码；只处理 NetShareEnum(0)。
	if len(params) >= 2 && binary.LittleEndian.Uint16(params[0:]) != 0 {
		return s.errReply(req, smb1StatusNotSupported)
	}

	add := func(name string, typ uint16) []byte {
		e := make([]byte, 20)
		copy(e[0:13], []byte(name))
		binary.LittleEndian.PutUint16(e[13:], typ)
		e[15] = 0                                         // 对齐填充
		binary.LittleEndian.PutUint32(e[16:], 0xFFFFFFFF) // RemarkOffset: 无备注
		return e
	}
	entries := append(add(s.share, 0x0000), add("IPC$", 0x0003)...)

	rapData := make([]byte, 2, 2+len(entries))
	binary.LittleEndian.PutUint16(rapData[0:], 2) // 共享数
	rapData = append(rapData, entries...)

	rapParams := make([]byte, 2)
	binary.LittleEndian.PutUint16(rapParams[0:], 0) // Status: success
	return s.replyTrans(req, smb1StatusSuccess, rapParams, rapData)
}

// ---------- IPC$ 命名管道 ----------

// onPipeOpen 处理在 IPC$ 上打开命名管道（\srvsvc / \lanman / \browser…）。
//
// 老设备列共享有两条路：RAP（\PIPE\LANMAN 上的 TRANSACTION）和
// srvsvc 的 DCE/RPC。后者要先 CREATE 管道再在管道 FID 上发 TRANSACTION，
// 所以这里必须放行，否则客户端连 RPC 都发不出来，只能看到空的共享列表。
func (s *smb1Session) onPipeOpen(req []byte) []byte {
	wc := int(req[32])
	if wc < 24 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	params := req[33:]
	nameLen := int(binary.LittleEndian.Uint16(params[5:]))
	raw := nameAfterAlign(readDataArea(req, readByteCount(req)), s.unicode)
	name := ""
	if nameLen > 0 && nameLen <= len(raw) {
		if s.unicode {
			name = decodeUTF16Strict(raw[:nameLen])
		} else {
			name = string(raw[:nameLen])
		}
	} else {
		name, _ = s.decStr(raw)
	}
	pipe := pipeKey(name)

	fid := s.nextFID
	s.nextFID++
	if s.nextFID == 0 {
		s.nextFID = 1
	}
	s.files[fid] = &smb1OpenFile{pipe: pipe}
	return s.ntCreateReply(req, fid, 0, false, time.Now())
}

func (s *smb1Session) pipeRead(req []byte, of *smb1OpenFile, max int) []byte {
	out := of.buf
	of.buf = nil
	if len(out) > max {
		out = out[:max]
	}
	return s.readReply(req, out)
}

func (s *smb1Session) onWrite(req []byte) []byte {
	wc := int(req[32])
	if wc < 12 {
		return s.errReply(req, smb1StatusInvalidParameter)
	}
	params := req[33:]
	// WRITE_ANDX 请求：AndXCommand(1) AndXReserved(1) AndXOffset(2) FID(2)
	// Offset(4) Timeout(4) WriteMode(2) Remaining(4) DataLength(2) DataOffset(2)
	// [DataOffsetHigh(4)]。DataLength 因此落在 20、DataOffset 落在 22——
	// 少算 Remaining 的最后 2 字节就会把长度读成 0，管道的 RPC 全部变成空请求。
	fid := binary.LittleEndian.Uint16(params[4:])
	dataLen := int(binary.LittleEndian.Uint16(params[20:]))
	dataOff := int(binary.LittleEndian.Uint16(params[22:]))
	of, ok := s.files[fid]
	if !ok || of.pipe == "" {
		// 文件写入：只读通道一律拒绝
		return s.errReply(req, smb1StatusAccessDenied)
	}
	chunk := sliceAbs(req, dataOff, dataLen)
	resp := s.pipeCall(of, chunk)
	if resp != nil {
		of.buf = append(of.buf, resp...)
	}

	// WRITE_ANDX 响应：AndXCommand/AndXReserved/AndXOffset/Count/Available/Reserved(4)
	p := make([]byte, 12)
	p[0] = 0xFF
	binary.LittleEndian.PutUint16(p[4:], uint16(dataLen)) // Count
	binary.LittleEndian.PutUint16(p[6:], uint16(dataLen)) // Available
	return s.reply(req, smb1StatusSuccess, p, nil)
}


// onDiskSize 回共享的容量统计（SMB_COM_QUERY_INFORMATION_DISK）。
// 老设备点进共享后会先要一次，不给就报 dskattr 失败。
func (s *smb1Session) onDiskSize(req []byte) []byte {
	p := make([]byte, 10)
	binary.LittleEndian.PutUint16(p[0:], 1024)  // TotalUnits
	binary.LittleEndian.PutUint16(p[2:], 65535) // BlocksPerUnit
	binary.LittleEndian.PutUint16(p[4:], 4096)  // BlockSize
	binary.LittleEndian.PutUint16(p[6:], 512)   // FreeUnits
	return s.reply(req, smb1StatusSuccess, p, nil)
}

// ---------- 工具 ----------

func readByteCount(req []byte) int {
	wc := int(req[32])
	off := 33 + wc*2
	if off+2 > len(req) {
		return 0
	}
	return int(binary.LittleEndian.Uint16(req[off:]))
}

func readDataArea(req []byte, bc int) []byte {
	wc := int(req[32])
	off := 33 + wc*2 + 2
	if off >= len(req) {
		return nil
	}
	end := off + bc
	if end > len(req) {
		end = len(req)
	}
	return req[off:end]
}

// sliceAbs 从整条 SMB1 报文里按绝对偏移取一段；偏移无效时返回空。
func sliceAbs(req []byte, off, n int) []byte {
	if off <= 0 || n <= 0 || off >= len(req) || off+n > len(req) {
		return nil
	}
	return req[off : off+n]
}

// matchLoose 支持 * 和 ? 通配（老设备基本只用 *）。
func matchLoose(pattern, name string) bool {
	if pattern == "" || pattern == "*" || pattern == "*.*" {
		return true
	}
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(name))
	if err != nil {
		return true
	}
	return ok
}

// hideAppleMeta 与 SMB2 侧的隐藏策略保持一致：非 mac 客户端看不到影子文件。
func (s *smb1Session) hideAppleMeta() bool {
	// SMB1 通道服务的都是电视/投影/老播放器，一律按非 mac 处理。
	return true
}

var _ = sync.Mutex{}
