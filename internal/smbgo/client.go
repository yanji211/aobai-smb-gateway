package smbgo

// 本文件是「接入端识别」：在协议边界上认出这次连进来的是什么系统，
// 并据此决定补哪几种兼容处理。
//
// 为什么非要认人：同一个服务端，Windows 资源管理器用得好好的，Linux 的
// 内核 CIFS 却连挂都挂不上。差别不在认证——内核比 Windows 严格得多：
//   - 它会用 FSCTL_VALIDATE_NEGOTIATE_INFO 把协商结果再核对一遍，
//     任何一个字段对不上就报 "security settings mismatch"，直接放弃；
//   - 它还会去查 FileFsDeviceInformation / FileFsSectorSizeInformation
//     这两个 Windows 从来不问的信息类，拿不到就把"取根 inode"判失败。
//
// macOS 又是另一套：Finder 只认 SPNEGO 包装的令牌，且默认要求签名，
// 而来宾会话根本没有会话密钥可以签。
//
// 所以做法是：先按首帧 NEGOTIATE 的形状投票认人，再按类型开对应的兼容补丁。
// 认错了也不致命——所有补丁补的都是"本来就该回、只是以前没回"的合法内容，
// 对 Windows 无副作用；真正需要区分对待的只有 fsProbe 这一项。

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
)

// ClientKind 是接入端大类。命名用协议实现而不是操作系统版本，
// 因为决定兼容行为的是"谁实现的客户端"，不是"跑的哪个发行版"。
type ClientKind string

const (
	ClientWindows    ClientKind = "windows"     // Windows 资源管理器 / net use
	ClientMacOS      ClientKind = "macos"       // macOS Finder（SMB2/3）
	ClientLinuxCIFS  ClientKind = "linux-cifs"  // Linux 内核 CIFS（mount -t cifs）
	ClientLinuxSamba ClientKind = "linux-samba" // Samba 用户态客户端（smbclient / libsmbclient / gvfs）
	ClientOther      ClientKind = "other"       // 电视、Android 文件管理器、老系统
	ClientUnknown    ClientKind = "unknown"     // 证据不足
)

// Label 是给人看的中文名。
func (k ClientKind) Label() string {
	if s, ok := clientLabels[k]; ok {
		return s
	}
	return string(k)
}

var clientLabels = map[ClientKind]string{
	ClientWindows:    "Windows",
	ClientMacOS:      "macOS",
	ClientLinuxCIFS:  "Linux（内核 CIFS）",
	ClientLinuxSamba: "Linux（Samba 客户端）",
	ClientOther:      "其他设备",
	ClientUnknown:    "未知",
}

// ClientInfo 是一次连接上认出来的接入端信息。
//
// Evidence 一并留着：识别不可能百分之百准，出问题时"凭什么这么判"比结论
// 本身更有用（日志和面板都会打出来）。
type ClientInfo struct {
	Kind     ClientKind `json:"kind"`
	Label    string     `json:"label"`
	Dialects []string   `json:"dialects,omitempty"`
	Caps     uint32     `json:"capabilities,omitempty"`
	Guid     string     `json:"client_guid,omitempty"`
	SecMode  uint16     `json:"security_mode,omitempty"`
	Evidence []string   `json:"evidence,omitempty"`
	// Hinted 表示这条结论来自配置里的 client_hints（人工指定），
	// 而不是协议指纹推断。人工指定的优先级最高。
	Hinted bool `json:"hinted,omitempty"`
}

func (c *ClientInfo) add(ev string) {
	c.Evidence = append(c.Evidence, ev)
}

// ---------- 识别 ----------

// sniffSMB1 从 SMB1 NEGOTIATE 里找 NativeOS / NativeLanMan。
//
// SMB1 的 NEGOTIATE 请求在方言列表后面跟着两个以 NUL 结尾的字符串：
//
//	NativeOS      "Windows 10.0" / "Samba 4.22.11" / "Mac OS X 13.5"
//	NativeLanMan  "Windows 10.0" / "Samba 4.22.11" / "Mac OS X 13.5"
//
// 这两个字段是**客户端自报**的，也是所有识别手段里最直接的一个。
// 只有一个坑：flags2 里 Unicode 位置了的话它们是 UTF-16LE，否则是 ASCII。
// 这里两种都试，不做精确的字段定位——字符串很短，子串匹配不会误伤，
// 而按 SMB1 规范逐字段解析反而容易在畸形报文上跑飞。
func sniffSMB1(frame []byte) *ClientInfo {
	if len(frame) < nbHeaderLen+32 {
		return nil
	}
	h := frame[nbHeaderLen:]
	if h[0] != 0xFF || string(h[1:4]) != "SMB" {
		return nil
	}
	ci := &ClientInfo{Kind: ClientUnknown}
	found := func(s string) bool {
		return bytes.Contains(frame, []byte(s)) || bytes.Contains(frame, utf16ASCII(s))
	}
	switch {
	case found("Windows"):
		ci.Kind = ClientWindows
		ci.add("SMB1 NativeOS 含 Windows")
	case found("Mac OS X") || found("macOS"):
		ci.Kind = ClientMacOS
		ci.add("SMB1 NativeOS 含 Mac OS X")
	case found("Samba"):
		ci.Kind = ClientLinuxSamba
		ci.add("SMB1 NativeOS 含 Samba")
	case found("Unix") || found("Linux"):
		ci.Kind = ClientLinuxSamba
		ci.add("SMB1 NativeOS 含 Unix/Linux")
	}
	if ci.Kind == ClientUnknown {
		return nil // SMB1 报文里没带自报串，交给后面的 SMB2 指纹
	}
	ci.Label = ci.Kind.Label()
	return ci
}

// smb1Dialects 从 SMB_COM_NEGOTIATE 请求里取出方言表（如 "NT LM 0.12"）。
//
// 报文（MS-CIFS 2.2.4.52）：
//
//	NB 头(4) | SMB1 头(32) | WordCount(1)=0 | ByteCount(2) | 方言列表
//
// 方言列表每项是 0x02 + ASCII 名 + 0x00。解析失败返回 nil（调用方据此保持
// 原来的"一律当 Windows"行为，不误伤）。
func smb1Dialects(frame []byte) []string {
	const off = nbHeaderLen + 32
	if len(frame) < off+3 {
		return nil
	}
	if frame[nbHeaderLen] != 0xFF || string(frame[nbHeaderLen+1:nbHeaderLen+4]) != "SMB" {
		return nil
	}
	if frame[nbHeaderLen+4] != 0x72 { // SMB_COM_NEGOTIATE
		return nil
	}
	if frame[off] != 0 { // 带扩展安全协商时 WordCount=0；非 0 的结构不在这里处理
		return nil
	}
	n := int(binary.LittleEndian.Uint16(frame[off+1 : off+3]))
	body := frame[off+3:]
	if n <= 0 || len(body) < n {
		return nil
	}
	body = body[:n]
	var out []string
	for i := 0; i < len(body); {
		if body[i] != 0x02 {
			i++
			continue
		}
		j := bytes.IndexByte(body[i+1:], 0)
		if j < 0 {
			break
		}
		out = append(out, string(body[i+1:i+1+j]))
		i += j + 2
	}
	return out
}

// smb1Only 判断这条 SMB1 协商是不是"纯 SMB1 客户端"——方言表里一个 SMB2
// 方言都没有。
//
// 这条判据是为小米电视加的。实测（2026-11-10，110 生产，抓包对照）：电视的
// SMB 客户端只发一个方言 `NT LM 0.12`，没有 `SMB 2.002`/`SMB 2.???`。
// 把它的协商改写成 SMB2 之后，它收到 SMB2 协商响应完全看不懂，直接放弃
// （抓包里服务端回了 dialect=0x0302、status=0，之后客户端一个字节都不再发）。
//
// Windows 与它长得像但本质不同：Windows 的探测包里同时列着 `SMB 2.002`，
// 拿到 SMB2 响应会接着走 SMB2 会话。
func smb1Only(dialects []string) bool {
	if len(dialects) == 0 {
		return false
	}
	for _, d := range dialects {
		if strings.HasPrefix(strings.ToUpper(d), "SMB 2") {
			return false
		}
	}
	return true
}

// sniffSMB2 从 SMB2 NEGOTIATE 请求里读方言表与能力位，据此判断客户端。
//
// 请求体（MS-SMB2 2.2.3）：
//
//	StructureSize(2) DialectCount(2) SecurityMode(2) Reserved(2)
//	Capabilities(4) ClientGuid(16) ContextOffset(4) ContextCount(2)
//	Reserved2(2) Dialects(2*count)
func sniffSMB2(frame []byte) (*ClientInfo, bool) {
	return sniffSMB2After(frame, false)
}

// sniffSMB2After 是 sniffSMB2 的带上下文版本。
//
// afterProbe 表示"这条连接先发过 SMB1 探测包"。这个信息很关键：Windows
// 发完探测包拿到 SMB2 协商响应后**直接进 SESSION_SETUP**，从不补发一条
// 独立的 SMB2 NEGOTIATE 请求；所以在 afterProbe 为真时又看到 SMB2
// NEGOTIATE，就说明对方不是 Windows，不能再按 Windows 画像处理。
func sniffSMB2After(frame []byte, afterProbe bool) (*ClientInfo, bool) {
	if len(frame) < smb2HeaderLen+36 {
		return nil, false
	}
	if frame[0] != 0xFE || string(frame[1:4]) != "SMB" {
		return nil, false
	}
	if binary.LittleEndian.Uint16(frame[12:]) != smb2CmdNegotiate {
		return nil, false
	}
	if binary.LittleEndian.Uint32(frame[16:])&smb2FlagResponse != 0 {
		return nil, false // 这是响应，不是请求
	}
	body := frame[smb2HeaderLen:]
	if binary.LittleEndian.Uint16(body[0:]) != 36 {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(body[2:]))
	if n <= 0 || 36+2*n > len(body) {
		return nil, false
	}
	dialects := make([]uint16, 0, n)
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		d := binary.LittleEndian.Uint16(body[36+2*i:])
		dialects = append(dialects, d)
		names = append(names, dialectName(d))
	}
	// 注意偏移：请求体是
	//	StructureSize(0) DialectCount(2) SecurityMode(4) Reserved(6)
	//	Capabilities(8) ClientGuid(12) ...
	// 而响应体的 Capacities 在 24、ServerGuid 在 8——两者的布局不一样，
	// 照响应去读请求会读成一堆随机数（曾经就是这么错的）。
	ci := &ClientInfo{
		Dialects: names,
		SecMode:  binary.LittleEndian.Uint16(body[4:]),
		Caps:     binary.LittleEndian.Uint32(body[8:]),
		Guid:     hex.EncodeToString(body[12:28]),
	}
	ci.Kind = classifyNegotiate(dialects, ci.Caps, ci, afterProbe)
	ci.Label = ci.Kind.Label()
	return ci, true
}

// classifyNegotiate 是识别的核心规则表。规则按"证据强度"从强到弱排列，
// 命中即返回，并把命中的理由记进 Evidence。
//
//  1. 只声明一个方言 —— Linux 内核 CIFS 的特征。mount.cifs 会把
//     `vers=` 翻成恰好一条 DialectRevision 填进请求，不写 vers 时也只报
//     一条（默认挑一个协商）。Windows 和 macOS 永远整套列出来。
//     这是全表里最硬的信号，实测 110 上 `mount -t cifs -o vers=3.0`
//     与不写 vers 两种情形都只发 0x0300 一个方言。
//
//  2. 有 3.1.1 但没有 ENCRYPTION 能力位 —— macOS。macOS 的 SMB 客户端
//     至今没实现 SMB3 加密，能力位里不会出现 SMB2_GLOBAL_CAP_ENCRYPTION；
//     而 Samba 用户态客户端（smbclient / gvfs）默认是带的。这一条把两者
//     分开。
//
//  3. 有 ENCRYPTION 能力位 —— Samba 用户态。gvfs（Nautilus 里点
//     smb://）走的也是这套，所以文件管理器能连、mount 不能连时，
//     日志里会直接显示成两类不同的客户端。
//
//  4. 其余 —— 按 Windows 处理。注意走到这里的 Windows 很少：Windows 的
//     首包通常是 SMB1 探测包，在 relay 里就已经认出来了（见 relay 的注释）。
//     这里的兜底主要给"禁用了 SMB1 的 Windows"和识别不出形状的设备用，
//     它们走验证过的 Windows 路径最安全。
func classifyNegotiate(dialects []uint16, caps uint32, ci *ClientInfo, afterProbe bool) ClientKind {
	// MS-SMB2 2.2.3 的 SMB2_GLOBAL_CAP_*：加密是 0x40，不是 0x20
	// （0x20 是 DIRECTORY_LEASING）。这一位是区分 macOS 与 Samba 的关键——
	// macOS 至今没实现 SMB3 加密，能力位里不会有它。
	const (
		capDFS       = 0x00000001
		capLargeMTU  = 0x00000004
		capMultiChan = 0x00000008
		capPersist   = 0x00000010
		capEncrypt   = 0x00000040
		dialect311   = 0x0311
	)

	has311 := false
	has3x := false
	for _, d := range dialects {
		if d == dialect311 {
			has311 = true
		}
		if d >= 0x0300 {
			has3x = true
		}
	}

	switch {
	// 先发 SMB1 探测、之后又补发一条独立的 SMB2 协商请求——Windows 不这么干。
	// 实测 Windows 10/11 拿到探测包的 SMB2 协商响应后直接进 SESSION_SETUP。
	// 所以这一条足以把 Windows 排除掉，剩下的常见客户端里会这么做的只有
	// macOS。再配一个 MULTI_CHANNEL(0x08)：mac 有（caps 0x7f），Samba 与
	// Linux 内核都没有（Linux 内核实测 0x77）。
	case afterProbe && caps&capMultiChan != 0:
		ci.add("SMB1 探测后又补发 SMB2 协商，且带 MULTI_CHANNEL：排除 Windows，判为 macOS")
		return ClientMacOS
	case len(dialects) == 1 && !afterProbe:
		ci.add("只声明 1 个方言（" + dialectName(dialects[0]) + "），内核 CIFS 的特征")
		return ClientLinuxCIFS
	case caps&(capMultiChan|capPersist) != 0:
		// MULTI_CHANNEL / PERSISTENT_HANDLES 是 Windows 从 SMB 3.0 起就带的能力位，
		// macOS 两个都没有。放在加密位之前判，因为 Windows 也带 ENCRYPTION，
		// 只看加密位会把它和 Samba 混在一起。
		ci.add("带 MULTI_CHANNEL/PERSISTENT_HANDLES 能力位（Windows 特征）")
		return ClientWindows
	case has311 && caps&capEncrypt == 0:
		ci.add("声明 3.1.1 但无 ENCRYPTION 能力位，macOS 的特征")
		return ClientMacOS
	case caps&capEncrypt != 0:
		ci.add("带 ENCRYPTION 能力位（Samba 用户态客户端）")
		return ClientLinuxSamba
	case has3x && caps&(capDFS|capLargeMTU) != 0:
		ci.add("整套方言 + DFS/LARGE_MTU，按 Windows 处理")
		return ClientWindows
	default:
		// 只剩 SMB2.0/2.1 的设备（电视、老 NAS），以及能力位异常的未知实现。
		// 都归到"其他"，兼容补丁按最保守的一档开。
		ci.add("未识别的方言组合，按其他设备处理")
		return ClientOther
	}
}

func dialectName(d uint16) string {
	switch d {
	case 0x0202:
		return "2.0.2"
	case 0x0210:
		return "2.1"
	case 0x0300:
		return "3.0"
	case 0x0302:
		return "3.0.2"
	case 0x0311:
		return "3.1.1"
	case 0x02FF:
		return "2.???"
	}
	return "0x" + hex.EncodeToString([]byte{byte(d >> 8), byte(d)})
}

// ---------- 人工指定 ----------

// ClientHint 让用户在配置里直接指定某台机器是什么客户端。
//
// 为什么需要：协议指纹终究是推断。真机上遇到"认错了导致补丁没开"的情况，
// 用户应该能一行配置解决，而不是等着改代码重新发版。
//
// IP 支持完整地址或前缀：`192.0.2.50` 精确匹配，
// `192.0.2.` 匹配整段（前缀按字符串比，不做网段计算——共享场景够用，
// 而且行为一眼能看懂）。
type ClientHint struct {
	IP   string
	Kind ClientKind
}

// matchHint 按顺序找第一条命中的提示。返回的 kind 可能无效（拼错了），
// 由调用方忽略。
func matchHint(remote string, hints []ClientHint) (ClientKind, bool) {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}
	for _, h := range hints {
		p := strings.TrimSpace(h.IP)
		if p == "" {
			continue
		}
		if host == p || strings.HasPrefix(host, p) {
			if _, ok := clientLabels[h.Kind]; ok {
				return h.Kind, true
			}
		}
	}
	return "", false
}

// ---------- 兼容画像 ----------

// compat 是"这个客户端需要补哪些东西"。
//
// 每一条都对应一个真实的、只在特定客户端上暴露的协议缺陷：
//
//	fsProbe       —— 内核 CIFS / macOS 会查 FileFsDeviceInformation(0x04) 与
//	                 FileFsSectorSizeInformation(0x0b)。内层对这两类回
//	                 STATUS_INVALID_PARAMETER，内核据此判"取根 inode 失败"，
//	                 挂载直接 abort（dmesg: cifs_read_super: get root inode failed）。
//	                 Windows 从不查这两类，所以以前没人发现。
//
//	validateNego  —— FSCTL_VALIDATE_NEGOTIATE_INFO 的响应内层是按请求字段
//	                 回显的：OutputCount=0、StructureSize 写成请求的 57。
//	                 内核按规范解析得到空数据，比对协商结果时全体不一致，
//	                 报 "protocol revalidation - security settings mismatch"。
//	                 Windows 不主动发这个 ioctl（只在重连时发，且容错），
//	                 所以也一直没暴露。这一条对谁都重写，因为内层那份是错的。
type compat struct {
	fsProbe      bool
	validateNego bool
}

// compatFor 按接入端类型给出兼容画像。
//
// Windows 不开 fsProbe 是刻意的：它不查，而多回两类数据意味着多覆盖两个
// 已经验证过的代码路径。宁可让 Windows 走原路。
func compatFor(k ClientKind) compat {
	switch k {
	case ClientWindows:
		return compat{fsProbe: false, validateNego: true}
	case ClientLinuxCIFS, ClientMacOS, ClientLinuxSamba:
		return compat{fsProbe: true, validateNego: true}
	default:
		// 未知与老设备：补上无害，缺了可能连不上。
		return compat{fsProbe: true, validateNego: true}
	}
}

// utf16ASCII 把纯 ASCII 串转成 UTF-16LE 字节，用于在 SMB1 报文里
// 同时匹配 ASCII 与 Unicode 两种编码的自报串。
func utf16ASCII(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}
