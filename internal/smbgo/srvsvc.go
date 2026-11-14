package smbgo

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

// srvsvc 是"列出共享"的 RPC 接口：资源管理器打开 \\服务器、net view、
// rpcclient 的 netshareenum 全靠它。IPC$ 管道共享挂的就是这个处理器。
//
// 依赖库自带的实现有两个致命伤，都是对照真实 Windows 抓包定下来的：
//
//   - NetrShareEnumAll（opnum 36）不认识，一律回 NACK。而 Windows 系工具
//     用的恰恰是 36，只有 smbclient 用 15。结果 \\192.0.2.11 打不开，
//     报"远程过程调用(RPC)协议出错"。
//   - NetrShareEnum（opnum 15）的响应 NDR 是错的：Level 后面凭空多了一个
//     DWORD、容器里多了两个 0，结尾又缺 ResumeHandle 的指针与解引用值。
//     客户端解不出 → WERR_RPC_S_CANNOT_SUPPORT / NDR 解析失败。
//
// 正确的字节布局（真实 Windows 响应，356 字节，已逐字节核对）：
//
//	Level(4) union标记(4,=Level) ptr→容器(4) EntriesRead(4) ptr→Buffer(4) 数组元素数(4)
//	每项 share_info_1{ ptr名字, type, ptr备注 }(12×n)
//	每个字符串{ MaxCount, Offset, ActualCount, UTF-16 + \0 + 对齐 }
//	TotalEntries(4) ptr→ResumeHandle(4) *ResumeHandle=0(4) WERR_OK(4)
//
// 参考指针从 0x00020000 起每多一个目标加 4，客户端拿它对齐数据位置。
const (
	srvsvcOpNetrShareEnum    = 15
	srvsvcOpNetrShareEnumAll = 36
)

// srvsvcShares 组装列共享要报的清单：磁盘共享在前，IPC$ 殿后。
func srvsvcShares(share string) [][2]string {
	return [][2]string{{share, ""}, {"IPC$", "Remote IPC"}}
}

// registerSrvsvc 在管道后端上注册 srvsvc，并返回挂了它的 IPC$ 共享。
// server.New 看到已存在名为 IPC$ 的共享就不会再塞它自己那套坏实现。
func registerSrvsvc(pb *vfs.PipeBackend, share string) vfs.Share {
	pb.Register("srvsvc", func(rpcData []byte) []byte {
		return handleSrvsvcRPC(rpcData, srvsvcShares(share))
	})
	return vfs.NewDiskShare("IPC$", pb)
}

func handleSrvsvcRPC(body []byte, shares [][2]string) []byte {
	if len(body) < 16 {
		return srvsvcNack(0)
	}
	callID := binary.LittleEndian.Uint32(body[12:16])
	switch body[2] {
	case 0x0B: // bind
		return srvsvcBindAck(callID)
	case 0x00: // request
		opnum := binary.LittleEndian.Uint16(body[22:24])
		if opnum == srvsvcOpNetrShareEnum || opnum == srvsvcOpNetrShareEnumAll {
			// 两个 opnum 的签名相同（MS-SRVS NetrShareEnum / NetrShareEnumAll），
			// 响应也是同一个 NDR 结构，直接复用。
			return srvsvcShareEnumResponse(callID, srvsvcLevelOf(body), shares)
		}
		return srvsvcNack(callID)
	default:
		return srvsvcNack(callID)
	}
}

// srvsvcLevelOf 从请求里取 Level（0 或 1），决定回 share_info_0 还是 share_info_1。
//
// 请求的 stub 是：ptr服务器名 + [字符串：MaxCount, Offset, ActualCount, UTF-16]
// + ptrInfoStruct + Level + ...。字符串长度因服务器名而异，必须跳过它再取 Level。
func srvsvcLevelOf(body []byte) uint32 {
	if len(body) < 40 {
		return 1
	}
	stub := body[24:]
	if binary.LittleEndian.Uint32(stub[0:]) == 0 { // 服务器名是 NULL 指针
		return 1
	}
	max := binary.LittleEndian.Uint32(stub[4:8])
	slen := int(max) * 2
	pad := (4 - slen%4) % 4
	off := 4 + 8 + slen + pad + 4 // 字符串头 + 字符串 + ptrInfoStruct
	if off+4 > len(stub) {
		return 1
	}
	switch lv := binary.LittleEndian.Uint32(stub[off:]); lv {
	case 0, 1, 2, 502:
		return lv
	default:
		return 1
	}
}

// srvsvcShareEnumResponse 构造 NetrShareEnum 系列的响应。字节布局见文件头注释。
func srvsvcShareEnumResponse(callID, level uint32, shares [][2]string) []byte {
	var buf []byte
	ref := uint32(0x00020000)
	nextRef := func() uint32 { r := ref; ref += 4; return r }
	u32 := func(v uint32) { buf = binary.LittleEndian.AppendUint32(buf, v) }
	// 字符串：MaxCount / Offset / ActualCount + UTF-16（含 \0）+ 4 字节对齐。
	str := func(s string) {
		runes := utf16.Encode([]rune(s))
		cnt := uint32(len(runes) + 1)
		u32(cnt)
		u32(0)
		u32(cnt)
		for _, r := range runes {
			buf = binary.LittleEndian.AppendUint16(buf, r)
		}
		buf = append(buf, 0, 0)
		for len(buf)%4 != 0 {
			buf = append(buf, 0)
		}
	}

	n := uint32(len(shares))
	u32(level)     // Level
	u32(level)     // union 的 switch tag：与 Level 相同（非封装联合体要先写标记）
	u32(nextRef()) // → ShareInfo 容器
	u32(n)         // EntriesRead
	u32(nextRef()) // → Buffer
	u32(n)         // 一致性数组的 MaxCount 在数据处再写一次
	for _, sh := range shares {
		switch level {
		case 0:
			// share_info_0：只有一个名字指针
			u32(nextRef())
		case 1:
			u32(nextRef())
			u32(srvsvcType(sh[0]))
			u32(nextRef())
		case 2:
			// share_info_2：share_info_1 + 权限/最大连接/当前连接
			u32(nextRef())
			u32(srvsvcType(sh[0]))
			u32(nextRef())
			u32(0)          // perms
			u32(0xffffffff) // max_uses（不限）
			u32(0)          // cur_uses
		case 502:
			// share_info_502：share_info_2 + 路径 + 口令
			u32(nextRef())
			u32(srvsvcType(sh[0]))
			u32(nextRef())
			u32(0)          // perms
			u32(0xffffffff) // max_uses
			u32(0)          // cur_uses
			u32(nextRef())  // 路径
			u32(0)          // 口令 = NULL 指针
		}
	}
	for _, sh := range shares {
		str(sh[0])
		if level >= 1 {
			str(sh[1])
		}
		if level == 502 {
			str("") // shi502_path：报空即可，浏览不需要它
		}
	}
	u32(n)         // TotalEntries
	u32(nextRef()) // → ResumeHandle（unique 指针，值在后面）
	u32(0)         // *ResumeHandle = 0
	u32(0)         // 返回值 WERR_OK（stub 的收尾 DWORD，漏了它客户端按"缓冲不足"处理）

	pad := (4 - len(buf)%4) % 4
	total := 24 + len(buf) + pad
	out := make([]byte, 24, total)
	out[0], out[1], out[2], out[3] = 5, 0, 0x02, 0x03 // response / 小端 / 并发
	binary.LittleEndian.PutUint32(out[4:], 0x10)
	binary.LittleEndian.PutUint32(out[8:], uint32(total))
	binary.LittleEndian.PutUint32(out[12:], callID)
	binary.LittleEndian.PutUint32(out[16:], uint32(len(buf))) // alloc hint
	out = append(out, buf...)
	out = append(out, make([]byte, pad)...)
	return out
}

// srvsvcType 共享类型位：磁盘 0（STYPE_DISKTREE），IPC 是 SPECIAL|IPC（0x80000003），
// 与真实 Windows 的响应一致。
func srvsvcType(name string) uint32 {
	if name == "IPC$" {
		return 0x80000003
	}
	return 0
}

// srvsvcBindAck 回 bind 确认。这 56 字节沿用库的形状——smbclient 和 rpcclient
// 都接受它，问题只在后续的响应 stub，没必要改。
func srvsvcBindAck(callID uint32) []byte {
	b := make([]byte, 56)
	b[0], b[1], b[2], b[3] = 5, 0, 0x0C, 0x03
	binary.LittleEndian.PutUint32(b[4:], 0x10)
	binary.LittleEndian.PutUint32(b[8:], 56)
	binary.LittleEndian.PutUint32(b[12:], callID)
	binary.LittleEndian.PutUint16(b[16:], 5840)
	binary.LittleEndian.PutUint16(b[18:], 5840)
	binary.LittleEndian.PutUint32(b[20:], 0x000053b6)
	binary.LittleEndian.PutUint16(b[24:], 0)
	binary.LittleEndian.PutUint16(b[26:], 40)
	binary.LittleEndian.PutUint32(b[28:], 1)
	tsUUID := [16]byte{
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	}
	copy(b[36:52], tsUUID[:])
	binary.LittleEndian.PutUint32(b[52:], 2)
	return b
}

// srvsvcNack 拒绝不认识的调用。
func srvsvcNack(callID uint32) []byte {
	b := make([]byte, 32)
	b[0], b[1], b[2], b[3] = 5, 0, 0x03, 0x03
	binary.LittleEndian.PutUint32(b[4:], 0x10)
	binary.LittleEndian.PutUint32(b[8:], 32)
	binary.LittleEndian.PutUint32(b[12:], callID)
	binary.LittleEndian.PutUint32(b[16:], 20)
	binary.LittleEndian.PutUint32(b[24:], 0x000006E4)
	return b
}
