//go:build linux || windows

package smbgo

// 复合请求（RELATED_OPERATIONS）与 FILE_ALL_INFORMATION 的回归测试。
//
// 这两块都是"Linux 挂不挂得上"的直接开关：
//   - 复合请求拆不开，内核拿不到根目录的 FileAllInformation，报 get root inode
//     failed，mount error(9)；
//   - FileAllInformation 短于 101 字节，内核报 buffer length smaller than
//     minimum size，mount error(20) Not a directory。
// 都属于改字节的活，偏移错一位就是另一条错误码，所以逐字段盯。

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// smb2Msg 拼一条不带 NetBIOS 头的 SMB2 消息，供组装复合报文用。
func smb2Msg(cmd uint16, mid uint64, flags uint32, body []byte) []byte {
	hdr := make([]byte, smb2HeaderLen)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:], smb2HeaderLen)
	binary.LittleEndian.PutUint16(hdr[12:], cmd)
	binary.LittleEndian.PutUint32(hdr[16:], flags)
	binary.LittleEndian.PutUint64(hdr[24:], mid)
	return append(hdr, body...)
}

// compound 把若干消息串成一条复合报文（带 NetBIOS 头，NextCommand 已接好）。
func compound(msgs ...[]byte) []byte {
	var body []byte
	for i, m := range msgs {
		next := 0
		if i+1 < len(msgs) {
			next = len(m)
		}
		binary.LittleEndian.PutUint32(m[20:], uint32(next))
		body = append(body, m...)
	}
	out := make([]byte, nbHeaderLen)
	out = append(out, body...)
	fixNBLength(out)
	return out
}

func createReq(mid uint64) []byte {
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:], 57)
	return smb2Msg(smb2CmdCreate, mid, 0, body)
}

func createResp(mid uint64, fileID []byte) []byte {
	body := make([]byte, 88)
	binary.LittleEndian.PutUint16(body[0:], 89)
	binary.LittleEndian.PutUint32(body[4:], 1) // CreateAction = FILE_OPENED
	copy(body[64:80], fileID)
	return smb2Frame(smb2CmdCreate, mid, body)
}

// queryInfoReq 造一条 FileAllInformation 的 QUERY_INFO 请求（body 40 字节，
// 和内核在复合里发的一模一样）。
func queryInfoReq(mid uint64, fileID []byte, related bool) []byte {
	body := make([]byte, 40)
	binary.LittleEndian.PutUint16(body[0:], 41)
	body[2] = infoTypeFile
	body[3] = fileAllInformation
	binary.LittleEndian.PutUint32(body[4:], 8192) // OutputBufferLength
	copy(body[24:40], fileID)
	flags := uint32(0)
	if related {
		flags = smb2FlagRelated
	}
	return smb2Msg(smb2CmdQueryInfo, mid, flags, body)
}

func closeReq(mid uint64, fileID []byte, related bool) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 24)
	copy(body[8:24], fileID)
	flags := uint32(0)
	if related {
		flags = smb2FlagRelated
	}
	return smb2Msg(smb2CmdClose, mid, flags, body)
}

func reservedFileID() []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = 0xFF
	}
	return b
}

func TestFileIDOffset(t *testing.T) {
	cases := map[uint16]int{
		smb2CmdClose:     8,
		smb2CmdIoctl:     8,
		smb2CmdQueryDir:  8,
		smb2CmdSetInfo:   16,
		smb2CmdQueryInfo: 24,
		smb2CmdCreate:    0, // 没有 FileId 字段
	}
	for cmd, want := range cases {
		if got := fileIDOffset(cmd); got != want {
			t.Errorf("fileIDOffset(%d) = %d，应为 %d", cmd, got, want)
		}
	}
}

func TestIsReservedFileID(t *testing.T) {
	if !isReservedFileID(reservedFileID()) {
		t.Error("全 0xFF 应识别为保留句柄")
	}
	real := reservedFileID()
	real[15] = 0
	if isReservedFileID(real) {
		t.Error("不是全 0xFF 就不该当保留句柄")
	}
	if isReservedFileID([]byte{0xFF}) {
		t.Error("长度不足时不能误判")
	}
}

func TestSplitMessages(t *testing.T) {
	fileID := reservedFileID()
	frame := compound(
		createReq(17),
		queryInfoReq(18, fileID, true),
		closeReq(19, fileID, true),
	)
	msgs := splitMessages(frame)
	if len(msgs) != 3 {
		t.Fatalf("应拆出 3 条，实际 %d", len(msgs))
	}
	for i, m := range msgs {
		h := m[nbHeaderLen:]
		if got := binary.LittleEndian.Uint32(h[20:]); got != 0 {
			t.Errorf("第 %d 条拆开后 NextCommand 应为 0，实际 %d", i, got)
		}
		if got := binary.LittleEndian.Uint64(h[24:]); got != uint64(17+i) {
			t.Errorf("第 %d 条 MessageId 应为 %d，实际 %d", i, 17+i, got)
		}
	}
	if got := len(msgs[1]) - nbHeaderLen; got != smb2HeaderLen+40 {
		t.Errorf("QUERY_INFO 请求体应为 40 字节，实际消息长 %d", got)
	}
}

func TestMergeMessagesMarksRelated(t *testing.T) {
	resps := [][]byte{
		createResp(17, make([]byte, 16)),
		smb2Frame(smb2CmdQueryInfo, 18, make([]byte, 8)),
		smb2Frame(smb2CmdClose, 19, make([]byte, 8)),
	}
	out := mergeMessages(resps)
	// 逐段走一遍，检查 NextCommand 串接与 RELATED 标志。
	off := nbHeaderLen
	for i := 0; i < 3; i++ {
		h := out[off:]
		flags := binary.LittleEndian.Uint32(h[16:])
		next := int(binary.LittleEndian.Uint32(h[20:]))
		if i == 0 {
			if flags&smb2FlagRelated != 0 {
				t.Error("第一段不该带 RELATED 标志")
			}
			if next == 0 {
				t.Fatal("非末段的 NextCommand 不能是 0")
			}
		} else {
			if flags&smb2FlagRelated == 0 {
				t.Errorf("第 %d 段必须带 RELATED 标志，否则客户端直接把这段丢掉", i)
			}
			if i == 2 && next != 0 {
				t.Error("末段的 NextCommand 必须是 0")
			}
		}
		if next > 0 {
			off += next
		}
	}
	if off+nbHeaderLen+smb2HeaderLen > len(out) {
		t.Error("合并后的长度与 NextCommand 对不上")
	}
}

// TestMergeMessagesAlignsNextCommand 复现小米电视的复合响应。
//
// 电视（SMB 2.0.2）点开共享时发的是 CREATE("") + QUERY_INFO + CLOSE 三连击，
// 内层回的 CREATE 响应是 64 字节头 + 89 字节体 = 153 字节。153 不是 8 的倍数，
// 如果原样写进 NextCommand，客户端会在 153 这个错位位置读下一条报文的头，
// 解不出 0xFE534D42，于是整条复合响应作废、连接立刻 RST —— 表现为"点进共享
// 马上断开"。MS-SMB2 3.2.5.1.1 要求 NextCommand 必须是 8 的整数倍。
func TestMergeMessagesAlignsNextCommand(t *testing.T) {
	// 故意造一条 89 字节体的 CREATE 响应：64+89 = 153，不是 8 的倍数。
	oddCreate := func(mid uint64) []byte {
		body := make([]byte, 89)
		binary.LittleEndian.PutUint16(body[0:], 89)
		return smb2Frame(smb2CmdCreate, mid, body)
	}
	resps := [][]byte{
		oddCreate(13),
		smb2Frame(smb2CmdQueryInfo, 14, make([]byte, 8)),
		smb2Frame(smb2CmdClose, 15, make([]byte, 8)),
	}
	out := mergeMessages(resps)

	off := nbHeaderLen
	seen := 0
	for {
		if off+smb2HeaderLen > len(out) {
			t.Fatalf("第 %d 段读不到完整报文头，合并结果长度 %d、偏移 %d", seen, len(out), off)
		}
		h := out[off:]
		if h[0] != 0xFE || string(h[1:4]) != "SMB" {
			t.Fatalf("第 %d 段偏移 %d 处不是 SMB2 报文头（NextCommand 没对齐）", seen, off)
		}
		next := int(binary.LittleEndian.Uint32(h[20:]))
		if next != 0 && off+next > len(out) {
			t.Fatalf("第 %d 段 NextCommand=%d 越界（总长 %d、偏移 %d）", seen, next, len(out), off)
		}
		seen++
		if next == 0 {
			break
		}
		if next%8 != 0 {
			t.Errorf("第 %d 段 NextCommand=%d 不是 8 的整数倍", seen-1, next)
		}
		off += next
	}
	if seen != 3 {
		t.Errorf("应能完整走完 3 段，实际 %d 段", seen)
	}
	// 首段本来 153，补齐后必须是 160。
	if got := binary.LittleEndian.Uint32(out[nbHeaderLen+20:]); got != 160 {
		t.Errorf("首段 NextCommand 应为补齐后的 160，实际 %d", got)
	}
}

// TestExchangeCompound 用管道模拟内层服务端，验证：
//   - 保留 FileId 被换成上一条 CREATE 返回的真句柄；
//   - RELATED 标志被抹掉（否则内层仍当"沿用上一条"处理）；
//   - QUERY_INFO 被补到 41 字节请求体（内层解析的最低要求）；
//   - 三条响应被合回一条复合响应。
func TestExchangeCompound(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.comp = compatFor(ClientLinuxCIFS)

	realID := []byte{
		0x01, 0, 0, 0, 0, 0, 0, 0,
		0x01, 0, 0, 0, 0x05, 0, 0, 0,
	}
	up, srv := net.Pipe()
	defer up.Close()
	defer srv.Close()

	type seen struct {
		cmd    uint16
		fileID []byte
		flags  uint32
		length int
	}
	got := make(chan seen, 3)
	go func() {
		for i := 0; i < 3; i++ {
			frame, _, err := readFrame(srv)
			if err != nil {
				return
			}
			h := frame[nbHeaderLen:]
			cmd := binary.LittleEndian.Uint16(h[12:])
			mid := binary.LittleEndian.Uint64(h[24:])
			s := seen{cmd: cmd, flags: binary.LittleEndian.Uint32(h[16:]), length: len(frame) - nbHeaderLen}
			if off := fileIDOffset(cmd); off > 0 {
				s.fileID = append([]byte(nil), h[smb2HeaderLen+off:smb2HeaderLen+off+16]...)
			}
			got <- s

			var resp []byte
			switch cmd {
			case smb2CmdCreate:
				resp = createResp(mid, realID)
			default:
				resp = smb2Frame(cmd, mid, make([]byte, 8))
			}
			// 走和真实链路一样的投递方式：pumpToClient 用 claimWaiter 把响
			// 应交给等待者。
			ch, ok := st.claimWaiter(resp)
			if !ok {
				t.Errorf("msgID %d 没有登记等待者", mid)
				return
			}
			ch <- resp
		}
	}()

	frame := compound(
		createReq(17),
		queryInfoReq(18, reservedFileID(), true),
		closeReq(19, reservedFileID(), true),
	)
	out, ok := st.exchangeCompound(frame, up)
	if !ok {
		t.Fatal("带 RELATED 的复合请求应被接管")
	}
	if out == nil {
		t.Fatal("应合回一条复合响应")
	}

	for i := 0; i < 3; i++ {
		select {
		case s := <-got:
			if i > 0 && s.flags&smb2FlagRelated != 0 {
				t.Errorf("第 %d 条发给内层时 RELATED 标志应已抹掉", i)
			}
			if i > 0 && string(s.fileID) != string(realID) {
				t.Errorf("第 %d 条的 FileId 应换成 CREATE 返回的句柄，实际 %x", i, s.fileID)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("第 %d 条一直没发到内层", i)
		}
	}
}

// 复合请求里若没有 RELATED 标志，内层自己能处理，代理层不该插手。
func TestExchangeCompoundIgnoresPlainChain(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	frame := compound(createReq(17), queryInfoReq(18, reservedFileID(), false))
	if _, ok := st.exchangeCompound(frame, nil); ok {
		t.Error("没有 RELATED 标志的复合请求不该被接管")
	}
}

// 内核要求这块缓冲至少 101 字节（sizeof(FILE_ALL_INFO)），且链接数不能是 0。
func TestFixFileAllInfo(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.comp = compatFor(ClientLinuxCIFS)
	st.noteQueryInfo(9, qinfoReq{infoType: infoTypeFile, class: fileAllInformation})

	// 内层给的 84 字节：Basic(40) + Standard(24) + 20 字节错位的"空字段"。
	inner := make([]byte, 84)
	for i := 0; i < 40; i++ {
		inner[i] = byte(i) // Basic
	}
	binary.LittleEndian.PutUint64(inner[40:], 4096) // AllocationSize
	binary.LittleEndian.PutUint64(inner[48:], 123)  // EndOfFile
	// inner[56:60] = NumberOfLinks，内层这次是 0 → 内核会报 bogus nlink
	inner[61] = 1 // Directory

	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:], 9)
	binary.LittleEndian.PutUint16(body[2:], smb2HeaderLen+8)
	binary.LittleEndian.PutUint32(body[4:], uint32(len(inner)))
	body = append(body, inner...)

	out, ok := fixFileAllInfo(smb2Frame(smb2CmdQueryInfo, 9, body), st)
	if !ok {
		t.Fatal("FileAllInformation 应被补全")
	}
	b := out[nbHeaderLen+smb2HeaderLen:]
	data := b[8:]
	if len(data) < 101 {
		t.Fatalf("补全后至少 101 字节，实际 %d", len(data))
	}
	if got := binary.LittleEndian.Uint32(data[56:]); got != 1 {
		t.Errorf("NumberOfLinks 应为 1，实际 %d（0 会让内核报 bogus nlink）", got)
	}
	if data[61] != 1 {
		t.Error("Directory 标志必须原样保留")
	}
	if got := binary.LittleEndian.Uint64(data[48:]); got != 123 {
		t.Errorf("EndOfFile 应保留，实际 %d", got)
	}
	if got := binary.LittleEndian.Uint32(data[96:]); got != 0 {
		t.Errorf("文件名长度应为 0，实际 %d", got)
	}
}

// ServerGuid 在协商响应体的 8..24；取错偏移（28..44）会让客户端判
// "协商结果被篡改"，smbclient 表现就是 TREE_CONNECT 报 ACCESS_DENIED。
func TestNoteNegotiateReadsGuid(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	guid := make([]byte, 16)
	for i := range guid {
		guid[i] = byte(0x40 + i)
	}
	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:], 65)
	binary.LittleEndian.PutUint16(body[2:], 1)      // SecurityMode
	binary.LittleEndian.PutUint16(body[4:], 0x0302) // Dialect 3.0.2
	copy(body[8:24], guid)
	binary.LittleEndian.PutUint32(body[24:], 0x00000004) // Capabilities

	if !st.noteNegotiate(smb2Frame(smb2CmdNegotiate, 0, body)) {
		t.Fatal("应识别为协商响应")
	}
	if string(st.negoGuid[:]) != string(guid) {
		t.Errorf("ServerGuid 取错位置: %x", st.negoGuid)
	}
	if st.negoCaps != 0x00000004 {
		t.Errorf("Capabilities 应为 0x00000004，实际 0x%08x", st.negoCaps)
	}
	if st.negoDialect != 0x0302 {
		t.Errorf("Dialect 应为 0x0302，实际 0x%04x", st.negoDialect)
	}
}

// 短响应也必须能被换手认领。
//
// SET_INFO（删目录/改属性走这条）的响应体只有 2 字节，整帧 70 字节。早先
// claimWaiter 按"至少 nbHeaderLen+smb2HeaderLen+8 = 76 字节"卡长度，这种短帧
// 会被判成"不是我要等的响应"直接转给客户端，而等待换手的那边没人唤醒，只能
// 干等 10 秒超时——表现就是 Linux 客户端 rmdir 必然失败、每个目录卡 10 秒。
func TestClaimWaiterAcceptsShortResponse(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	ch := st.addWaiter(26)

	frame := smb2Frame(smb2CmdSetInfo, 26, []byte{0, 0})
	if len(frame) >= nbHeaderLen+smb2HeaderLen+8 {
		t.Fatalf("测试前提变了：这帧 %d 字节，已经不算短帧", len(frame))
	}
	got, ok := st.claimWaiter(frame)
	if !ok || got != ch {
		t.Fatal("2 字节的 SET_INFO 响应必须能认领到等待者")
	}
	// 认领即摘牌：同一个等待者不能再被第二条响应命中，否则一条子请求会被
	// 交给两处，复合响应就会串位。
	if _, ok := st.claimWaiter(frame); ok {
		t.Error("同一个等待者不能被认领两次")
	}
}
