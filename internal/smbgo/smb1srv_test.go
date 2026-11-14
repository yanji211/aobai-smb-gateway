package smbgo

// 内置 SMB1 通道（smb1srv.go）的报文级单测。
//
// 这里覆盖的都是"偏移写错就整片功能不可用、但编译和类型检查都发现不了"的地方：
// Trans2 响应的参数区/数据区偏移、目录条目的前缀长度、NT_CREATE 名字前的对齐
// pad、管道名规范化、TRANSACTION 的 SetupWords 与 Name 位置。每一条都对应
// 2026-11-11 联调时真实踩到的问题，回归时靠它们兜住。

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

// newTestSess 造一个只够拼响应用的会话。
func newTestSess(unicode bool) *smb1Session {
	return &smb1Session{
		unicode: unicode,
		tid:     1,
		uid:     1,
		files:   map[uint16]*smb1OpenFile{},
		finds:   map[uint16]*smb1Find{},
		share:   "share",
	}
}

// smb1Req 造一条带 32 字节 SMB 头的请求骨架，cmd 为命令字。
func smb1Req(cmd byte, unicode bool) []byte {
	req := make([]byte, smb1HeaderLen+1)
	req[0], req[1], req[2], req[3] = 0xFF, 'S', 'M', 'B'
	req[4] = cmd
	if unicode {
		binary.LittleEndian.PutUint16(req[10:], smb1Flags2Unicode)
	}
	return req
}

func TestReplyTransPlacesAreasAtSambaOffsets(t *testing.T) {
	s := newTestSess(true)
	req := smb1Req(smb1CmdTransaction2, true)
	params := make([]byte, 10) // FIND_FIRST2 的参数区正好 10 字节
	data := []byte("payload")

	out := s.replyTrans(req, smb1StatusSuccess, params, data)

	if out[32] != 10 {
		t.Fatalf("WordCount = %d，TRANSACTION2 响应固定 10", out[32])
	}
	w := out[33:]
	paramOff := int(binary.LittleEndian.Uint16(w[8:]))
	dataOff := int(binary.LittleEndian.Uint16(w[14:]))
	if paramOff != 56 {
		t.Errorf("参数区偏移 = %d，应为 56（samba 实测值）", paramOff)
	}
	if dataOff != 68 {
		t.Errorf("数据区偏移 = %d，应为 68（10 字节参数区后补到 4 字节对齐）", dataOff)
	}
	if got := out[paramOff : paramOff+len(params)]; len(got) != len(params) {
		t.Fatalf("参数区越界")
	}
	if got := string(out[dataOff : dataOff+len(data)]); got != "payload" {
		t.Errorf("数据区内容 = %q", got)
	}
	// 数据区没有参数区时（管道 RPC 就是这种），仍要落在 4 字节对齐的 68 之前
	out2 := s.replyTrans(req, smb1StatusSuccess, nil, data)
	w2 := out2[33:]
	if off := int(binary.LittleEndian.Uint16(w2[14:])); off%4 != 0 {
		t.Errorf("空参数区时数据区偏移 = %d，未按 4 字节对齐", off)
	}
}

func TestEncodeFindEntryPrefixPerLevel(t *testing.T) {
	e := smb1FindEntry{
		name:  "中文.txt",
		size:  7,
		mtime: time.Date(2026, 11, 11, 9, 48, 0, 0, time.UTC),
		attr:  0x0080,
	}
	nameLen := len(utf16.Encode([]rune(e.name))) * 2

	cases := []struct {
		level uint16
		base  int
	}{
		{infoFindDir, 64},     // 0x0101 DIRECTORY_INFO（老电视只发这个）
		{infoFindFullDir, 68}, // 0x0102 FULL_DIRECTORY_INFO
		{infoFindBothDir, 94}, // 0x0104 BOTH_DIRECTORY_INFO：带 24 字节短名区
		{infoFindIDFull, 76},  // 0x0105 ID_FULL_DIRECTORY
		{infoFindIDBoth, 102}, // 0x0106 ID_BOTH_DIRECTORY
	}
	for _, c := range cases {
		rec := encodeFindEntry(e, c.level)
		want := c.base + nameLen
		if len(rec) != want {
			t.Errorf("level 0x%04x 条目长度 = %d，应为 %d（前缀 %d）", c.level, len(rec), want, c.base)
			continue
		}
		// 名字从 base 起，且 NameLength 字段（偏移 60）等于字节数
		if got := binary.LittleEndian.Uint32(rec[60:]); int(got) != nameLen {
			t.Errorf("level 0x%04x NameLength = %d，应为 %d", c.level, got, nameLen)
		}
		got := make([]rune, 0, 8)
		for i := c.base; i+1 < len(rec); i += 2 {
			got = append(got, rune(binary.LittleEndian.Uint16(rec[i:])))
		}
		if string(got) != e.name {
			t.Errorf("level 0x%04x 名字起点落错：%q", c.level, string(got))
		}
	}

	// 0x0103 (NAMES_INFO) 只有名字，前缀 12 字节
	if rec := encodeFindEntry(e, infoFindNames); len(rec) != 12+nameLen {
		t.Errorf("level 0x0103 条目长度 = %d，应为 %d", len(rec), 12+nameLen)
	}
	// 未知级别不返回条目，让客户端自己降级
	if rec := encodeFindEntry(e, 0x0199); rec != nil {
		t.Errorf("未知级别应返回 nil，却得到 %d 字节", len(rec))
	}
}

// FILE_ALL_INFO(0x0107) 的 EndOfFile 在 48：写到 40 会让客户端认为文件是 0 字节，
// 于是只建链不下载（表现为"文件能列出、点开是空的"）。
func TestQueryFileInfoAllInfoEOF(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, make([]byte, 1234), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	s := newTestSess(true)
	req := smb1Req(smb1CmdTransaction2, true)
	out := s.replyWithInfo(req, 0x0107, st)

	w := out[33:]
	dataOff := int(binary.LittleEndian.Uint16(w[14:]))
	dataLen := int(binary.LittleEndian.Uint16(w[2:]))
	if dataLen != 68 {
		t.Fatalf("FILE_ALL_INFO 长度 = %d，应为 68", dataLen)
	}
	if got := binary.LittleEndian.Uint64(out[dataOff+48:]); got != 1234 {
		t.Errorf("EndOfFile = %d，应在数据区偏移 48", got)
	}
}

// NT_CREATE_ANDX 响应的 FID 必须落在参数区偏移 5（p[5:7]），文件大小（EndOfFile）
// 落在偏移 55，FileAttributes 落在 43。响应里 OplockLevel(偏移 4)之后没有 Reserved
// 字节，FID 直接从 5 开始——与请求区不同。之前误放成偏移 6/56/44（整体 +1），
// 客户端按 p[5:7] 读到 [0x00,0x01]=256 而不是真实 FID，后续 QUERY_FILE_INFO /
// READ_ANDX 查不到句柄 → INVALID_PARAMETER / 断链。这条测试锁死正确偏移。
func TestNtCreateReplyFIDAndEOFOffset(t *testing.T) {
	s := newTestSess(true)
	req := smb1Req(smb1CmdNTCreateAndX, true)

	out := s.ntCreateReply(req, 42, 1234, false, time.Now())
	if out[32] != 34 {
		t.Fatalf("WordCount = %d，NT_CREATE_ANDX 响应固定 34", out[32])
	}
	w := out[33:]
	gotFID := binary.LittleEndian.Uint16(w[5:])
	if gotFID != 42 {
		t.Errorf("FID = %d，应落在参数区偏移 5 且等于 42", gotFID)
	}
	eof := binary.LittleEndian.Uint64(w[55:])
	if eof != 1234 {
		t.Errorf("EndOfFile = %d，应落在参数区偏移 55 且等于 1234", eof)
	}
	attr := binary.LittleEndian.Uint32(w[43:])
	if attr != 0x0080 {
		t.Errorf("FileAttributes = 0x%08x，应为 0x00000080（普通文件）", attr)
	}

	// 目录：FileAttributes 应为 0x0010，且 Directory 标志位置 1。
	outDir := s.ntCreateReply(req, 7, 0, true, time.Now())
	wDir := outDir[33:]
	if attr := binary.LittleEndian.Uint32(wDir[43:]); attr != 0x0010 {
		t.Errorf("目录的 FileAttributes = 0x%08x，应为 0x00000010", attr)
	}
	if wDir[67] != 1 {
		t.Errorf("目录响应的 Directory 标志位应为 1")
	}
	if gotFID := binary.LittleEndian.Uint16(wDir[5:]); gotFID != 7 {
		t.Errorf("目录 FID = %d，应等于 7", gotFID)
	}
}

func TestNameAfterAlign(t *testing.T) {
	// NT_CREATE 的字节区可能多一个对齐 pad，UTF-16 名字因此整体错位成"尀猀甀戀"
	raw := append([]byte{0x00}, []byte{0x5c, 0x00, 0x73, 0x00, 0x75, 0x00, 0x62, 0x00, 0x00, 0x00}...)
	got := decodeUTF16Strict(nameAfterAlign(raw, true))
	if strings.TrimRight(got, "\x00") != `\sub` {
		t.Fatalf("去 pad 后 = %q，应为 \\sub", got)
	}
	// 没有 pad 时原样返回
	plain := []byte{0x5c, 0x00, 0x73, 0x00}
	if string(nameAfterAlign(plain, true)) != string(plain) {
		t.Error("没有对齐 pad 时不应裁掉首字节")
	}
	// ASCII 名字不做处理
	if string(nameAfterAlign([]byte(`\sub`), false)) != `\sub` {
		t.Error("ASCII 模式不该改字节")
	}
}

func TestPipeKey(t *testing.T) {
	cases := map[string]string{
		"srvsvc\x00":       "srvsvc",
		`\PIPE\srvsvc`:     "srvsvc",
		`\srvsvc`:          "srvsvc",
		"SRVSVC":           "srvsvc",
		"\\PIPE\\LANMAN\x00": "lanman",
	}
	for in, want := range cases {
		if got := pipeKey(in); got != want {
			t.Errorf("pipeKey(%q) = %q，应为 %q", in, got, want)
		}
	}
}

// transReq 拼一条 SMB_COM_TRANSACTION 请求。
//
// 报文顺序：32 字节头 + WordCount + 14 个固定字 + SetupWords + ByteCount
// + 字节区（可选 1 pad + Name + pad + 参数区 + pad + 数据区）。
func transReq(setup []uint16, name string, params, data []byte, unicode bool) []byte {
	req := smb1Req(smb1CmdTransaction, unicode)
	params = append([]byte(nil), params...)
	data = append([]byte(nil), data...)

	// 字节区起点 = 头(32) + wc(1) + 14 字(28) + setup + ByteCount(2)
	byteStart := smb1HeaderLen + 1 + 28 + len(setup)*2 + 2
	var body []byte
	if unicode {
		body = append(body, 0) // 对齐 pad
		u := utf16.Encode([]rune(name))
		for _, r := range u {
			body = append(body, byte(r), byte(r>>8))
		}
		body = append(body, 0, 0)
	} else {
		body = append(body, []byte(name)...)
		body = append(body, 0)
	}
	paramOffset := byteStart + len(body)
	if paramOffset%4 != 0 {
		pad := 4 - paramOffset%4
		body = append(body, make([]byte, pad)...)
		paramOffset += pad
	}
	body = append(body, params...)
	dataOffset := byteStart + len(body)
	if dataOffset%4 != 0 {
		pad := 4 - dataOffset%4
		body = append(body, make([]byte, pad)...)
		dataOffset += pad
	}
	body = append(body, data...)

	w := make([]byte, 28)
	binary.LittleEndian.PutUint16(w[0:], uint16(len(params)))   // TotalParameterCount
	binary.LittleEndian.PutUint16(w[2:], uint16(len(data)))     // TotalDataCount
	binary.LittleEndian.PutUint16(w[18:], uint16(len(params)))  // ParameterCount
	binary.LittleEndian.PutUint16(w[20:], uint16(paramOffset))  // ParameterOffset
	binary.LittleEndian.PutUint16(w[22:], uint16(len(data)))    // DataCount
	binary.LittleEndian.PutUint16(w[24:], uint16(dataOffset))   // DataOffset
	w[26] = byte(len(setup))                                    // SetupCount

	req[32] = byte(14 + len(setup))
	req = append(req, w...)
	for _, sw := range setup {
		req = binary.LittleEndian.AppendUint16(req, sw)
	}
	req = binary.LittleEndian.AppendUint16(req, uint16(len(body)))
	return append(req, body...)
}

// 管道收发：SetupWords = {TRANS_NMPIPE, FID}，Name 只是 "\PIPE\"。
// 早先按"Name 里含 SRVSVC"分流，管道事务全部落到 NOT_SUPPORTED，
// smbclient 报 rpc_pipe_bind ... NT_STATUS_CONNECTION_DISCONNECTED。
func TestTransactionPipeRouteBySetupWords(t *testing.T) {
	s := newTestSess(true)
	s.files[1] = &smb1OpenFile{pipe: "srvsvc"}

	bind := make([]byte, 116)
	bind[0], bind[1], bind[2], bind[3] = 5, 0, 0x0B, 0x03
	binary.LittleEndian.PutUint32(bind[12:], 0xAABBCCDD) // callID

	req := transReq([]uint16{transNMPipe, 1}, `\PIPE\`, nil, bind, true)
	out := s.onTransaction(req)

	if out == nil {
		t.Fatal("管道事务不该返回 nil")
	}
	w := out[33:]
	if got := binary.LittleEndian.Uint32(out[5:]); got != 0 {
		t.Errorf("NTSTATUS = 0x%08x，应为成功", got)
	}
	dataOff := int(binary.LittleEndian.Uint16(w[14:]))
	dataLen := int(binary.LittleEndian.Uint16(w[2:]))
	if dataLen != 56 {
		t.Fatalf("bind 应答长度 = %d，应为 56", dataLen)
	}
	if out[dataOff+2] != 0x0C {
		t.Errorf("回包不是 bind_ack（type = 0x%02x）", out[dataOff+2])
	}
	if got := binary.LittleEndian.Uint32(out[dataOff+12:]); got != 0xAABBCCDD {
		t.Errorf("callID 没回填：0x%08x", got)
	}
}

// RAP（\PIPE\LANMAN）里的 Name 是 UTF-16，且前面有 1 个对齐 pad。
// 从 28 字节处直接找 NUL 会得到 "&"，于是列共享永远走不到 RAP 分支。
func TestTransactionRAPShareEnumNameParse(t *testing.T) {
	s := newTestSess(true)
	// RAP 请求参数区：opcode = 0（NetShareEnum）
	req := transReq(nil, `\PIPE\LANMAN`, []byte{0, 0}, nil, true)
	out := s.onTransaction(req)

	w := out[33:]
	if got := binary.LittleEndian.Uint32(out[5:]); got != 0 {
		t.Fatalf("NTSTATUS = 0x%08x，应为成功", got)
	}
	dataOff := int(binary.LittleEndian.Uint16(w[14:]))
	dataLen := int(binary.LittleEndian.Uint16(w[2:]))
	if dataLen != 2+2*20 {
		t.Fatalf("RAP 数据区 = %d 字节，应为 42（2 字节计数 + 2 条 20 字节项）", dataLen)
	}
	if n := binary.LittleEndian.Uint16(out[dataOff:]); n != 2 {
		t.Errorf("共享数 = %d，应为 2", n)
	}
	// 第一条的共享名
	name := string(out[dataOff+2 : dataOff+2+13])
	name = name[:len("share")]
	if name != "share" {
		t.Errorf("第一条共享名 = %q", name)
	}
}

// 未知 Name、又没有 TRANS_NMPIPE setup 的事务要干净地回 NOT_SUPPORTED。
func TestTransactionUnknownIsNotSupported(t *testing.T) {
	s := newTestSess(false)
	req := transReq(nil, `\PIPE\WINREG`, nil, []byte(hex.EncodeToString(nil)), false)
	out := s.onTransaction(req)
	if got := binary.LittleEndian.Uint32(out[5:]); got != smb1StatusNotSupported {
		t.Errorf("NTSTATUS = 0x%08x，应为 NOT_SUPPORTED", got)
	}
}

// 小米电视等老客户端用 SMB_COM_OPEN_ANDX（0x2D）打开文件。之前没实现，电视一发
// 就掉进 default 回 NOT_SUPPORTED 并断链（broken pipe）。这条锁住：OPEN_ANDX 能
// 打开文件、回正确的 FID（参数区偏移 4），且 FID 登记进 files 表供后续 READ_ANDX。
func TestOpenAndXOpensFileAndReturnsFID(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "movie.mp4")
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestSess(true)
	s.treeRoot = dir
	s.root = dir
	s.nextFID = 1 // serveSMB1 里从 1 起，避免 FID=0

	req := openAndXReq("movie.mp4", true)
	out := s.onOpenAndX(req)
	if out == nil {
		t.Fatal("onOpenAndX 返回 nil")
	}
	if got := binary.LittleEndian.Uint32(out[5:]); got != 0 {
		t.Fatalf("NTSTATUS = 0x%08x，应为成功", got)
	}
	if out[32] != 15 {
		t.Fatalf("WordCount = %d，OPEN_ANDX 响应固定 15", out[32])
	}
	w := out[33:]
	fid := binary.LittleEndian.Uint16(w[4:]) // FID @ offset 4
	if fid == 0 {
		t.Fatalf("FID = 0，应是非零有效句柄")
	}
	if got := binary.LittleEndian.Uint32(w[12:]); got != 4096 { // FileSize @ offset 12
		t.Errorf("FileSize = %d，应等于 4096", got)
	}
	if _, ok := s.files[fid]; !ok {
		t.Errorf("FID %d 没登记进 files 表，后续 READ_ANDX 会查不到句柄", fid)
	}
	s.closeAll() // 关掉 onOpenAndX 打开的文件，避免占用临时文件
}

// 拼一条 SMB_COM_OPEN_ANDX 请求：WordCount=15、30 字节参数区、ByteCount 数据区
// 里放 null 结尾的文件名（Unicode 时 UTF-16LE）。
func openAndXReq(name string, unicode bool) []byte {
	req := smb1Req(smb1CmdOpenAndX, unicode)
	req[32] = 15 // WordCount
	req = append(req, make([]byte, 30)...)
	var data []byte
	if unicode {
		u := utf16.Encode([]rune(name))
		for _, r := range u {
			data = binary.LittleEndian.AppendUint16(data, r)
		}
		data = append(data, 0, 0) // null 终止
	} else {
		data = append([]byte(name), 0)
	}
	req = binary.LittleEndian.AppendUint16(req, uint16(len(data))) // ByteCount
	return append(req, data...)
}

// QUERY_PATH_INFO 对"子目录/文件"路径之前会报 INVALID_PARAMETER——根因是数据区
// 文件名解析在外层没做 Unicode 对齐 pad 与去 null。这条直接喂子目录路径，确认能
// 正常回 FILE_ALL_INFO 且 EndOfFile 正确。
func TestQueryPathInfoSubdirPath(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "desk88")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "1024.html"), []byte("<html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestSess(true)
	s.treeRoot = dir
	s.root = dir

	params := make([]byte, 6)
	binary.LittleEndian.PutUint16(params[0:], 0x0107) // FILE_ALL_INFO（passthrough）

	name := "desk88/1024.html"
	u := utf16.Encode([]rune(name))
	data := make([]byte, len(u)*2+2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(data[i*2:], r)
	}
	data[len(data)-2], data[len(data)-1] = 0, 0

	req := smb1Req(smb1CmdTransaction2, true)
	out := s.onQueryPathInfo(req, params, data)
	if out == nil {
		t.Fatal("onQueryPathInfo 返回 nil")
	}
	if got := binary.LittleEndian.Uint32(out[5:]); got != 0 {
		t.Fatalf("NTSTATUS = 0x%08x，应为成功（之前子目录会报 INVALID_PARAMETER）", got)
	}
	w := out[33:]
	dataOff := int(binary.LittleEndian.Uint16(w[14:]))
	dataLen := int(binary.LittleEndian.Uint16(w[2:]))
	if dataLen != 68 {
		t.Fatalf("FILE_ALL_INFO 长度 = %d，应为 68", dataLen)
	}
	if eof := binary.LittleEndian.Uint64(out[dataOff+48:]); eof != 6 {
		t.Errorf("EndOfFile = %d，应等于 6", eof)
	}
}

// 真实小米电视把 QUERY_PATH_INFO 的文件名塞进 Parameter 区（Level+Reserved 之后），
// Data 区为空（实测 paramCnt=60、dataCnt=0）。之前只读 Data 区得到空名 → 永远返回
// 共享根目录的信息 → 电视拿到错误大小后断链。这条锁住"文件名在 Param 区"的解析。
func TestQueryPathInfoNameInParamArea(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "desk88")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "1024.html"), []byte("<html>xyz"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestSess(true)
	s.treeRoot = dir
	s.root = dir

	// params: Level(0x0107) + Reserved(2) + UTF-16LE 文件名 + null；data 区为空
	name := "desk88/1024.html"
	u := utf16.Encode([]rune(name))
	params := make([]byte, 4+len(u)*2+2)
	binary.LittleEndian.PutUint16(params[0:], 0x0107)
	for i, r := range u {
		binary.LittleEndian.PutUint16(params[4+i*2:], r)
	}
	params[len(params)-2], params[len(params)-1] = 0, 0

	req := smb1Req(smb1CmdTransaction2, true)
	out := s.onQueryPathInfo(req, params, nil) // data 区为空，模拟电视
	if out == nil {
		t.Fatal("onQueryPathInfo 返回 nil")
	}
	if got := binary.LittleEndian.Uint32(out[5:]); got != 0 {
		t.Fatalf("NTSTATUS = 0x%08x，应为成功（之前会按空名返回根目录信息，电视断链）", got)
	}
	w := out[33:]
	dataOff := int(binary.LittleEndian.Uint16(w[14:]))
	dataLen := int(binary.LittleEndian.Uint16(w[2:]))
	if dataLen != 68 {
		t.Fatalf("FILE_ALL_INFO 长度 = %d，应为 68", dataLen)
	}
	if eof := binary.LittleEndian.Uint64(out[dataOff+48:]); eof != 9 {
		t.Errorf("EndOfFile = %d，应为 9（<html>xyz 的字节数）", eof)
	}
}

// 抓包实测（smbclient -m NT1 / 小米电视）：QUERY_PATH_INFO 的参数区头部是
// Level(2)+Reserved(4)=6 字节，即 params[4:6]=[0x00,0x00]，文件名从 params[6]
// 开始。之前固定按 4 取，读到两个 0x00 → 空名 → 返回根目录信息 → 电视断链。
// 这条锁住"6 字节头部"这条真实布局。
func TestQueryPathInfoNameAtOffset6(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "desk88")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "aigc-human.txt"), []byte("hello6"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestSess(true)
	s.treeRoot = dir
	s.root = dir

	// params: Level(0x0107) + Reserved(4 字节 0) + UTF-16LE "\desk88\aigc-human.txt" + null
	name := `\desk88\aigc-human.txt`
	u := utf16.Encode([]rune(name))
	params := make([]byte, 6+len(u)*2+2)
	binary.LittleEndian.PutUint16(params[0:], 0x0107)
	// params[2:6] 保持全 0（Reserved 4 字节）
	for i, r := range u {
		binary.LittleEndian.PutUint16(params[6+i*2:], r)
	}
	params[len(params)-2], params[len(params)-1] = 0, 0

	req := smb1Req(smb1CmdTransaction2, true)
	out := s.onQueryPathInfo(req, params, nil) // data 区为空，文件名在 Param 区偏移 6
	if out == nil {
		t.Fatal("onQueryPathInfo 返回 nil")
	}
	if got := binary.LittleEndian.Uint32(out[5:]); got != 0 {
		t.Fatalf("NTSTATUS = 0x%08x，应为成功（6 字节头部布局）", got)
	}
	w := out[33:]
	dataOff := int(binary.LittleEndian.Uint16(w[14:]))
	if eof := binary.LittleEndian.Uint64(out[dataOff+48:]); eof != 6 {
		t.Errorf("EndOfFile = %d，应为 6（hello6 的字节数）", eof)
	}
}
