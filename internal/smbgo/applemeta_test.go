package smbgo

import (
	"encoding/binary"
	"testing"
)

func TestIsAppleMetaName(t *testing.T) {
	yes := []string{
		".DS_Store", ".ds_store", "._foo.txt", "._.hidden",
		".Trashes", ".Spotlight-V100", ".fseventsd", ".TemporaryItems",
		".apdisk", ".VolumeIcon.icns", ".DocumentRevisions-V100",
		`.Trashes/501/x`, `dir\.DS_Store`,
	}
	for _, n := range yes {
		if !IsAppleMetaName(n) {
			t.Errorf("%q 应判为 Apple 元数据", n)
		}
	}
	no := []string{
		"", "a.txt", "DS_Store", ".gitignore", "._", "foo._bar.mp4",
		"照片.DS_Store.jpg", ".hidden", "Trashes",
	}
	for _, n := range no {
		if IsAppleMetaName(n) {
			t.Errorf("%q 不该判为 Apple 元数据", n)
		}
	}
}

func TestFilterAppleMetaKeepsOrder(t *testing.T) {
	entries := []dirEnt{
		{name: utf16leBytes("b.txt")},
		{name: utf16leBytes(".DS_Store")},
		{name: utf16leBytes("._b.txt")},
		{name: utf16leBytes("a.txt")},
	}
	out, dropped := filterAppleMeta(entries)
	if dropped != 2 || len(out) != 2 {
		t.Fatalf("过滤结果不对：dropped=%d len=%d", dropped, len(out))
	}
	if got := utf16le(out[0].name); got != "b.txt" {
		t.Errorf("顺序被破坏，第一条是 %q", got)
	}
	if got := utf16le(out[1].name); got != "a.txt" {
		t.Errorf("顺序被破坏，第二条是 %q", got)
	}
}

// dirRespFrame 造一条"内层枚举成功"的 QUERY_DIRECTORY 响应，目录项按
// FileDirectoryInformation(0x01) 布局编码（名字从第 64 字节开始）：
//
//	NextEntryOffset(4) … FileNameLength(60,4) … Name
func dirRespFrame(msgID uint64, names []string) []byte {
	var buf []byte
	for _, n := range names {
		var e [64]byte
		binary.LittleEndian.PutUint32(e[60:], uint32(len(n)*2))
		buf = append(buf, e[:]...)
		buf = append(buf, utf16leBytes(n)...)
		for len(buf)%8 != 0 {
			buf = append(buf, 0)
		}
	}
	// 补 NextEntryOffset：指向下一条起点，最后一条留 0。
	for pos := 0; pos+64 <= len(buf); {
		next := 0
		nameLen := int(binary.LittleEndian.Uint32(buf[pos+60:]))
		total := 64 + nameLen
		for total%8 != 0 {
			total++
		}
		if pos+total < len(buf) {
			next = total
		}
		binary.LittleEndian.PutUint32(buf[pos:], uint32(next))
		if next == 0 {
			break
		}
		pos += next
	}

	out := make([]byte, nbHeaderLen+smb2HeaderLen+8)
	out[nbHeaderLen] = 0xFE
	copy(out[nbHeaderLen+1:], "SMB")
	binary.LittleEndian.PutUint16(out[nbHeaderLen+12:], smb2CmdQueryDir)
	binary.LittleEndian.PutUint64(out[nbHeaderLen+24:], msgID)
	body := out[nbHeaderLen+smb2HeaderLen:]
	binary.LittleEndian.PutUint16(body[0:], 9)
	binary.LittleEndian.PutUint16(body[2:], smb2HeaderLen+8) // OutputBufferOffset
	binary.LittleEndian.PutUint32(body[4:], uint32(len(buf)))
	out = append(out, buf...)
	fixNBLength(out)
	return out
}

// dirNamesOf 把 fixQueryDirectory 的产出解回名字列表。
func dirNamesOf(t *testing.T, frame []byte) []string {
	t.Helper()
	if binary.LittleEndian.Uint32(frame[nbHeaderLen+8:]) != 0 {
		return nil
	}
	body := frame[nbHeaderLen+smb2HeaderLen:]
	off := int(binary.LittleEndian.Uint16(body[2:])) - smb2HeaderLen
	n := int(binary.LittleEndian.Uint32(body[4:]))
	raw := body[off : off+n]
	var names []string
	for pos := 0; pos+64 <= len(raw); {
		e := raw[pos:]
		nameLen := int(binary.LittleEndian.Uint32(e[60:]))
		names = append(names, utf16le(e[64:64+nameLen]))
		next := int(binary.LittleEndian.Uint32(e[0:]))
		if next <= 0 {
			break
		}
		pos += next
	}
	return names
}

// 这条是"Z: 盘根目录里冒出 .DS_Store"的那个问题：mac 写进来的影子文件不该
// 出现在任何客户端的枚举结果里，而且过滤后分页游标必须按过滤后的条数走。
func TestFixQueryDirectoryHidesAppleMeta(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.appleMeta = "hide"
	st.client.Kind = ClientWindows
	st.qdir[11] = qdReq{class: 0x01, outLen: 65536, key: "k"}

	out, ok := fixQueryDirectory(dirRespFrame(11, []string{"b.txt", ".DS_Store", "._b.txt", "a.txt"}), st)
	if !ok {
		t.Fatal("fixQueryDirectory 未接管这条响应")
	}
	names := dirNamesOf(t, out)
	if len(names) != 2 || names[0] != "b.txt" || names[1] != "a.txt" {
		t.Fatalf("过滤结果不对：%v", names)
	}
	// 游标按过滤后的条数推进，否则下一次枚举会从"看不见的位置"开始。
	if got := st.cursors["k"]; got != 2 {
		t.Fatalf("游标应为 2，实际 %d", got)
	}
}

// 默认策略的关键一半：mac 自己必须仍然看得见自己的影子文件。否则它找不到
// .DS_Store 就每次进目录重建一遍，写入放大的同时还存不住窗口布局。
func TestFixQueryDirectoryKeepsAppleMetaForMac(t *testing.T) {
	for _, mode := range []string{"", "hide"} {
		st := newConnState("/tmp", "share", nil, nil)
		st.appleMeta = mode
		st.client.Kind = ClientMacOS
		st.qdir[13] = qdReq{class: 0x01, outLen: 65536, key: "k3"}
		out, ok := fixQueryDirectory(dirRespFrame(13, []string{".DS_Store", "a.txt"}), st)
		if !ok {
			t.Fatalf("mode=%q: fixQueryDirectory 未接管这条响应", mode)
		}
		if names := dirNamesOf(t, out); len(names) != 2 {
			t.Fatalf("mode=%q: mac 的枚举被过滤了，实际 %v", mode, names)
		}
	}
}

// "all" 是显式要求连 mac 一起藏。
func TestFixQueryDirectoryHidesAppleMetaForAll(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.appleMeta = "all"
	st.client.Kind = ClientMacOS
	st.qdir[14] = qdReq{class: 0x01, outLen: 65536, key: "k4"}
	out, ok := fixQueryDirectory(dirRespFrame(14, []string{".DS_Store", "a.txt"}), st)
	if !ok {
		t.Fatal("fixQueryDirectory 未接管这条响应")
	}
	if names := dirNamesOf(t, out); len(names) != 1 || names[0] != "a.txt" {
		t.Fatalf("all 模式下应只剩 a.txt，实际 %v", names)
	}
}

func TestFixQueryDirectoryKeepsAppleMetaWhenOff(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.appleMeta = "off"
	st.qdir[12] = qdReq{class: 0x01, outLen: 65536, key: "k2"}

	out, ok := fixQueryDirectory(dirRespFrame(12, []string{".DS_Store", "a.txt"}), st)
	if !ok {
		t.Fatal("fixQueryDirectory 未接管这条响应")
	}
	if names := dirNamesOf(t, out); len(names) != 2 {
		t.Fatalf("关掉过滤后不该动条目，实际 %v", names)
	}
}
