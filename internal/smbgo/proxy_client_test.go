//go:build linux || windows

package smbgo

// macOS 接入相关的回归测试。
//
// mac 的失败点很有代表性：TCP 通、协商通、认证通过，只在树连接上返回
// STATUS_BAD_NETWORK_NAME，客户端侧折成一句 "No such file or directory"。
// 两个原因都在这里锁住：
//   - 它把共享名统一转成大写再发，内层按字面比对就找不到共享；
//   - 它的首包是 SMB1 探测包、且不带 NativeOS，光看首包与 Windows 无法区分，
//     必须等 SMB2 NEGOTIATE 到了再修正一次识别结论。

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// smb2Req 拼一条**请求**方向的 SMB2 报文（带 NetBIOS 头，无 RESPONSE 标志）。
func smb2Req(cmd uint16, mid uint64, body []byte) []byte {
	msg := smb2Msg(cmd, mid, 0, body)
	out := make([]byte, nbHeaderLen)
	out = append(out, msg...)
	fixNBLength(out)
	return out
}

func treeConnectReq(mid uint64, path string) []byte {
	p := utf16LE(path)
	body := make([]byte, 8+len(p))
	binary.LittleEndian.PutUint16(body[0:], 9)
	binary.LittleEndian.PutUint16(body[4:], smb2HeaderLen+8) // PathOffset，从 SMB2 头起算
	binary.LittleEndian.PutUint16(body[6:], uint16(len(p)))
	copy(body[8:], p)
	return smb2Req(smb2CmdTreeConnect, mid, body)
}

func readTreePath(frame []byte) string {
	hdr := frame[nbHeaderLen:]
	body := hdr[smb2HeaderLen:]
	off := int(binary.LittleEndian.Uint16(body[4:])) - smb2HeaderLen
	n := int(binary.LittleEndian.Uint16(body[6:]))
	if off < 0 || off+n > len(body) {
		return ""
	}
	return string(utf16Decode(body[off : off+n]))
}

func utf16Decode(b []byte) []rune {
	out := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, rune(binary.LittleEndian.Uint16(b[i:])))
	}
	return out
}

func negotiateReq(dialects []uint16, caps uint32) []byte {
	body := make([]byte, 36+2*len(dialects))
	binary.LittleEndian.PutUint16(body[0:], 36)
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:], 0x0001) // signing enabled
	binary.LittleEndian.PutUint32(body[8:], caps)
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+2*i:], d)
	}
	return smb2Req(smb2CmdNegotiate, 1, body)
}

// macOS 发的是大写共享名，必须被纠正成真实名字，否则树连必然
// STATUS_BAD_NETWORK_NAME，而客户端只说"目录不存在"，根本看不出是大小写。
func TestFixTreePathNormalizesShareCase(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)

	req := treeConnectReq(4, `\\172.16.0.1\SHARE`)
	st.fixTreePath(req)
	if got := readTreePath(req); got != `\\172.16.0.1\share` {
		t.Fatalf("大写共享名没有被纠正，得到 %q", got)
	}
	// 长度不变是这套改法的前提：改了长度就得重算所有偏移与 NextCommand。
	if want := len(utf16LE(`\\172.16.0.1\SHARE`)); len(utf16LE(`\\172.16.0.1\SHARE`)) != want {
		t.Fatal("测试本身写错了")
	}

	// 已经正确的不应被动到任何一个字节
	ok := treeConnectReq(5, `\\172.16.0.1\share`)
	before := append([]byte(nil), ok...)
	st.fixTreePath(ok)
	if !bytes.Equal(before, ok) {
		t.Error("共享名大小写已正确时不该改写报文")
	}

	// IPC$ 与共享名无关，不能被换成 share
	ipc := treeConnectReq(6, `\\172.16.0.1\IPC$`)
	ipcBefore := append([]byte(nil), ipc...)
	st.fixTreePath(ipc)
	if !bytes.Equal(ipcBefore, ipc) {
		t.Error("IPC$ 不该被改写")
	}
}

// mac 的首包与 Windows 无法区分（都是只列方言的 SMB1 探测包、都不带
// NativeOS），所以首包会暂判成 Windows；随后真正的 SMB2 NEGOTIATE 一到，
// 必须把结论和兼容画像一起改过来——否则 mac 拿不到设备/扇区信息，
// 挂载仍然失败。
func TestRefineClientFixesMacMisjudgedAsWindows(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.client = ClientInfo{Kind: ClientWindows, Label: ClientWindows.Label()}
	st.comp = compatFor(ClientWindows)
	st.sawSMB1Probe = true // 真实 mac 就是先发 SMB1 探测、再补 SMB2 协商

	// macOS 11 的 SMBFS 实测：整套方言到 3.1.1，caps=0x7f（含 MULTI_CHANNEL
	// 与 ENCRYPTION）——这两个位恰好也是以前"判 Windows"的依据，所以必须
	// 靠"探测后又补协商"这个行为把它和 Windows 分开。
	req := negotiateReq([]uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x0000007f)
	st.refineClient(req)

	if st.client.Kind != ClientMacOS {
		t.Fatalf("应修正为 macOS，实际 %q（%s）", st.client.Kind, st.client.Evidence)
	}
	if !st.comp.fsProbe {
		t.Error("macOS 必须开 fsProbe，否则内核取根 inode 会失败")
	}
}

// Windows 自己的 SMB2 NEGOTIATE 不该把结论改坏。
func TestRefineClientKeepsWindows(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.client = ClientInfo{Kind: ClientWindows, Label: ClientWindows.Label()}
	st.comp = compatFor(ClientWindows)

	// Windows 带 MULTI_CHANNEL(0x08) | PERSISTENT_HANDLES(0x10) | ENCRYPTION(0x40)
	req := negotiateReq([]uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x00000058)
	st.refineClient(req)

	if st.client.Kind != ClientWindows {
		t.Fatalf("Windows 不该被改判成 %q", st.client.Kind)
	}
	if st.comp.fsProbe {
		t.Error("Windows 的兼容画像不该被打开 fsProbe")
	}
}

// 人工指定（client_hints）优先级最高，二次识别不能覆盖它。
func TestRefineClientRespectsHint(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.client = ClientInfo{Kind: ClientLinuxCIFS, Label: ClientLinuxCIFS.Label(), Hinted: true}
	st.comp = compatFor(ClientLinuxCIFS)

	st.refineClient(negotiateReq([]uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x00000004))
	if st.client.Kind != ClientLinuxCIFS {
		t.Fatalf("client_hints 指定的类型被覆盖成了 %q", st.client.Kind)
	}
}
