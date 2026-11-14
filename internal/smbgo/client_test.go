package smbgo

// 接入端识别的回归测试。
//
// 这里守的是两类事：
//  1. 识别的判据不能悄悄失效——认错了，兼容补丁就不开，Linux 直接挂不上，
//     而且现象看起来像"服务端坏了"，很难反推到识别这一步；
//  2. 人工指定必须压过指纹——它是出问题时的唯一逃生门。

import (
	"encoding/binary"
	"testing"
)

// buildNegotiate 造一个 SMB2 NEGOTIATE 请求（不含 NetBIOS 头）。
func buildNegotiate(dialects []uint16, caps uint32, secMode uint16, guid [16]byte) []byte {
	body := make([]byte, 36+2*len(dialects))
	binary.LittleEndian.PutUint16(body[0:], 36)
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:], secMode)
	binary.LittleEndian.PutUint32(body[8:], caps)
	copy(body[12:28], guid[:])
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+2*i:], d)
	}

	hdr := make([]byte, smb2HeaderLen)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:], smb2HeaderLen)
	binary.LittleEndian.PutUint16(hdr[12:], smb2CmdNegotiate)
	binary.LittleEndian.PutUint16(hdr[14:], 1)
	return append(hdr, body...)
}

func TestClassifyNegotiate(t *testing.T) {
	cases := []struct {
		name     string
		dialects []uint16
		caps     uint32
		probe    bool // 这条连接是否先发过 SMB1 探测包
		want     ClientKind
	}{
		// 内核 CIFS 的招牌：mount.cifs 只报一条方言（vers= 翻成一条）。
		{"内核CIFS-单方言", []uint16{0x0300}, 0, false, ClientLinuxCIFS},
		{"内核CIFS-单方言21", []uint16{0x0210}, 0, false, ClientLinuxCIFS},
		{"内核CIFS-单方言202", []uint16{0x0202}, 0, false, ClientLinuxCIFS},

		// macOS：整套方言、有 3.1.1、没有加密位，也没有 Windows 那两位。
		{"macOS", []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x05, false, ClientMacOS},

		// Samba 用户态：带 ENCRYPTION(0x40)，没有多通道位。
		{"smbclient", []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x45, false, ClientLinuxSamba},
		{"gvfs", []uint16{0x0210, 0x0300, 0x0302, 0x0311}, 0x41, false, ClientLinuxSamba},

		// Windows：带 MULTI_CHANNEL(0x08)。它也带 ENCRYPTION，
		// 所以必须先按多通道位判，否则会被当成 Samba。
		{"Windows", []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x4D, false, ClientWindows},
		{"Windows仅多通道", []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x08, false, ClientWindows},

		// 只支持 SMB2 的老设备（电视、老 NAS）。
		{"老设备", []uint16{0x0202, 0x0210}, 0, false, ClientOther},

		// 先发过 SMB1 探测、又补发 SMB2 协商：Windows 不会这么做，所以
		// 即便带着 MULTI_CHANNEL 也不能再按 Windows 算。mac 实测就是这套
		// 组合：整套方言 + caps=0x7f（含 MULTI_CHANNEL 与 ENCRYPTION）。
		{"macOS-探测后补协商", []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x7f, true, ClientMacOS},
	}
	for _, c := range cases {
		ci := &ClientInfo{Dialects: nil}
		got := classifyNegotiate(c.dialects, c.caps, ci, c.probe)
		if got != c.want {
			t.Errorf("%s: 期望 %s，实际 %s（证据 %v）", c.name, c.want, got, ci.Evidence)
		}
		if len(ci.Evidence) == 0 {
			t.Errorf("%s: 必须留下判定依据，否则出问题时无从解释", c.name)
		}
	}
}

func TestSniffSMB2(t *testing.T) {
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(i + 1)
	}
	frame := buildNegotiate([]uint16{0x0300}, 0x00000004, 0x0001, guid)

	ci, ok := sniffSMB2(frame)
	if !ok {
		t.Fatal("应该能认出这是 SMB2 协商请求")
	}
	if ci.Kind != ClientLinuxCIFS {
		t.Errorf("单方言应判为内核 CIFS，实际 %s", ci.Kind)
	}
	if len(ci.Dialects) != 1 || ci.Dialects[0] != "3.0" {
		t.Errorf("方言解析错了: %v", ci.Dialects)
	}
	if ci.Caps != 0x00000004 {
		t.Errorf("能力位解析错了: 0x%08x", ci.Caps)
	}
	if ci.Label != "Linux（内核 CIFS）" {
		t.Errorf("展示名不对: %q", ci.Label)
	}

	// 响应不该被当成请求识别。
	resp := append([]byte(nil), frame...)
	binary.LittleEndian.PutUint32(resp[16:], smb2FlagResponse)
	if _, ok := sniffSMB2(resp); ok {
		t.Error("响应帧不该被当请求识别")
	}
}

// SMB1 的自报串是 ASCII 与 UTF-16LE 两种写法，必须都能认出来。
func TestSniffSMB1(t *testing.T) {
	mk := func(payload []byte) []byte {
		out := make([]byte, nbHeaderLen, nbHeaderLen+64+len(payload))
		out = append(out, 0xFF, 'S', 'M', 'B', 0x72)
		out = append(out, make([]byte, 27)...) // 头部其余字段
		out = append(out, 0, 0, 0)             // WordCount / ByteCount
		out = append(out, payload...)
		return out
	}

	cases := []struct {
		payload []byte
		want    ClientKind
	}{
		{[]byte("Windows 10.0\x00Windows 10.0\x00"), ClientWindows},
		{utf16ASCII("Windows 10.0"), ClientWindows},
		{[]byte("Samba 4.22.11\x00Samba 4.22.11\x00"), ClientLinuxSamba},
		{utf16ASCII("Mac OS X 13.5"), ClientMacOS},
		{utf16ASCII("Samba 4.19.0"), ClientLinuxSamba},
	}
	for _, c := range cases {
		ci := sniffSMB1(mk(c.payload))
		if ci == nil {
			t.Errorf("报文体 %q 应该能认出来", c.payload)
			continue
		}
		if ci.Kind != c.want {
			t.Errorf("报文体 %q: 期望 %s，实际 %s", c.payload, c.want, ci.Kind)
		}
	}

	if ci := sniffSMB1(mk([]byte("nonsense"))); ci != nil {
		t.Error("认不出来就该返回 nil，交给后面的指纹，而不是猜一个")
	}
}

func TestMatchHint(t *testing.T) {
	hints := []ClientHint{
		{IP: "192.0.2.50", Kind: ClientMacOS},
		{IP: "192.0.2.", Kind: ClientLinuxCIFS},
		{IP: "", Kind: ClientWindows},           // 空 IP 忽略
		{IP: "10.0.0.1", Kind: ClientKind("x")}, // 拼错的类型忽略
	}

	if k, ok := matchHint("192.0.2.50:49152", hints); !ok || k != ClientMacOS {
		t.Errorf("精确匹配失败: %v %v", k, ok)
	}
	if k, ok := matchHint("192.0.2.77:1234", hints); !ok || k != ClientLinuxCIFS {
		t.Errorf("前缀匹配失败: %v %v", k, ok)
	}
	if _, ok := matchHint("172.16.0.9:1234", hints); ok {
		t.Error("没有命中的地址不该被指定")
	}
	if _, ok := matchHint("10.0.0.1:1234", hints); ok {
		t.Error("kind 写错的提示应该被忽略")
	}
}

// Windows 走原路：不开 fsProbe，避免动到已经验证过的代码路径。
func TestCompatFor(t *testing.T) {
	for _, k := range []ClientKind{ClientLinuxCIFS, ClientMacOS, ClientLinuxSamba, ClientUnknown} {
		if c := compatFor(k); !c.fsProbe {
			t.Errorf("%s 需要补文件系统信息类，否则内核挂载会失败", k)
		}
	}
	if c := compatFor(ClientWindows); c.fsProbe {
		t.Error("Windows 不查这两类信息，不该给它开")
	}
	if !compatFor(ClientWindows).validateNego {
		t.Error("VALIDATE_NEGOTIATE_INFO 的响应重建对所有人都要开——内层那份本来就是错的")
	}
}
