package smbgo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
)

// tvNegotiate 是 2026-11-10 从小米电视抓到的那一条 SMB_COM_NEGOTIATE 原包
// （含 4 字节 NetBIOS 头，51 字节）。它只列一个方言：NT LM 0.12。
const tvNegotiate = "0000002fff534d4272000000001803c800000000000000000000000000004aa600000100000c00024e54204c4d20302e313200"

func TestSMB1DialectsFromTV(t *testing.T) {
	raw, err := hex.DecodeString(tvNegotiate)
	if err != nil {
		t.Fatal(err)
	}
	got := smb1Dialects(raw)
	if len(got) != 1 || got[0] != "NT LM 0.12" {
		t.Fatalf("方言表解析错误：%v", got)
	}
	if !smb1Only(got) {
		t.Fatal("只列 NT LM 0.12 应判为纯 SMB1 客户端")
	}
}

func TestSMB1Only(t *testing.T) {
	cases := []struct {
		dialects []string
		want     bool
	}{
		{[]string{"NT LM 0.12"}, true},
		{[]string{"NT LM 0.12", "SMB 2.002", "SMB 2.???"}, false},
		{[]string{"SMB 2.002"}, false},
		{nil, false}, // 解析失败：保持"一律当 Windows 改写"的老行为
		{[]string{}, false},
	}
	for _, c := range cases {
		if got := smb1Only(c.dialects); got != c.want {
			t.Errorf("smb1Only(%v) = %v，应为 %v", c.dialects, got, c.want)
		}
	}
}

// 非协商命令、或结构不对的包一律返回 nil，调用方据此不误判。
func TestSMB1DialectsRejectsOther(t *testing.T) {
	// 把 cmd 从 0x72 改成 0x73（TREE_CONNECT），其余不变。
	raw, _ := hex.DecodeString(tvNegotiate)
	raw[nbHeaderLen+4] = 0x73
	if got := smb1Dialects(raw); got != nil {
		t.Fatalf("非 NEGOTIATE 不该解析出方言：%v", got)
	}
	// 截断包
	if got := smb1Dialects(raw[:nbHeaderLen+10]); got != nil {
		t.Fatalf("截断包不该解析出方言：%v", got)
	}
	// SMB2 包
	if got := smb1Dialects(smb2NegotiateRequest(nil)); got != nil {
		t.Fatalf("SMB2 包不该解析出 SMB1 方言：%v", got)
	}
}

// relayToSMB1 必须做到三件事：把已经读出来的首帧原样交给后端、两个方向都能
// 转发、客户端断开后整条链路收尾。这条链路是小米电视这类 SMB1-only 设备的
// 唯一通路，出错的表现是"电视一直转圈"。
func TestRelayToSMB1PassesFirstFrameAndBothDirections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	first := []byte{0x00, 0x00, 0x00, 0x2f, 0xff, 'S', 'M', 'B'}
	backendGot := make(chan []byte, 2)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(first))
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		backendGot <- buf
		// 后端 → 客户端
		_, _ = c.Write([]byte("PONG"))
		// 客户端 → 后端
		more := make([]byte, 4)
		if _, err := io.ReadFull(c, more); err == nil {
			backendGot <- more
		}
	}()

	cli, cliPeer := net.Pipe() // cli 交给 relay；cliPeer 扮演客户端
	defer cliPeer.Close()
	done := make(chan error, 1)
	go func() { done <- relayToSMB1(cli, first, ln.Addr().String()) }()

	if got := <-backendGot; !bytes.Equal(got, first) {
		t.Fatalf("后端收到的首帧不对：%x", got)
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(cliPeer, pong); err != nil || string(pong) != "PONG" {
		t.Fatalf("后端→客户端方向不通：%q %v", pong, err)
	}
	if _, err := cliPeer.Write([]byte("MORE")); err != nil {
		t.Fatalf("客户端→后端方向写入失败：%v", err)
	}
	if got := <-backendGot; string(got) != "MORE" {
		t.Fatalf("客户端→后端方向内容不对：%q", got)
	}

	_ = cliPeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("客户端关闭后 relayToSMB1 没有收尾")
	}
}

func TestRelayToSMB1FailsFastWhenBackendDown(t *testing.T) {
	// 拿一个刚关掉的端口：DialTimeout 必须快速失败，不能卡住客户端。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	start := time.Now()
	if err := relayToSMB1(a, []byte{1, 2, 3, 4}, addr); err == nil {
		t.Fatal("后端不可用时应当报错")
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("失败得太慢：%v", d)
	}
}

// 105（第二台小米电视）的 SMB1 探测包里只声明到 SMB 2.002。服务端如果回
// 3.0.2，它收到一个自己没声明过的方言就直接丢弃连接——实测就是这个现象：
// 服务端回了 DialectRevision=0x0302、status=0，之后电视一个业务字节都不发。
// 所以换算函数必须把"它能接受的上限"压到 2.0.2。
func TestSMB2DialectsFromSMB1TV(t *testing.T) {
	// 原包（192.0.2.105，2026-11-10 21:14）里解出的方言表。
	got := smb2DialectsFromSMB1([]string{"NT LM 0.12", "SMB 2.???", "SMB 2.002"})
	if len(got) != 1 || got[0] != 0x0202 {
		t.Fatalf("只到 2.002 的客户端应只得 [0x0202]，实际 %#x", got)
	}
}

func TestSMB2DialectsFromSMB1Mixed(t *testing.T) {
	got := smb2DialectsFromSMB1([]string{"NT LM 0.12", "SMB 2.002", "SMB 2.1"})
	if len(got) != 2 || got[0] != 0x0210 || got[1] != 0x0202 {
		t.Fatalf("应得 [0x0210 0x0202]（从高到低），实际 %#x", got)
	}
	// 纯 SMB1 方言不该混进 SMB2 列表
	if got := smb2DialectsFromSMB1([]string{"NT LM 0.12", "NT LANMAN 1.0"}); len(got) != 0 {
		t.Fatalf("纯 SMB1 客户端应得空列表，实际 %#x", got)
	}
}

// 合成的协商请求必须只声明传进去的方言，且 DialectCount / NB 长度自洽。
func TestSMB2NegotiateRequestHonoursDialects(t *testing.T) {
	frame := smb2NegotiateRequest([]uint16{0x0202})
	if got := binary.BigEndian.Uint16(frame[0:2]); got != 0 {
		t.Fatalf("NB 长度高字节异常：%#x", got)
	}
	if n := binary.BigEndian.Uint32(frame[0:4]) & 0xFFFFFF; int(n) != len(frame)-4 {
		t.Fatalf("NB 长度字段 %d 与实际 %d 不符", n, len(frame)-4)
	}
	body := frame[nbHeaderLen+64:]
	if c := binary.LittleEndian.Uint16(body[2:]); c != 1 {
		t.Fatalf("DialectCount 应为 1，实际 %d", c)
	}
	if d := binary.LittleEndian.Uint16(body[36:]); d != 0x0202 {
		t.Fatalf("第一个方言应为 0x0202，实际 %#x", d)
	}
	// 空列表退化成最保守的一档，绝不能变成 3.x
	if body := smb2NegotiateRequest(nil)[nbHeaderLen+64:]; binary.LittleEndian.Uint16(body[36:]) != 0x0202 {
		t.Fatal("空方言列表应退化为 0x0202")
	}
}

// 签名算法必须跟着方言走：2.0.2 / 2.1 是 HMAC-SHA256，3.0 以上才是 AES-CMAC。
// 一律 CMAC 的后果是 2.0.2 客户端在认证后的第一个签名响应上判签名无效、
// 直接断开（服务端只看到"登录成功"，之后毫无动静）——小米电视就是这样。
func TestSignAlgoFollowsDialect(t *testing.T) {
	cases := []struct {
		dialect uint16
		want    signing.Algorithm
	}{
		{0x0202, signing.AlgoHMACSHA256},
		{0x0210, signing.AlgoHMACSHA256},
		{0x0300, signing.AlgoAESCMAC},
		{0x0302, signing.AlgoAESCMAC},
		{0x0311, signing.AlgoAESCMAC},
	}
	for _, c := range cases {
		st := &connState{negoDialect: c.dialect}
		if got := st.signAlgo(); got != c.want {
			t.Fatalf("方言 %#x 应选算法 %#x，实际 %#x", c.dialect, c.want, got)
		}
	}
}

// resignChain 用传进来的算法签名：同一条消息、同一把密钥，HMAC 与 CMAC 必须
// 给出不同结果（否则说明 algo 参数没生效，只是"看着编译过了"）。
func TestResignChainHonoursAlgorithm(t *testing.T) {
	mk := func() []byte {
		frame := make([]byte, nbHeaderLen+smb2HeaderLen)
		frame[nbHeaderLen] = 0xFE
		copy(frame[nbHeaderLen+1:], []byte("SMB"))
		binary.LittleEndian.PutUint16(frame[nbHeaderLen+4:], 64) // StructureSize
		binary.LittleEndian.PutUint16(frame[nbHeaderLen+12:], 1) // NEGOTIATE
		binary.LittleEndian.PutUint32(frame[nbHeaderLen+16:], smb2FlagSigned)
		return frame
	}
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	hmacFrame, cmacFrame := mk(), mk()
	resignChain(hmacFrame, key, signing.AlgoHMACSHA256)
	resignChain(cmacFrame, key, signing.AlgoAESCMAC)

	sigHMAC := hmacFrame[nbHeaderLen+smb2HeaderLen-16:]
	sigCMAC := cmacFrame[nbHeaderLen+smb2HeaderLen-16:]
	if bytes.Equal(sigHMAC, sigCMAC) {
		t.Fatal("HMAC 与 CMAC 签出同样的结果，说明算法参数没生效")
	}
	if !bytes.Equal(sigHMAC, hmacFrame[nbHeaderLen+smb2HeaderLen-16:]) {
		t.Fatal("签名区没有落在 SMB2 头尾")
	}
}

// TestSignIsIdempotentOnSignedFrame 是"重签已签名报文"的回归测试。
//
// 代理层改完响应体后调 resignChain，此时签名域里还留着内层算好的旧签名。
// edge case：HMAC 分支曾经没清这一域，等于把旧签名也拿去算摘要，客户端
// 一律判 STATUS_INVALID_SIGNATURE——SMB 2.0.2/2.1 全废、只有 3.x 能用。
// 判据：同一份报文连签两次，第二次必须得到同样的结果（而不是雪崩）。
func TestSignIsIdempotentOnSignedFrame(t *testing.T) {
	frame := make([]byte, nbHeaderLen+smb2HeaderLen+32)
	frame[nbHeaderLen] = 0xFE
	copy(frame[nbHeaderLen+1:], []byte("SMB"))
	binary.LittleEndian.PutUint16(frame[nbHeaderLen+4:], 64)
	binary.LittleEndian.PutUint16(frame[nbHeaderLen+12:], 1)
	binary.LittleEndian.PutUint32(frame[nbHeaderLen+16:], smb2FlagSigned)
	// 模拟"上一手已经签过"：先塞一段非零垃圾，等价于旧签名。
	for i := nbHeaderLen + smb2HeaderLen - 16; i < nbHeaderLen+smb2HeaderLen; i++ {
		frame[i] = 0xA5
	}
	key := []byte("0123456789abcdef")

	for _, tc := range []struct {
		name string
		algo signing.Algorithm
	}{
		{"HMAC-SHA256", signing.AlgoHMACSHA256}, // SMB 2.0.2 / 2.1
		{"AES-CMAC", signing.AlgoAESCMAC},       // SMB 3.x
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := append([]byte(nil), frame...)
			if err := signing.Sign(first, key, tc.algo); err != nil {
				t.Fatalf("首次签名失败: %v", err)
			}
			second := append([]byte(nil), first...)
			if err := signing.Sign(second, key, tc.algo); err != nil {
				t.Fatalf("二次签名失败: %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("重签结果不一致：旧签名被算进了摘要（HMAC 漏清零会导致客户端判签名无效）\nfirst =%x\nsecond=%x", first[len(first)-16:], second[len(second)-16:])
			}
		})
	}
}
