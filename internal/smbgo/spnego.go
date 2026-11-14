package smbgo

// 本文件是 SPNEGO / DER 的最小实现，只够拼出 SMB 协商与会话建立需要的三个形状。
//
// 不放在 proxy.go 里，是因为那边带 //go:build linux：认证器（ntlmguest.go）也要
// 用这些函数，放在 linux-only 的文件里会让 Windows 构建直接编译失败。
//
// 三个形状：
//   NegTokenInit      —— 协商响应里告诉客户端"用 NTLM 谈"
//   NegTokenResp(继续) —— CHALLENGE，附 responseToken
//   accept-completed  —— 认证完成，只有 negState

// SPNEGO 结构必须带 GSS-API OID：
//
//	60 { 06 06 2B 06 01 05 05 02, A0 { 30 { ... } } }
//
// 少了最外层的 SPNEGO OID，或者把 NegTokenInit 写成 IMPLICIT 形式，Samba 与
// Windows 的解析器都会直接报 Invalid SPNEGO request / 拒绝握手。
var (
	ntlmOIDBytes   = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 1.3.6.1.4.1.311.2.2.10 NTLMSSP
	spnegoOIDBytes = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                         // 1.3.6.1.5.5.2 SPNEGO
)

// spnegoNegTokenInit 造一个只列 NTLMSSP 的 NegTokenInit，告诉客户端"用 NTLM 谈"。
//
// 结构照着 GSS-API InitialContextToken 来：
//
//	[APPLICATION 0] { OID(1.3.6.1.5.5.2) , [0] { SEQUENCE { [0] { SEQUENCE OF OID } } } }
func spnegoNegTokenInit() []byte {
	mechList := derWrap(0x30, ntlmOIDBytes) // SEQUENCE OF MechType
	mechTypes := derWrap(0xa0, mechList)    // [0] mechTypes
	init := derWrap(0x30, mechTypes)        // NegTokenInit ::= SEQUENCE
	body := append(append([]byte{}, spnegoOIDBytes...), derWrap(0xa0, init)...)
	return derWrap(0x60, body) // [APPLICATION 0] InitialContextToken
}

// spnegoNegTokenResp 造一个 NegTokenResp：negState 0=接受完成、1=继续。
// token 非空时作为 [2] responseToken 附上（CHALLENGE）。
func spnegoNegTokenResp(negState byte, token []byte) []byte {
	neg := []byte{0xa0, 0x03, 0x0a, 0x01, negState} // [0] negState
	mech := derWrap(0xa1, ntlmOIDBytes)             // [1] supportedMech
	inner := append(append(neg, mech...), derWrap(0xa2, derWrap(0x04, token))...)
	return derWrap(0xa1, derWrap(0x30, inner))
}

// spnegoAcceptCompleted 是"认证完成"这一包该带的内容：只有 negState=0。
//
//	A1 07 30 05 A0 03 0A 01 00
//
// 这是 samba 回给 Windows 的实际形状（抓包可证），也是 RFC 4178 最规矩的收尾。
// 多写 supportedMech 或塞一个空的 responseToken（04 00）会让 Windows 的 SPNEGO
// 解析器多绕一圈。
func spnegoAcceptCompleted() []byte {
	return []byte{0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00}
}

func derWrap(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch n := len(content); {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xFF:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}
