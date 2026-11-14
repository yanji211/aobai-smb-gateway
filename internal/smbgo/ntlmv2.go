package smbgo

// 本文件是 NTLMv2 的三个关键推导，服务端认证（ntlmguest.go）与代理层
// 重算签名（proxy.go）必须用同一份实现，否则两边算出的会话密钥不一致，
// 表现为客户端报 STATUS_INVALID_SIGNATURE(0xc000a000)。
//
// 为什么需要真实口令：Windows 11 24H2 起，SMB 客户端默认强制签名，而
// 「来宾会话」没有会话密钥、根本没法签名，微软的说明是「即使放开来宾回退，
// 签名也会让它失败」。所以要么让客户端关掉签名要求（削弱整机安全策略），
// 要么服务端提供一个可认证的账号——后者才是能长期用的做法。
//
// NTLMv2 的验算只需要口令，不需要口令原文参与协议（NTLM 只用到它的哈希）：
//
//	NTOWFv1       = MD4(UTF-16LE(password))              —— 常说的 NT 哈希
//	ResponseKeyNT = HMAC_MD5(NTOWFv1, UTF-16LE(大写用户名 + 域))   —— NTLMv2 真正用的密钥
//	NTProofStr    = HMAC_MD5(ResponseKeyNT, ServerChallenge || blob)
//	SessionBaseKey= HMAC_MD5(ResponseKeyNT, NTProofStr)
//	SessionKey    = SessionBaseKey            （未协商 KEY_EXCH 时）
//
// 第二行最容易漏：直接拿 NT 哈希去算 HMAC 会得到一个永远对不上的证明，
// 现象是客户端报「指定的网络密码不正确」，而口令明明是错的——本机就栽在这。

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/md4"
)

// ntHashOf 计算口令的 NT 哈希（NTOWFv1）。
func ntHashOf(password string) []byte {
	h := md4.New()
	h.Write(utf16LE(password))
	return h.Sum(nil)
}

// responseKeyNT 计算 NTLMv2 的 ResponseKeyNT。
//
// 用户名必须按协议大写，域用客户端在 AUTHENTICATE 里报的那个（空就是空，
// 不能替换成 WORKGROUP——换了就算不出同一个密钥）。
func responseKeyNT(ntHash []byte, user, domain string) []byte {
	return hmacMD5(ntHash, utf16LE(strings.ToUpper(user)+domain))
}

// hmacMD5 是 HMAC-MD5，NTLM 全篇都是它。
func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// ntHashFromHex 解析配置里的 nt_hash（32 个十六进制字符）。
func ntHashFromHex(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 32 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, false
	}
	return b, true
}

// NTHashHex 返回口令的 NT 哈希（大写十六进制）。
// 供 `fsgw smb nt-hash <口令>` 打印，便于配置里只放哈希、不留明文。
func NTHashHex(password string) string {
	return strings.ToUpper(hex.EncodeToString(ntHashOf(password)))
}

// ParseNTHash 是 ntHashFromHex 的导出包装，供上层把配置里的十六进制转成字节。
func ParseNTHash(s string) ([]byte, bool) { return ntHashFromHex(s) }

// NTHashBytes 是 ntHashOf 的导出包装，供上层从口令直接算 NTOWFv1。
func NTHashBytes(password string) []byte { return ntHashOf(password) }

// ntProof 计算 HMAC_MD5(ResponseKeyNT, ServerChallenge || blob)。
func ntProof(key, serverChallenge, blob []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(serverChallenge)
	m.Write(blob)
	return m.Sum(nil)
}

// sessionBaseKey 计算 HMAC_MD5(ResponseKeyNT, NTProofStr)。
func sessionBaseKey(key, proof []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(proof)
	return m.Sum(nil)
}

// flagNegotiateKeyExch 是 NTLM 的 NEGOTIATE_KEY_EXCH。我们的 CHALLENGE flags
// （serverSupportedFlags）里带着这一位，所以客户端一定会送 EncryptedRandomSessionKey，
// 真正的会话密钥必须再用 RC4 解一次。漏了这步的直接后果是：口令明明正确，
// 客户端却报 "Bad SMB2 signature"（它用解出来的密钥验签，我们用了另一把）。
const flagNegotiateKeyExch = 0x40000000

// sessionKey 按 MS-NLMP 3.1.5.1.2 算出会话密钥（也就是 SMB 签名的种子）。
func sessionKey(responseKey, proof, encryptedRandom []byte, flags uint32) []byte {
	base := sessionBaseKey(responseKey, proof)
	if flags&flagNegotiateKeyExch != 0 && len(encryptedRandom) == 16 {
		return rc4Crypt(base, encryptedRandom)
	}
	return base
}

// rc4Crypt 是 RC4（NTLM 的密钥交换用它，加密与解密是同一个操作）。
func rc4Crypt(key, data []byte) []byte {
	var s [256]byte
	for i := range s {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) & 0xFF
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(data))
	i, j := 0, 0
	for k := range data {
		i = (i + 1) & 0xFF
		j = (j + int(s[i])) & 0xFF
		s[i], s[j] = s[j], s[i]
		out[k] = data[k] ^ s[(int(s[i])+int(s[j]))&0xFF]
	}
	return out
}
