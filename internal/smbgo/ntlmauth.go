package smbgo

// 本文件是服务端的 NTLMSSP 实现：默认免口令放行（来宾），
// 配置了账号时对该账号做真正的 NTLMv2 验算。
//
// 为什么不用库自带的 ntlmssp.NewServer：它生成的 CHALLENGE_MESSAGE 与主流实现
// 差异太大——TargetInfo 只有一条 NbComputerName、Version 全零、flags 里还塞了
// 客户端没协商过的 SEAL 位。Linux 的 smbclient 能忍，Windows 的 msv1_0 不忍，
// 表现为收到 challenge 后直接 RST（资源管理器报系统错误 53）。
//
// 这里按 Windows 服务端的实际报文（见 deploy 时的对照抓包）重建 CHALLENGE：
//   - TargetInfo 依次给 NbDomainName / NbComputerName / DnsDomainName /
//     DnsComputerName / MsvAvFlags / MsvAvTimestamp，与 Windows 一致；
//   - Version 写 10.0.19041；
//   - flags 只回客户端请求过的位。
//
// 口令策略是「账号表 + 来宾兜底」：
//   - 没配置任何账号时维持纯来宾：第二轮 AUTHENTICATE 一律接受，身份记为客户端
//     报上来的用户名（缺省 guest）。电视/手机/老系统的匿名访问走这条路。
//   - 配置了账号表时，客户端报的用户名在表里就必须验过口令才放行；验不过明确回
//     STATUS_LOGON_FAILURE，而不是悄悄降级成来宾。降级成来宾会让 Win11 给出
//     「策略阻止未经验证的来宾访问」乃至 0x80004005 这种看不懂的错，
//     把「口令错了 / 没登记」伪装成「策略问题」。
//   - 配置了账号表时，报的是表里没有的用户名（例如 Windows 默认拿当前登录用户
//     来试）同样明确拒绝。这样资源管理器会正常弹出「输入网络凭据」，
//     而不是拿到一个注定被它自己否决的来宾会话。
//   - 只有匿名类的用户名（空 / guest / anonymous 等，见 guestNames）在配了账号表
//     之后仍走来宾，保证电视、iOS 文件、老播放器不被这次改动砸掉。

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
)

// serverSupportedFlags 是服务端愿意接受的 NTLM 能力位：
// UNICODE | REQUEST_TARGET | SIGN | ALWAYS_SIGN | NTLM | EXT_SESS_SEC |
// TARGET_INFO | VERSION | 128 | KEY_EXCH | 56。
//
// 这里每一位都有来历，删任何一位都会踢掉一类客户端：
//   - TARGET_INFO 少了，客户端报 "Server did not provide 'target information'"；
//   - EXT_SESS_SEC(0x00080000) 少了，Win11 24H2+ 会在收到 CHALLENGE 后直接
//     丢掉挑战、以新 SessionId 重发 NEGOTIATE，连发数次后放弃（net use 报
//     系统错误 67「找不到网络名」）。原因：Win11 24H2 起默认强制 SMB 签名，
//     而签名的会话密钥要靠 NTLM 的扩展会话安全派生；挑战里没有 ESS，客户端
//     既算不出可签名的密钥，也不肯退回弱会话安全，只能拒绝。
//   - SIGN / ALWAYS_SIGN 同理：客户端协商时就带上了（实测 Win11 的
//     NEGOTIATE flags = 0xe2088297），服务端不回等于否认自己支持签名。
//   - 56 位只影响极老客户端的降级；128 位同时给出时按 128 走。
//
// 注意：NTLM 的 SIGN 位与 SMB2 报文签名是两套东西。SMB2 怎么签由协商响应的
// SecurityMode 和双方从 SessionKey 派生的密钥决定；但 24H2 的客户端会先看
// NTLM 层有没有 ESS 才决定是否继续，所以这一位必须给。
const serverSupportedFlags = uint32(0xE2888215)

// msAV* 是 MS-NLMP 2.2.2.1 的 AV_PAIR 标识。
const (
	msAVNbComputer  = 0x0001
	msAVNbDomain    = 0x0002
	msAVDNSComputer = 0x0003
	msAVDNSDomain   = 0x0004
	msAVFlags       = 0x0006
	msAVTimestamp   = 0x0007
	msAVEOL         = 0x0000
)

type ntlmAuth struct {
	stage     int
	flags     uint32
	challenge [8]byte
	user      string
	domain    string
	log       *slog.Logger

	// spnego 记录客户端这一轮用的是哪种封装。必须原样回敬：
	// Windows 大部分时候发 SPNEGO NegTokenInit（首字节 0x60），但偶尔——
	// 典型是"同一条连接上再建一个会话"时——会发裸 NTLMSSP（首字节 'N'）。
	// 对裸包回 SPNEGO，客户端按裸格式解析直接失败，表现为收到挑战后不发
	// AUTHENTICATE、几毫秒内连开数个会话然后放弃，上层看到的是错误 87/58。
	spnego bool

	// accounts 是允许登录的客户端账号表：小写用户名 → NTOWFv1。
	// 只存哈希不存口令原文——NTLM 验算本来也只需要哈希。
	// 空表 = 纯来宾模式，与改动前行为完全一致。
	accounts map[string][]byte
}

// replyToken 按客户端送来的封装形状包装我们自己的输出。
// 裸 NTLM 会话没有收尾 token 这一说，返回 nil（空安全缓冲区）才是对的。
func (a *ntlmAuth) replyToken(challenge []byte) []byte {
	if a.spnego {
		return spnegoNegTokenResp(1, challenge)
	}
	return challenge
}

// doneToken 是认证完成时的输出：SPNEGO 要给一个 accept-completed，
// 裸 NTLM 什么都不给。
func (a *ntlmAuth) doneToken() []byte {
	if a.spnego {
		return spnegoAcceptCompleted()
	}
	return nil
}

// guestNames 是"配了账号表之后仍然按来宾放行"的用户名。
//
// 为什么要留这一层：配账号表是为了让 Windows 11 能走"真账号+真签名"，
// 但电视、iOS 文件、老播放器这类设备只会发匿名请求（用户名空着，或者
// 固定写 guest/anonymous）。把它们一并拒掉等于为了修 Win11 砸掉电视。
//
// 反过来，凡是报了具体用户名的（典型是 Windows 资源管理器拿当前登录用户
// 来试），一律要求它出现在账号表里——否则会拿到一个"来宾会话"，
// 而 Win11 24H2 会直接否决来宾会话，最后抛出毫无信息的 0x80004005。
// 明确回 STATUS_LOGON_FAILURE 反而能让资源管理器正常弹出"输入网络凭据"。
var guestNames = map[string]bool{
	"":          true,
	"guest":     true,
	"anonymous": true,
	"nobody":    true,
	"public":    true,
	"ftp":       true,
}

func (a *ntlmAuth) Accept(_ context.Context, in []byte) (auth.AcceptResult, error) {
	// 首字节 0x60 是 ASN.1 的 GSS-API 应用标签，即 SPNEGO；
	// 裸 NTLMSSP 以 'N' 开头。按请求的形状决定回什么形状，别自作主张统一。
	//
	// 只在第一轮判定并保持：后面几轮的 token 可能很短甚至为空（SPNEGO 的
	// accept-completed 轮就只有 negState，裸 NTLM 的收尾干脆没有 token），
	// 每轮重算会把形状判反，于是给 SPNEGO 客户端回了空 token，
	// 它会报 "SPNEGO login failed: 参数错误"。
	if a.stage == 0 {
		a.spnego = len(in) > 0 && in[0] == 0x60
	}

	raw, err := ntlmssp.UnwrapSPNEGOToken(in)
	if a.stage == 0 {
		if err != nil {
			return auth.AcceptResult{}, err
		}
		return a.handleNegotiate(raw)
	}
	if a.stage == 1 && err == nil {
		return a.handleAuthenticate(raw)
	}
	// 走到这里有两种情况，都必须回成功而不是报错：
	//  1) 会话已建立后，客户端补发 SPNEGO 完成确认（内容只有 negState，没有 NTLMSSP），
	//     解包会失败——这不是错误，是正常收尾；Samba / Windows 都可能发这一轮。
	//  2) 重复的 SESSION_SETUP。
	a.stage = 3
	return auth.AcceptResult{
		Identity:    a.identity(),
		OutputToken: a.doneToken(),
	}, nil
}

func (a *ntlmAuth) identity() *auth.Identity {
	user, domain := a.user, a.domain
	if user == "" {
		user = "guest"
	}
	return &auth.Identity{Username: user, Domain: domain}
}

// handleNegotiate 回一个标准形状的 CHALLENGE，并记下客户端请求的能力位。
func (a *ntlmAuth) handleNegotiate(raw []byte) (auth.AcceptResult, error) {
	flags := serverSupportedFlags
	if nm, err := ntlmssp.ParseNegotiateMessage(raw); err == nil {
		if f := nm.Flags & serverSupportedFlags; f != 0 {
			flags = f
		}
	}
	// UNICODE / NTLM / EXT_SESS_SEC / TARGET_INFO 是必须的，客户端没请求也要给：
	//   - 少了 TARGET_INFO，客户端会认为服务端没发 target information 而拒绝 NTLMv2；
	//   - 少了 EXT_SESS_SEC，客户端（尤其 Win11 24H2+）会拒绝在挑战上继续认证。
	flags |= 0x00000001 | 0x00000200 | 0x00080000 | 0x00800000

	if _, err := rand.Read(a.challenge[:]); err != nil {
		return auth.AcceptResult{}, err
	}
	a.flags = flags
	a.stage = 1

	challenge := buildChallenge(flags, a.challenge)
	tok := a.replyToken(challenge) // accept-incomplete，后附 CHALLENGE
	return auth.AcceptResult{OutputToken: tok}, nil
}

// handleAuthenticate 校验口令（配了账号且用户名对得上时），否则按来宾放行。
func (a *ntlmAuth) handleAuthenticate(raw []byte) (auth.AcceptResult, error) {
	am, err := ntlmssp.ParseAuthenticateMessage(raw)
	if err != nil {
		// 解不出 AUTHENTICATE 说明这一轮不是认证：可能是客户端补发的 SPNEGO
		// 收尾确认，也可能是重复的 SESSION_SETUP。按已建立处理。
		a.stage = 3
		return auth.AcceptResult{Identity: a.identity(), OutputToken: a.doneToken()}, nil
	}
	if u := ntlmssp.UTF16String(am.UserName); u != "" {
		a.user = u
	}
	a.domain = ntlmssp.UTF16String(am.DomainName)

	if h, ok := a.lookupNTHash(a.user); ok {
		if len(am.NtChallengeResponse) < 16 {
			// 空响应 = 匿名登录。既然客户端报了账号却没带响应，就是口令没填。
			return auth.AcceptResult{}, auth.ErrLogonFailed
		}
		key := responseKeyNT(h, a.user, a.domain)
		proof := ntProof(key, a.challenge[:], am.NtChallengeResponse[16:])
		if !hmac.Equal(proof, am.NtChallengeResponse[:16]) {
			if a.log != nil {
				a.log.Warn("SMB 口令校验失败", "user", a.user, "domain", a.domain)
			}
			return auth.AcceptResult{}, auth.ErrLogonFailed
		}
		sessKey := sessionKey(key, proof, am.EncryptedSessionKey, am.Flags)
		a.stage = 2
		if a.log != nil {
			a.log.Info("SMB 会话已通过账号口令认证", "user", a.user, "domain", a.domain)
		}
		// SessionKey 非空 → 库会用它派生签名密钥，响应就会被签名。
		// Win11 24H2+ 要求的就是这个：既有口令，又能签名。
		return auth.AcceptResult{
			Identity:    &auth.Identity{Username: a.user, Domain: a.domain},
			SessionKey:  sessKey,
			OutputToken: a.doneToken(),
		}, nil
	}

	// 走到这里说明：账号表里没有这个用户名。配了账号表就不能再悄悄放行——
	// 悄悄放行换来的是一个"来宾会话"，而 Win11 24H2 会否决来宾、报 0x80004005
	// 这种看不懂的错。明确拒绝反而对：资源管理器会弹出"输入网络凭据"，
	// 用户填上登记过的账号就能进。
	if !a.allowGuest() {
		if a.log != nil {
			a.log.Warn("SMB 拒绝了未登记的客户端账号", "user", a.user, "domain", a.domain)
		}
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	a.stage = 2
	if a.log != nil {
		a.log.Info("SMB 会话按来宾放行", "user", a.identity().Username, "domain", a.domain)
	}
	return auth.AcceptResult{
		Identity:    a.identity(),
		OutputToken: a.doneToken(),
	}, nil
}

// lookupNTHash 在账号表里按用户名取 NTOWFv1（不区分大小写）。
func (a *ntlmAuth) lookupNTHash(user string) ([]byte, bool) {
	if len(a.accounts) == 0 {
		return nil, false
	}
	h, ok := a.accounts[strings.ToLower(strings.TrimSpace(user))]
	return h, ok && len(h) > 0
}

// allowGuest 判断这次登录能不能按来宾放行。
//
//   - 没配任何账号表 → 纯来宾模式，全部放行（电视/手机/老系统的默认路径）；
//   - 配了账号表 → 只有匿名类用户名放行，其余必须验口令。
func (a *ntlmAuth) allowGuest() bool {
	if len(a.accounts) == 0 {
		return true
	}
	return guestNames[strings.ToLower(strings.TrimSpace(a.user))]
}

// mustVerify 判断这次登录是不是"必须验口令"的那一种：客户端报的用户名
// 正好在账号表里（不区分大小写；域不看——局域网里客户端常填计算机名或 WORKGROUP）。
func (a *ntlmAuth) mustVerify() bool {
	_, ok := a.lookupNTHash(a.user)
	return ok
}

// buildChallenge 按 Windows 服务端的布局拼 CHALLENGE_MESSAGE。
func buildChallenge(flags uint32, nonce [8]byte) []byte {
	host, dns := hostNames()
	domain := "WORKGROUP"

	target := utf16LE(host)
	info := targetInfo(domain, host, dns)

	const fixedLen = 56 // 8 签名 + 4 类型 + 8 目标名 + 4 标志 + 8 随机数 + 8 保留 + 8 目标信息 + 8 版本
	out := make([]byte, fixedLen+len(target)+len(info))
	copy(out[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(out[8:12], 2) // CHALLENGE

	binary.LittleEndian.PutUint16(out[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(out[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(out[16:20], fixedLen)

	binary.LittleEndian.PutUint32(out[20:24], flags)
	copy(out[24:32], nonce[:])

	binary.LittleEndian.PutUint16(out[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(out[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(out[44:48], uint32(fixedLen+len(target)))

	// Version：10.0 build 19041 rev 15（不写会让部分客户端当成非法版本）
	copy(out[48:56], []byte{0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f})

	copy(out[fixedLen:], target)
	copy(out[fixedLen+len(target):], info)
	return out
}

func targetInfo(domain, host, dns string) []byte {
	var out []byte
	put := func(id uint16, val []byte) {
		out = binary.LittleEndian.AppendUint16(out, id)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(val)))
		out = append(out, val...)
	}
	put(msAVNbDomain, utf16LE(domain))
	put(msAVNbComputer, utf16LE(host))
	put(msAVDNSDomain, utf16LE(domain))
	put(msAVDNSComputer, utf16LE(dns))
	// MsvAvFlags=2：与真实 Windows 服务端一致，语义是"本机是域成员环境"。
	// 不能写 1——MS-NLMP 里 bit0 的语义是"本条消息携带 MIC"，而 CHALLENGE 根本
	// 没有 MIC 字段；Win11 24H2+（NTLM 加固）会把它当成畸形报文拒掉。
	put(msAVFlags, binary.LittleEndian.AppendUint32(nil, 2))
	put(msAVTimestamp, binary.LittleEndian.AppendUint64(nil, filetime(time.Now())))
	put(msAVEOL, nil)
	return out
}

// hostNames 返回 NetBIOS 名（≤15 字符、大写）与完整主机名。
func hostNames() (string, string) {
	dns, err := os.Hostname()
	if err != nil || dns == "" {
		dns = "FSGW"
	}
	nb := strings.ToUpper(dns)
	if i := strings.IndexByte(nb, '.'); i > 0 {
		nb = nb[:i]
	}
	if len(nb) > 15 {
		nb = nb[:15]
	}
	return nb, dns
}

func filetime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}

func utf16LE(s string) []byte {
	if s == "" {
		return nil
	}
	r := []rune(s)
	out := make([]byte, 0, len(r)*2)
	for _, c := range r {
		out = binary.LittleEndian.AppendUint16(out, uint16(c))
	}
	return out
}
