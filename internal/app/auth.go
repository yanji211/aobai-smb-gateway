package app

// 控制台登录用的账号校验：不另立一套账号，直接用共享设置里的那套。
//
// 依据顺序（命中即通过，用户名不区分大小写）：
//  1. webdav.username / password(_hash)  —— 外部只读面的主账号
//  2. webdav.users[]                     —— 多账号表
//  3. smb.account_name / password / nt_hash —— 局域网共享账号（Win11 用的那个）
//  4. smb_clients.yaml 里由控制台登记的客户端账号
//
// 为什么并集：现实里"共享账号"就是这几个，用户记的是同一套口令。分成两个
// 账号体系只会多一个"我这台机器该用哪个密码"的问题。口令错就整体拒绝，
// 不告诉对方"用户名对但口令错"，避免枚举账号。

import (
	"strings"

	"fsgw/internal/config"
	"fsgw/internal/smbgo"
	"fsgw/internal/webdav"
)

// CheckAccount 校验控制台登录，返回规范用户名。
func (a *App) CheckAccount(user, pass string) (string, bool) {
	user = strings.TrimSpace(user)
	if user == "" || pass == "" {
		return "", false
	}
	// SMB 的 NT 哈希按大写十六进制存，口令只转一次。
	nt := strings.ToUpper(smbgo.NTHashHex(pass))

	wd := a.cfg.WebDAV
	if strings.EqualFold(user, wd.Username) && passwordOK(pass, wd.Password, wd.PasswordHash) {
		return wd.Username, true
	}
	for _, u := range wd.Users {
		if strings.EqualFold(user, u.Username) && passwordOK(pass, u.Password, u.PasswordHash) {
			return u.Username, true
		}
	}

	smb := a.cfg.SMB
	if smb.Account != "" && strings.EqualFold(user, smb.Account) {
		if smb.NTHash != "" {
			if strings.EqualFold(nt, strings.TrimSpace(smb.NTHash)) {
				return smb.Account, true
			}
		} else if passwordOK(pass, smb.Password, "") {
			return smb.Account, true
		}
	}

	if clients, err := config.LoadClients(a.cfg.Path); err == nil {
		for _, c := range clients {
			if c.NTHash != "" && strings.EqualFold(user, c.Name) &&
				strings.EqualFold(nt, strings.TrimSpace(c.NTHash)) {
				return c.Name, true
			}
		}
	}
	return "", false
}

// passwordOK 兼容两种存法：加盐摘要优先，其次明文（本地临时验证用）。
// 两者都空视为"这个账号没有口令"，直接拒绝——不能因为没配口令就放行。
func passwordOK(pass, plain, hash string) bool {
	if hash != "" {
		return webdav.VerifyPassword(pass, hash)
	}
	if plain != "" {
		return len(pass) == len(plain) && subtleEqual(pass, plain)
	}
	return false
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
