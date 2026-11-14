//go:build linux

package smbhost

// Linux 的"免密"不是系统开关，而是 Go SMB 服务端的认证策略：
// 完整走 NTLMSSP 握手（客户端才认），校验不过就直接按 guest 放行。
// 所以这里没有 Guest 账户、ForceGuest、LSA 权限那一套，那些是 Windows
// 把整机切到来宾模式才需要的。本文件只负责把"是否可写"落到服务端上。

import (
	"fmt"
	"os"
)

// State 免密相关开关的现状，供诊断与状态展示使用。
type State struct {
	GuestExists        bool `json:"guest_exists"`
	GuestActive        bool `json:"guest_active"`
	ForceGuest         int  `json:"force_guest"`
	ClientGuest        bool `json:"client_guest"`
	GuestDeniedNetwork bool `json:"guest_denied_network"`
	NetLogonKnown      bool `json:"net_logon_known"`
	BlankPwdNetwork    bool `json:"blank_pwd_network"`
}

// Backup 记录改动前的状态。Go 服务端没有落盘配置，关闭即停止监听，
// 所以这里只需要一份可读的记录供日志与还原使用。
type Backup struct {
	GuestActive        bool `json:"guest_active"`
	ForceGuest         int  `json:"force_guest"`
	EveryoneHadAccess  bool `json:"everyone_had_access"`
	GuestDenyNetwork   bool `json:"guest_deny_network"`
	LimitBlankPassword int  `json:"limit_blank_password"`
	// WritableBefore 开启免密前共享是否可写，用于 Restore 恢复。
	WritableBefore bool `json:"writable_before"`
}

func ReadState() State {
	mu.Lock()
	defer mu.Unlock()
	active := running != nil
	fg := 0
	if active {
		fg = 1
	}
	return State{
		GuestExists:     true,
		GuestActive:     active,
		ForceGuest:      fg,
		ClientGuest:     true,
		NetLogonKnown:   true,
		BlankPwdNetwork: true,
	}
}

// Enable 按 guest_writable 重设共享的读写属性。
// 服务端跑在 root 下，文件权限拦不住读，所以只读必须在 VFS 层强制（smbgo 已做）。
func Enable(root string, writable bool) (Backup, error) {
	mu.Lock()
	defer mu.Unlock()
	bk := Backup{GuestActive: true, ForceGuest: 1, WritableBefore: curWrite}
	if running == nil || curName == "" {
		return bk, fmt.Errorf("SMB 共享尚未启动")
	}
	if fi, err := os.Stat(root); err != nil {
		return bk, fmt.Errorf("共享根不可用: %w", err)
	} else if !fi.IsDir() {
		return bk, fmt.Errorf("共享根不是目录: %s", root)
	}
	if err := startLocked(curName, root, writable); err != nil {
		return bk, err
	}
	return bk, nil
}

// Restore 停掉服务端，445 不再监听。系统里没有任何配置需要还原。
func Restore(root string, bk Backup) error {
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		running.Stop()
		running = nil
	}
	curName, curRoot, curWrite = "", "", false
	return nil
}

func SetClientGuest(enable bool) error { return nil }

func GuestDeniedNetworkLogon() (bool, error) { return false, nil }
func AllowGuestNetworkLogon() (bool, error)  { return false, nil }
func EnsureGuestLogon() error                { return nil }

// EnsureRootAccess / RevokeRootAccess 是 Windows 系统共享专有的 NTFS 授权，
// Linux 上免密由进程内认证完成，不需要动文件系统权限。
func EnsureRootAccess(root string, writable bool) error { return nil }
func RevokeRootAccess(root string) error                { return nil }
func RestoreGuestNetworkLogon(denied bool) error {
	return nil
}
