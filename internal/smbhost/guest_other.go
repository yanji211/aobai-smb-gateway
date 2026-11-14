//go:build !windows && !linux

package smbhost

// State 免密相关开关的现状（非 Windows 平台恒为零值）。
type State struct {
	GuestExists        bool `json:"guest_exists"`
	GuestActive        bool `json:"guest_active"`
	ForceGuest         int  `json:"force_guest"`
	ClientGuest        bool `json:"client_guest"`
	GuestDeniedNetwork bool `json:"guest_denied_network"`
	NetLogonKnown      bool `json:"net_logon_known"`
	BlankPwdNetwork    bool `json:"blank_pwd_network"`
}

// Backup 改动前的状态快照。
type Backup struct {
	GuestActive        bool `json:"guest_active"`
	ForceGuest         int  `json:"force_guest"`
	EveryoneHadAccess  bool `json:"everyone_had_access"`
	GuestDenyNetwork   bool `json:"guest_deny_network"`
	LimitBlankPassword int  `json:"limit_blank_password"`
}

func ReadState() State                                  { return State{ForceGuest: -1} }
func Enable(root string, writable bool) (Backup, error) { return Backup{}, errUnsupported }
func Restore(root string, bk Backup) error              { return nil }
func SetClientGuest(enable bool) error                  { return errUnsupported }

// GuestDeniedNetworkLogon / AllowGuestNetworkLogon / RestoreGuestNetworkLogon
// 只在 Windows 上有意义，这里给出空实现让跨平台构建通过。
func GuestDeniedNetworkLogon() (bool, error) { return false, errUnsupported }
func AllowGuestNetworkLogon() (bool, error)  { return false, errUnsupported }
func EnsureGuestLogon() error                { return errUnsupported }

// EnsureRootAccess / RevokeRootAccess 是 Windows 系统共享专有的 NTFS 授权。
func EnsureRootAccess(root string, writable bool) error { return nil }
func RevokeRootAccess(root string) error                { return nil }
func RestoreGuestNetworkLogon(denied bool) error {
	return nil
}
