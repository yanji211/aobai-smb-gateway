//go:build linux

package smbhost

// Linux 的 SMB 共享由进程内的纯 Go SMB2/3 服务端提供（见 hosted_go.go 与
// internal/smbgo），不使用 samba：没有 /etc/samba/smb.conf、没有 smbd 子进程、
// 没有系统账户。
//
// 这样做的好处直接对应方案里的"开关即安全"：
//   - 关闭网关 = Stop() = 445 立刻不再监听，没有残留配置要还原；
//   - 共享根之外一律不可达（vfs 层做了穿越防护）；
//   - 免密只作用于这一个共享，不改变整机的任何设置。
//
// 本文件只做平台转发，实现全在 hosted_go.go（与 Windows 共用）。

import (
	"fsgw/internal/smbgo"
)

func SetAccounts(list []smbgo.Account) { goSetAccounts(list) }

// SetClientHints 设置接入端类型的人工指定表。
func SetClientHints(list []ClientHint) { goSetClientHints(list) }

// SetAppleMeta 设置"列目录时是否过滤 mac 影子文件"（.DS_Store / ._xxx）。
func SetAppleMeta(mode string) { goSetAppleMeta(mode) }

// SetSMB1Backend 设置纯 SMB1 客户端的兜底后端（仅自研服务端有意义）。
func SetSMB1Backend(addr string) { goSetSMB1Backend(addr) }

// EnsureShare 启动（或重启）Go SMB 服务端。
func EnsureShare(name, root string, writable bool) error { return goEnsureShare(name, root, writable) }

// RemoveShare 停掉服务端，445 立即关闭。
func RemoveShare(name string) error { return goRemoveShare(name) }

// Exists 共享当前是否真的在对外提供。
func Exists(name string) bool { return goExists(name) }

// Engine 固定为 go：Linux 上不存在"系统共享"这条备选路线。
func Engine() string { return "go" }

// GuestBySystem 在 Linux 上恒为 false：免密就是服务端的认证策略，
// 没有 Guest 账户 / ForceGuest 那套整机开关要改。
func GuestBySystem() bool { return false }

// SetEngine 在 Linux 上是空操作，只为让上层的启动流程在两个平台写法一致。
func SetEngine(name, stateDir string) error { return nil }

// FallbackReason 在 Linux 上没有"回退"这回事（自研服务端就是唯一实现）。
func FallbackReason() string { return "" }

// Recover 在 Linux 上没有需要收拾的现场：进程没了 445 就自动释放。
func Recover() {}
