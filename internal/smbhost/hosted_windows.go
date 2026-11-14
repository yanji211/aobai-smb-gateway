//go:build windows

// Package smbhost 托管 Windows 上的 SMB 共享：默认由进程内的纯 Go SMB2/3
// 服务端提供（与 Linux 同一套代码），也可以显式切回系统自带的 SMB 服务。
// 两条路线的取舍见 hosted_windows.go 顶部注释。
package smbhost

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"fsgw/internal/smbgo"
)

const (
	EngineAuto   = "auto"
	EngineGo     = "go"
	EngineNative = "native"
)

var (
	engineMu   sync.Mutex
	engineName = EngineAuto
	// fallbackReason 记录 auto 下为什么退回了系统共享（空=没退）。
	// 上层拿它写状态说明，让用户知道"为什么不是自研服务端"。
	fallbackReason string
)

// SetEngine 由 app 在启动 SMB 之前调用。stateDir 用来放服务接管现场的备份。
func SetEngine(name, stateDir string) error {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "", EngineAuto:
		n = EngineAuto
	case EngineGo, "golang", "builtin", "internal":
		n = EngineGo
	case EngineNative, "system", "lanman", "share":
		n = EngineNative
	default:
		return fmt.Errorf("未知的 smb.engine: %q（可选 auto / go / native）", name)
	}
	engineMu.Lock()
	engineName = n
	fallbackReason = ""
	engineMu.Unlock()
	setPortStateDir(stateDir)
	return nil
}

// Engine 返回当前生效的引擎名（永远是 auto / go / native 之一）。
func Engine() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	return engineName
}

// SetAccounts 设置允许登录的账号表。
// native 引擎不用它（账号就是本机账户），go 引擎必须靠它做 NTLM 校验。
func SetAccounts(list []smbgo.Account) { goSetAccounts(list) }

// SetClientHints 设置接入端类型的人工指定表（仅自研服务端有意义）。
func SetClientHints(list []ClientHint) { goSetClientHints(list) }

// SetAppleMeta 设置"列目录时是否过滤 mac 影子文件"（仅自研服务端有意义）。
func SetAppleMeta(mode string) { goSetAppleMeta(mode) }

// SetSMB1Backend 设置纯 SMB1 客户端的兜底后端（仅自研服务端有意义）。
func SetSMB1Backend(addr string) { goSetSMB1Backend(addr) }

// EnsureShare 启动共享。auto 下自研服务端起不来会退回系统共享。
func EnsureShare(name, root string, writable bool) error {
	switch Engine() {
	case EngineNative:
		return nativeEnsureShare(name, root, writable)
	case EngineGo:
		return goEnsureShare(name, root, writable)
	}

	err := goEnsureShare(name, root, writable)
	if err == nil {
		return nil
	}
	// 退回系统共享之前，把刚才为接管 445 动过的服务还原，
	// 否则会留下一个"系统共享服务已停、我们的服务又没起来"的裸奔状态。
	releasePort445()
	slog.Default().Warn("自研 SMB 服务端未能启动，回退系统共享（Win11 免密将不可用）", "err", err)
	if nerr := nativeEnsureShare(name, root, writable); nerr != nil {
		return fmt.Errorf("自研服务端失败：%v；回退系统共享也失败：%w", err, nerr)
	}
	// 关键：回退成功后把引擎真正切成 native。
	// 否则 Engine() 还是 auto，后面判断"免密要不要走系统策略"（GuestBySystem）
	// 会算出 false，于是用自研口径去改免密，必然报"SMB 共享尚未启动"，
	// 明明共享已经建好了，界面上却显示创建失败。
	engineMu.Lock()
	engineName = EngineNative
	fallbackReason = err.Error()
	engineMu.Unlock()
	slog.Default().Info("已改用系统共享引擎（本进程内）", "reason", err.Error())
	return nil
}

// FallbackReason 报告 auto 下退回系统共享的原因；空字符串表示没有回退。
func FallbackReason() string {
	engineMu.Lock()
	defer engineMu.Unlock()
	return fallbackReason
}

// RemoveShare 停掉共享：两条路线都清一遍，保证"关闭 = 零暴露"。
func RemoveShare(name string) error {
	gerr := goRemoveShare(name) // 内部会还原 LanmanServer
	if Engine() == EngineGo {
		return gerr
	}
	nerr := nativeRemoveShare(name)
	if Engine() == EngineNative {
		return nerr
	}
	if gerr != nil {
		return gerr
	}
	return nerr
}

// Recover 收拾上一次被强杀留下的现场：接管过 LanmanServer 但当前没有服务在跑，
// 就把系统服务还原回去，别让用户开机后发现整台机器的共享莫名其妙全没了。
// 上层在启动时、按配置切换开关前调用。
func Recover() {
	if goExists("") {
		return
	}
	releasePort445()
}

// GuestBySystem 报告"免密"是否要动系统策略（只有 native 引擎需要）。
// 上层据此决定要不要落盘一份"改动前的系统状态"，退出时好还原。
func GuestBySystem() bool { return systemGuestActive() }

// Exists 共享当前是否真的在对外提供。
func Exists(name string) bool {
	if Engine() != EngineNative && goExists(name) {
		return true
	}
	if Engine() == EngineGo {
		return false
	}
	return nativeExists(name)
}
