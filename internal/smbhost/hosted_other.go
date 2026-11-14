//go:build !windows && !linux

package smbhost

import (
	"errors"

	"fsgw/internal/smbgo"
)

var errUnsupported = errors.New("smbhost: 当前平台未实现")

func Exists(name string) bool                            { return false }
func EnsureShare(name, root string, writable bool) error { return errUnsupported }
func RemoveShare(name string) error                      { return nil }

// SetAccounts 只在纯 Go 服务端上有意义；其他平台没有实现。
func SetAccounts(list []smbgo.Account) {}

// SetClientHints 同上。
func SetClientHints(list []ClientHint) {}

// SetAppleMeta 同上。
func SetAppleMeta(mode string) {}

// SetSMB1Backend 同上。
func SetSMB1Backend(addr string) {}

// Engine / SetEngine / GuestBySystem：让上层的启动流程在三个平台写法一致。
func Engine() string                        { return "none" }
func SetEngine(name, stateDir string) error { return nil }
func FallbackReason() string                { return "" }
func GuestBySystem() bool                   { return false }
func Recover()                              {}
