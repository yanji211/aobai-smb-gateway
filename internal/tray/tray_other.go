//go:build !windows

// 非 Windows 平台没有通知区域，这里只提供能编译的空实现，
// 让 selftest 与交叉编译不至于因为 import 就挂掉。
package tray

import "errors"

type Item struct {
	ID       string
	Label    string
	Disabled bool
	Checked  bool
	Divider  bool
}

type Options struct {
	Tip        string
	Items      func() []Item
	OnSelect   func(id string)
	OnActivate func()
}

func Available() bool     { return false }
func Start(Options) error { return errors.New("当前平台不支持托盘") }
func Stop()               {}
func SetTip(string)       {}
