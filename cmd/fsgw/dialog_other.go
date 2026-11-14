//go:build !windows

package main

// Linux 服务端跑在 systemd 里，没有桌面；保持原来的"打印一行再返回"。
func askConflict(_, _ string, _ bool) conflictChoice { return choiceSkip }
func showInfo(_, _ string, _ bool)                   {}
func showError(_, _ string, _ bool)                  {}
