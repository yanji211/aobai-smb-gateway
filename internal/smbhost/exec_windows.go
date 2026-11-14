//go:build windows

package smbhost

import (
	"bytes"
	"os/exec"
	"syscall"
)

// run 跑一个控制台命令并收拢输出（Hidden 窗口：托盘程序别弹黑框）。
// net / icacls 的输出在中文系统上是 GBK，不保证是合法 UTF-8，
// 所以调用方要把"我们自己写的中文说明"和"命令原始输出"分开对待（见 tail）。
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}
