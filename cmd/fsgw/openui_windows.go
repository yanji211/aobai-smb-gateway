//go:build windows

package main

import "os/exec"

// openBrowser 用系统默认程序打开 URL（Windows 走 start）。
func openBrowser(url string) error {
	return exec.Command("cmd", "/c", "start", "", url).Start()
}
