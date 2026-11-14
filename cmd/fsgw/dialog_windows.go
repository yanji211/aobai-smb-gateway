//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// 直接用 user32!MessageBoxW，不引入 GUI 框架：绿色包要能单文件跑，
// 也不想为一个提示框把整个 Windows.Forms / webview 拖进来。
const (
	mbOK            = 0x00000000
	mbYesNo         = 0x00000004
	mbIconQuestion  = 0x00000020
	mbIconWarning   = 0x00000030
	mbIconInfo      = 0x00000040
	mbDefButton2    = 0x00000100 // 默认落在「否」：误按回车不该停掉正在被电视用的服务
	mbSetForeground = 0x00010000
	mbTopMost       = 0x00040000
	idYes           = 6
)

var (
	user32Lib     = syscall.NewLazyDLL("user32.dll")
	messageBoxW   = user32Lib.NewProc("MessageBoxW")
	kernel32Lib   = syscall.NewLazyDLL("kernel32.dll")
	procSessionID = kernel32Lib.NewProc("ProcessIdToSessionId")
)

// interactiveSession 排除 session 0（Windows 服务 / 计划任务）。
// 那边没有可见桌面，MessageBox 会挂住进程且谁也看不见。
func interactiveSession() bool {
	var sid uint32
	r, _, _ := procSessionID.Call(uintptr(os.Getpid()), uintptr(unsafe.Pointer(&sid)))
	return r != 0 && sid != 0
}

func messageBox(title, text string, flags uintptr) int {
	t, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return 0
	}
	b, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return 0
	}
	r, _, _ := messageBoxW.Call(0,
		uintptr(unsafe.Pointer(b)),
		uintptr(unsafe.Pointer(t)),
		flags|mbSetForeground|mbTopMost)
	return int(r)
}

// askConflict 把"为什么没反应"和两个选择摆到用户面前。
// allowGUI=false 或非交互会话时直接返回 choiceSkip。
func askConflict(title, text string, allowGUI bool) conflictChoice {
	if !allowGUI || !interactiveSession() {
		return choiceSkip
	}
	if messageBox(title, text, mbYesNo|mbIconQuestion|mbDefButton2) == idYes {
		return choiceTakeOver
	}
	return choiceKeepOld
}

func showInfo(title, text string, allowGUI bool) {
	if !allowGUI || !interactiveSession() {
		return
	}
	messageBox(title, text, mbOK|mbIconInfo)
}

func showError(title, text string, allowGUI bool) {
	if !allowGUI || !interactiveSession() {
		return
	}
	messageBox(title, text, mbOK|mbIconWarning)
}
