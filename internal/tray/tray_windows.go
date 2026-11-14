//go:build windows

// Package tray 在 Windows 通知区域放一个图标，菜单里能打开控制台、切状态、退出程序。
//
// 为什么自己调 Win32 而不用现成库：本项目除 sqlite 外不引第三方依赖，
// 而托盘的核心只有三件事——注册窗口类、Shell_NotifyIcon、跑消息循环，
// 加起来两百行，比拖一个 cgo 依赖进来划算。
package tray

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

//go:embed fsgw.ico
var iconICO []byte

// Item 是托盘菜单里的一项。每次弹出菜单前由 Items 回调现场生成，
// 这样菜单能反映当前的开关状态，不需要跨线程同步界面对象。
type Item struct {
	ID       string
	Label    string
	Disabled bool
	Checked  bool
	Divider  bool
}

type Options struct {
	// Tip 是图标悬停提示，最长 127 个字符。
	Tip string
	// Items 每次右键时调用，返回菜单项。
	Items func() []Item
	// OnSelect 菜单项被点击。
	OnSelect func(id string)
	// OnActivate 左键单击或双击图标。
	OnActivate func()
}

const (
	wmNull      = 0x0000
	wmDestroy   = 0x0002
	wmClose     = 0x0010
	wmCommand   = 0x0111
	wmContext   = 0x007B
	wmRButtonUp = 0x0205
	wmLButtonUp = 0x0202
	wmLDouble   = 0x0203
	wmApp       = 0x8000
	wmTrayMsg   = wmApp + 1
	wmUpdateTip = wmApp + 2

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x1
	nifIcon    = 0x2
	nifTip     = 0x4

	mfString    = 0x0
	mfChecked   = 0x8
	mfSeparator = 0x800
	mfGrayed    = 0x1

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100

	imageIcon      = 1
	lrLoadFromFile = 0x0010
	lrDefaultSize  = 0x0040
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenuW      = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procSetForeground    = user32.NewProc("SetForegroundWindow")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procLoadImageW       = user32.NewProc("LoadImageW")
	procLoadIconW        = user32.NewProc("LoadIconW")
	procRegisterMsgW     = user32.NewProc("RegisterWindowMessageW")
	procShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandle  = kernel32.NewProc("GetModuleHandleW")
)

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type notifyIconData struct {
	CbSize            uint32
	_                 uint32
	HWnd              uintptr
	UID               uint32
	UFlags            uint32
	UCallbackMessage  uint32
	_                 uint32
	HIcon             uintptr
	SzTip             [128]uint16
	DwState           uint32
	DwStateMask       uint32
	SzInfo            [256]uint16
	UTimeoutOrVersion uint32
	SzInfoTitle       [64]uint16
	DwInfoFlags       uint32
	GuidItem          [16]byte
	HBalloonIcon      uintptr
}

type msgT struct {
	HWnd    uintptr
	Message uint32
	_       uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	_       uint32
	PtX     int32
	PtY     int32
}

type point struct{ X, Y int32 }

const (
	className  = "FSGW_TrayWindow"
	windowText = "熬拜共享家"
	trayUID    = 1
)

var (
	mu      sync.Mutex
	current *instance
	wndProc = syscall.NewCallback(wndProcFn)
)

type instance struct {
	opts     Options
	hwnd     uintptr
	hIcon    uintptr
	taskbar  uint32
	ready    chan error
	stopOnce sync.Once
}

// Start 启动托盘。返回 nil 表示图标已经在通知区域里了。
// 非交互会话（例如被服务方式拉起）会返回错误，调用方可以降级为无托盘运行。
func Start(o Options) error {
	mu.Lock()
	if current != nil {
		mu.Unlock()
		return fmt.Errorf("托盘已在运行")
	}
	inst := &instance{opts: o, ready: make(chan error, 1)}
	current = inst
	mu.Unlock()

	go inst.run()
	return <-inst.ready
}

// Stop 移除图标并结束消息循环。可重复调用。
func Stop() {
	mu.Lock()
	inst := current
	current = nil
	mu.Unlock()
	if inst == nil {
		return
	}
	inst.stopOnce.Do(func() {
		if inst.hwnd != 0 {
			// 先把图标摘掉再关窗口：wmClose 那条路上 inst 已经不在 current 里了，
			// 靠这里同步删才不会留下僵尸图标（鼠标划过才消失的那种）。
			inst.removeIcon()
			procPostMessageW.Call(inst.hwnd, wmClose, 0, 0)
		}
	})
}

// SetTip 更新悬停提示（状态变化时调用）。
func SetTip(tip string) {
	mu.Lock()
	inst := current
	if inst != nil {
		inst.opts.Tip = tip
	}
	mu.Unlock()
	if inst != nil && inst.hwnd != 0 {
		procPostMessageW.Call(inst.hwnd, wmUpdateTip, 0, 0)
	}
}

// Available 判断当前进程能否显示托盘图标（存在交互式桌面）。
func Available() bool { return procShellNotifyIcon.Find() == nil }

func (t *instance) run() {
	// 消息循环必须固定在同一个 OS 线程上，否则 GetMessage 拿不到窗口消息。
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInst, _, _ := procGetModuleHandle.Call(0)
	cls := utf16Ptr(className)
	var wc wndClassExW
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = wndProc
	wc.HInstance = hInst
	wc.LpszClassName = cls
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		t.ready <- fmt.Errorf("注册窗口类失败: %v", err)
		return
	}
	hwnd, _, err := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(utf16Ptr(windowText))),
		0, 0, 0, 0, 0, 0, 0, hInst, 0)
	if hwnd == 0 {
		t.ready <- fmt.Errorf("创建消息窗口失败: %v", err)
		return
	}
	t.hwnd = hwnd

	// explorer 重启后会广播 TaskbarCreated，收到就重新添加图标，否则图标永久消失。
	msgName := utf16Ptr("TaskbarCreated")
	if r, _, _ := procRegisterMsgW.Call(uintptr(unsafe.Pointer(msgName))); r != 0 {
		t.taskbar = uint32(r)
	}

	t.hIcon = loadIcon()
	if err := t.addIcon(); err != nil {
		t.ready <- err
		procDestroyWindow.Call(hwnd)
		return
	}
	t.ready <- nil

	var m msgT
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 { // 0 = WM_QUIT，-1 = 出错
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// loadIcon 优先用内嵌图标；失败就用系统默认图标，保证托盘一定有东西显示。
func loadIcon() uintptr {
	if len(iconICO) > 0 {
		p := filepath.Join(os.TempDir(), fmt.Sprintf("fsgw-%d.ico", os.Getpid()))
		if err := os.WriteFile(p, iconICO, 0o644); err == nil {
			h, _, _ := procLoadImageW.Call(0,
				uintptr(unsafe.Pointer(utf16Ptr(p))), imageIcon,
				0, 0, lrLoadFromFile|lrDefaultSize)
			os.Remove(p) // 句柄已加载，文件可以删
			if h != 0 {
				return h
			}
		}
	}
	const idiApplication = 32512
	h, _, _ := procLoadIconW.Call(0, idiApplication)
	return h
}

func (t *instance) nid() notifyIconData {
	var d notifyIconData
	d.CbSize = uint32(unsafe.Sizeof(d))
	d.HWnd = t.hwnd
	d.UID = trayUID
	d.UFlags = nifMessage | nifIcon | nifTip
	d.UCallbackMessage = wmTrayMsg
	d.HIcon = t.hIcon
	copy(d.SzTip[:], syscall.StringToUTF16(truncate(t.tipText(), 120)))
	d.SzTip[len(d.SzTip)-1] = 0
	return d
}

func (t *instance) tipText() string {
	mu.Lock()
	defer mu.Unlock()
	if t.opts.Tip == "" {
		return "熬拜共享家"
	}
	return t.opts.Tip
}

func (t *instance) addIcon() error {
	d := t.nid()
	ok, _, err := procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&d)))
	if ok == 0 {
		return fmt.Errorf("添加托盘图标失败（当前会话可能没有通知区域）: %v", err)
	}
	return nil
}

func (t *instance) updateTip() {
	d := t.nid()
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&d)))
}

func (t *instance) removeIcon() {
	d := t.nid()
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&d)))
}

func (t *instance) showMenu() {
	hmenu, _, _ := procCreatePopupMenu.Call()
	if hmenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hmenu)

	var ids []string
	if t.opts.Items != nil {
		for _, it := range t.opts.Items() {
			if it.Divider {
				procAppendMenuW.Call(hmenu, mfSeparator, 0, 0)
				continue
			}
			flags := uintptr(mfString)
			if it.Disabled {
				flags |= mfGrayed
			}
			if it.Checked {
				flags |= mfChecked
			}
			ids = append(ids, it.ID)
			procAppendMenuW.Call(hmenu, flags, uintptr(len(ids)),
				uintptr(unsafe.Pointer(utf16Ptr(it.Label))))
		}
	}
	if len(ids) == 0 {
		return
	}

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// 这两个调用是 Win32 的老规矩：不置前，菜单会弹了不消失。
	procSetForeground.Call(t.hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(hmenu,
		tpmReturnCmd|tpmRightButton,
		uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	procPostMessageW.Call(t.hwnd, wmNull, 0, 0)

	if cmd > 0 && int(cmd) <= len(ids) && t.opts.OnSelect != nil {
		go t.opts.OnSelect(ids[cmd-1])
	}
}

func wndProcFn(hwnd, msg, wparam, lparam uintptr) uintptr {
	mu.Lock()
	inst := current
	mu.Unlock()

	if inst != nil && inst.taskbar != 0 && uint32(msg) == inst.taskbar {
		// explorer 重启：图标被系统丢掉了，重新加一次
		inst.addIcon()
		return 0
	}

	switch uint32(msg) {
	case wmTrayMsg:
		if inst == nil {
			return 0
		}
		switch uint32(lparam) & 0xFFFF {
		case wmRButtonUp, wmContext:
			inst.showMenu()
		case wmLButtonUp, wmLDouble:
			if inst.opts.OnActivate != nil {
				go inst.opts.OnActivate()
			}
		}
		return 0
	case wmUpdateTip:
		if inst != nil {
			inst.updateTip()
		}
		return 0
	case wmCommand:
		return 0
	case wmClose:
		if inst != nil {
			inst.removeIcon()
		}
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func utf16Ptr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		empty := ""
		p, _ = syscall.UTF16PtrFromString(empty)
	}
	return p
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
