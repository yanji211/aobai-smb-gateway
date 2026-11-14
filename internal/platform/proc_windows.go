//go:build windows

package platform

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	detachedProcess        = 0x00000008
	createBreakawayFromJob = 0x01000000
)

// listPIDs 列出同名进程的 PID（不含自己）。
func listPIDs(exeName string) ([]int, error) {
	out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq "+exeName, "/FO", "CSV", "/NH").Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("tasklist 失败: %w", err)
	}
	self := os.Getpid()
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		fields := strings.Split(line, `","`)
		if len(fields) < 2 {
			continue
		}
		pid, convErr := strconv.Atoi(strings.Trim(fields[1], `"`))
		if convErr != nil || pid == self {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// KillOtherInstances 结束同名进程（排除自己），返回结束的数量。
// 需要在提权环境下运行，才能结束提权运行的旧实例。
func KillOtherInstances(exeName string) (int, error) {
	pids, err := listPIDs(exeName)
	if err != nil {
		return 0, err
	}
	killed := 0
	for _, pid := range pids {
		cmd := exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err == nil {
			killed++
		}
	}
	return killed, nil
}

// WaitProcessGone 等到同名进程全部消失（最多 d）。消失返回 true。
func WaitProcessGone(exeName string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		pids, err := listPIDs(exeName)
		if err != nil || len(pids) == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// SpawnDetached 拉起一个与当前进程脱钩的子进程，父进程退出后它继续活着。
func SpawnDetached(exe string, args ...string) error {
	// 优先带 CREATE_BREAKAWAY_FROM_JOB。
	// 父进程若被放进 Job Object（IDE、CI、终端管理器、沙箱常这么做），
	// 单纯 DETACHED_PROCESS 的新实例仍属于该 Job，父进程退出时会被一起
	// 终结——表现就是 restart 打印"新实例已启动"，几百毫秒后进程凭空消失。
	// 部分 Job 不允许 breakaway，会返回 ACCESS_DENIED，此时退回普通 detached。
	flagsList := []uint32{
		detachedProcess | createBreakawayFromJob,
		detachedProcess,
	}
	var lastErr error
	for _, flags := range flagsList {
		cmd := exec.Command(exe, args...)
		cmd.Dir = filepath.Dir(exe)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: flags,
		}
		err := cmd.Start()
		if err == nil {
			return cmd.Process.Release()
		}
		lastErr = err
		// 只有"Job 不允许 breakaway"才值得重试，其余直接报错。
		if !isAccessDenied(err) {
			return err
		}
	}
	return lastErr
}

// isAccessDenied 判断是否为 ERROR_ACCESS_DENIED（Job 禁止 breakaway）。
func isAccessDenied(err error) bool {
	var errno syscall.Errno
	if ok := errors.As(err, &errno); ok {
		return errno == syscall.ERROR_ACCESS_DENIED
	}
	return false
}

// RelaunchElevated 用 UAC 重新拉起自己（ShellExecuteW + runas）。
// SMB 共享与免密策略都要求管理员，而双击 exe 默认没提权，
// 与其让用户去"右键 → 以管理员身份运行"，不如自己弹一次 UAC。
//
// hidden=true 时把新进程的控制台窗口藏起来：转后台运行只要用户点一次
// UAC，不需要再看一个常亮的黑框；hidden=false 用于前台调试，日志要看得到。
func RelaunchElevated(params string, hidden bool) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	shell32 := syscall.NewLazyDLL("shell32.dll")
	proc := shell32.NewProc("ShellExecuteW")
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(self)
	p, _ := syscall.UTF16PtrFromString(params)
	dir, _ := syscall.UTF16PtrFromString(filepath.Dir(self))
	const swShowNormal = 1
	const swHide = 0
	show := uintptr(swShowNormal)
	if hidden {
		show = swHide
	}
	r, _, _ := proc.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(dir)), show)
	if r <= 32 {
		if r == 5 {
			return errors.New("UAC 被拒绝（用户在弹窗里点了否）")
		}
		return fmt.Errorf("提权启动失败，ShellExecute 返回 %d", r)
	}
	return nil
}

// WaitPortFree 等到端口不再被占用（最多 d）。端口空闲返回 true。
func WaitPortFree(addr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err != nil {
			return true
		}
		conn.Close()
		time.Sleep(120 * time.Millisecond)
	}
	return false
}
