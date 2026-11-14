//go:build linux

package platform

// Linux 平台实现。
//
// 与 Windows 版的差异（刻意为之，不硬凑）：
//   - 没有"应用级防火墙"。Windows 那边每次开面都增删 FSGW- 规则；Linux 上
//     这边不动 iptables/nftables——家庭网关最常见的是本就跑在局域网里，
//     乱插规则会把这个盘上前端（LXD、80 端口那些）一起搞坏。需要收紧端口的
//     场景请用发行版自带的防火墙自行放行。
//   - 文件监听用轮询快照（磁盘上是 183 个文件，代价可忽略）。inotify 需要
//     处理 watch 上限与子目录递归注册，收益在这里不成比例。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errUnsupported = errors.New("platform: 该能力在当前平台未实现")

func IsAdmin() bool { return os.Geteuid() == 0 }

func LongPath(p string) string { return p }

func FirewallRules(state string, extra ...Rule) []Rule { return nil }

func EnsureRules(rules []Rule) error { return nil }

func RemoveByPrefix(prefix string) error { return nil }

func List(prefix string) ([]string, error) { return nil, nil }

func GetFileID(path string, isDir bool) (FileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, errUnsupported
	}
	var id FileID
	id.VolumeSerial = uint64(st.Dev)
	binary.LittleEndian.PutUint64(id.Serial[:8], st.Ino)
	return id, nil
}

func VolumeSerial(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

func Hardlink(existing, newLink string) error { return os.Link(existing, newLink) }

func FreeSpace(path string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err = unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	return st.Bavail * bs, st.Blocks * bs, nil
}

// RelaunchElevated Linux 下没有 UAC 那套，直接用 sudo 起即可。
func RelaunchElevated(params string, hidden bool) error {
	return fmt.Errorf("Linux 下请用 sudo 启动：sudo <程序> %s", params)
}

func SpawnDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd.Start()
}

// processAlive 判断 pid 是否还是同一个可执行文件。
func processAlive(pid int, exeName string) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	fields := strings.Split(string(raw), "\x00")
	if len(fields) == 0 {
		return false
	}
	return filepath.Base(fields[0]) == exeName
}

func findInstances(exeName string) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		if processAlive(pid, exeName) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// KillOtherInstances 结束同名进程（排除自己）。先 SIGTERM，给它拆暴露面的机会。
func KillOtherInstances(exeName string) (int, error) {
	killed := 0
	for _, pid := range findInstances(exeName) {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			continue
		}
		killed++
	}
	return killed, nil
}

func WaitProcessGone(exeName string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if len(findInstances(exeName)) == 0 {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return len(findInstances(exeName)) == 0
}

func WaitPortFree(addr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// ---------- 目录监听（轮询快照） ----------

type fileMeta struct {
	size  int64
	mtime int64
	dir   bool
}

// Watcher 用周期性快照对比代替 inotify：简单、无 watch 上限、不会漏注册子目录。
// 代价是最长一个轮询间隔的延迟（默认 5 秒），对"拷完文件在电视上看到"完全够用。
type Watcher struct {
	root     string
	events   chan Event
	overflow chan Overflow
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

func NewWatcher(root string) (*Watcher, error) {
	fi, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("监听目标不是目录: %s", root)
	}
	w := &Watcher{
		root:     root,
		events:   make(chan Event, 8192),
		overflow: make(chan Overflow, 4),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go w.loop()
	return w, nil
}

func (w *Watcher) Events() <-chan Event      { return w.events }
func (w *Watcher) Overflow() <-chan Overflow { return w.overflow }

func (w *Watcher) Close() error {
	w.once.Do(func() { close(w.stop) })
	<-w.done
	return nil
}

func (w *Watcher) loop() {
	defer close(w.done)
	defer close(w.events)
	defer close(w.overflow)

	prev := w.scan()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
		}
		next := w.scan()
		events := diffSnapshots(prev, next)
		if len(events) == 0 {
			prev = next
			continue
		}
		if !w.push(events) {
			return
		}
		prev = next
	}
}

func (w *Watcher) push(events []Event) bool {
	// 一次冒出太多变化（比如 rsync 灌库）就不逐条处理了，直接让上层重建子树。
	if len(events) > 1000 {
		select {
		case w.overflow <- Overflow{Root: w.root}:
		case <-w.stop:
			return false
		}
		return true
	}
	for _, ev := range events {
		select {
		case w.events <- ev:
		case <-w.stop:
			return false
		}
	}
	return true
}

func (w *Watcher) scan() map[string]fileMeta {
	out := make(map[string]fileMeta, 256)
	_ = filepath.WalkDir(w.root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() && p != w.root {
				return filepath.SkipDir
			}
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		out[p] = fileMeta{size: info.Size(), mtime: info.ModTime().UnixNano(), dir: d.IsDir()}
		return nil
	})
	return out
}

func diffSnapshots(prev, next map[string]fileMeta) []Event {
	var events []Event
	for p, n := range next {
		o, ok := prev[p]
		if !ok {
			events = append(events, Event{Op: OpCreate, Path: p})
			continue
		}
		if !o.dir && (o.size != n.size || o.mtime != n.mtime) {
			events = append(events, Event{Op: OpWrite, Path: p})
		}
	}
	for p := range prev {
		if _, ok := next[p]; !ok {
			events = append(events, Event{Op: OpRemove, Path: p})
		}
	}
	return events
}
