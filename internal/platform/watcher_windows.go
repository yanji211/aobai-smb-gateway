//go:build windows

package platform

import (
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type Op int

const (
	OpCreate Op = iota + 1
	OpWrite
	OpRename
	OpRemove
)

func (o Op) String() string {
	switch o {
	case OpCreate:
		return "create"
	case OpWrite:
		return "write"
	case OpRename:
		return "rename"
	case OpRemove:
		return "remove"
	}
	return "unknown"
}

// Event 是一条归一化的变更事件。RenameFired 时 OldPath 有效。
type Event struct {
	Op      Op
	Path    string
	OldPath string
}

type Overflow struct{ Root string }

var (
	procReadDirectoryChangesW = kernel32.NewProc("ReadDirectoryChangesW")
	procCancelIoEx            = kernel32.NewProc("CancelIoEx")
	procCreateEventW          = kernel32.NewProc("CreateEventW")
	procResetEvent            = kernel32.NewProc("ResetEvent")
	procGetOverlappedResult   = kernel32.NewProc("GetOverlappedResult")
	procWaitForSingleObject   = kernel32.NewProc("WaitForSingleObject")
)

const (
	errOperationAborted = 995
	errNotifyEnumDir    = 1022
)

const (
	fileListDirectory     = 0x0001
	notifyFileName        = 0x00000001
	notifyDirName         = 0x00000002
	notifyAttributes      = 0x00000004
	notifySize            = 0x00000008
	notifyLastWrite       = 0x00000010
	notifyCreation        = 0x00000040
	notifyAll             = notifyFileName | notifyDirName | notifyAttributes | notifySize | notifyLastWrite | notifyCreation
	flagOverlapped        = 0x40000000
	errIOPending          = 997
	actionAdded           = 1
	actionRemoved         = 2
	actionModified        = 3
	actionRenamedOldName  = 4
	actionRenamedNewName  = 5
	notifyBufferSize      = 64 * 1024
	notifyEntryHeaderSize = 12
)

// Watcher 用 ReadDirectoryChangesW 递归监听一个共享根。
// 刻意不使用第三方递归封装：缓冲大小、溢出语义、重命名配对都需要自己可控。
type Watcher struct {
	root     string
	handle   syscall.Handle
	events   chan Event
	overflow chan Overflow
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once

	pendingOld string
	pendingAt  time.Time
}

func NewWatcher(root string) (*Watcher, error) {
	p, err := syscall.UTF16PtrFromString(LongPath(root))
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, fileListDirectory, shareReadWriteDelete, nil,
		openExisting, flagBackupSemantics|flagOverlapped, 0)
	if err != nil {
		return nil, fmt.Errorf("打开监听根 %s: %w", root, err)
	}
	w := &Watcher{
		root:     root,
		handle:   h,
		events:   make(chan Event, 4096),
		overflow: make(chan Overflow, 64),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go w.loop()
	return w, nil
}

func (w *Watcher) Events() <-chan Event      { return w.events }
func (w *Watcher) Overflow() <-chan Overflow { return w.overflow }

func (w *Watcher) Close() error {
	w.once.Do(func() {
		close(w.stop)
		procCancelIoEx.Call(uintptr(w.handle), 0)
	})
	<-w.done
	syscall.CloseHandle(w.handle)
	return nil
}

func (w *Watcher) loop() {
	defer close(w.done)
	defer close(w.events)
	defer close(w.overflow)

	buf := make([]byte, notifyBufferSize)
	ev, _, e := procCreateEventW.Call(0, 1, 0, 0)
	if ev == 0 {
		_ = e
		return
	}
	defer syscall.CloseHandle(syscall.Handle(ev))

	for {
		select {
		case <-w.stop:
			return
		default:
		}

		var ov syscall.Overlapped
		ov.HEvent = syscall.Handle(ev)
		procResetEvent.Call(ev)

		r1, _, e := procReadDirectoryChangesW.Call(
			uintptr(w.handle),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			1, // bWatchSubtree
			uintptr(notifyAll),
			0,
			uintptr(unsafe.Pointer(&ov)),
			0,
		)
		if r1 == 0 {
			errno, ok := e.(syscall.Errno)
			if !ok || errno != errIOPending {
				return
			}
		}

		// 等待 I/O 完成，期间定期检查停止信号。
		stopped := false
		for {
			rc, _, _ := procWaitForSingleObject.Call(ev, 200)
			if uint32(rc) == 0 { // WAIT_OBJECT_0
				break
			}
			select {
			case <-w.stop:
				stopped = true
			default:
			}
			if stopped {
				procCancelIoEx.Call(uintptr(w.handle), 0)
				return
			}
		}

		var got uint32
		ok, _, gerr := procGetOverlappedResult.Call(
			uintptr(w.handle),
			uintptr(unsafe.Pointer(&ov)),
			uintptr(unsafe.Pointer(&got)),
			0,
		)
		if ok == 0 {
			if errno, isErrno := gerr.(syscall.Errno); isErrno && uint32(errno) == errOperationAborted {
				return
			}
			return
		}
		if got == 0 {
			// 缓冲溢出：ERROR_NOTIFY_ENUM_DIR。交给上层做子树级重建，不扫全盘。
			select {
			case w.overflow <- Overflow{Root: w.root}:
			default:
			}
			continue
		}
		w.parse(buf[:got])
	}
}

func (w *Watcher) parse(b []byte) {
	for off := 0; off+notifyEntryHeaderSize <= len(b); {
		next := *(*uint32)(unsafe.Pointer(&b[off]))
		action := *(*uint32)(unsafe.Pointer(&b[off+4]))
		nameLen := *(*uint32)(unsafe.Pointer(&b[off+8]))

		if nameLen == 0 || int(nameLen) > len(b)-off-notifyEntryHeaderSize {
			break
		}
		nameU16 := unsafe.Slice((*uint16)(unsafe.Pointer(&b[off+notifyEntryHeaderSize])), nameLen/2)
		name := syscall.UTF16ToString(nameU16)
		full := filepath.Join(w.root, name)

		switch action {
		case actionAdded:
			w.flushPendingAs(OpRemove)
			w.emit(Event{Op: OpCreate, Path: full})
		case actionModified:
			w.flushPendingAs(OpRemove)
			w.emit(Event{Op: OpWrite, Path: full})
		case actionRemoved:
			w.flushPendingAs(OpRemove)
			w.emit(Event{Op: OpRemove, Path: full})
		case actionRenamedOldName:
			// 上一对还没等到 NEW，先按删除结算，避免悬挂。
			w.flushPendingAs(OpRemove)
			w.pendingOld = full
			w.pendingAt = time.Now()
		case actionRenamedNewName:
			if w.pendingOld != "" && time.Since(w.pendingAt) <= 2*time.Second {
				w.emit(Event{Op: OpRename, OldPath: w.pendingOld, Path: full})
				w.pendingOld = ""
			} else {
				w.emit(Event{Op: OpCreate, Path: full})
				w.pendingOld = ""
			}
		}

		if next == 0 {
			break
		}
		off += int(next)
	}

	// 超时未配对的 OLD：按删除结算。
	if w.pendingOld != "" && time.Since(w.pendingAt) > 2*time.Second {
		w.flushPendingAs(OpRemove)
	}
}

func (w *Watcher) flushPendingAs(op Op) {
	if w.pendingOld == "" {
		return
	}
	p := w.pendingOld
	w.pendingOld = ""
	w.emit(Event{Op: op, Path: p})
}

func (w *Watcher) emit(e Event) {
	select {
	case w.events <- e:
	default:
		// 上层消费不过来，按溢出处理，让索引去做范围重建。
		select {
		case w.overflow <- Overflow{Root: w.root}:
		default:
		}
	}
}
