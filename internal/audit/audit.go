// Package audit 提供结构化运行日志与独立审计日志。
// 审计与调试日志分文件，不混用（见 docs/01 第 15 节）。
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	Time   time.Time `json:"time"`
	Source string    `json:"source"` // smb | webdav | ctlapi | index | system
	Action string    `json:"action"`
	Path   string    `json:"path,omitempty"`
	Result string    `json:"result"` // ok | deny | error
	Detail string    `json:"detail,omitempty"`
	Remote string    `json:"remote,omitempty"`
}

// Log 是并发安全的 JSON 行写入器，单文件超过 maxBytes 时滚动。
type Log struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	size     int64
	maxBytes int64
	keep     int
}

func Open(path string, maxBytes int64, keep int) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	l := &Log{path: path, maxBytes: maxBytes, keep: keep}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	l.f = f
	if st, err := f.Stat(); err == nil {
		l.size = st.Size()
	}
	return l, nil
}

func (l *Log) Write(v any) {
	if l == nil {
		return
	}
	if e, ok := v.(Entry); ok && e.Time.IsZero() {
		e.Time = time.Now()
		v = e
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	raw = append(raw, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	n, _ := l.f.Write(raw)
	l.size += int64(n)
	if l.maxBytes > 0 && l.size >= l.maxBytes {
		l.rotateLocked()
	}
}

func (l *Log) rotateLocked() {
	l.f.Close()
	for i := l.keep - 1; i >= 1; i-- {
		old := fmt.Sprintf("%s.%d", l.path, i)
		next := fmt.Sprintf("%s.%d", l.path, i+1)
		os.Remove(next)
		os.Rename(old, next)
	}
	os.Rename(l.path, l.path+".1")
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		l.f = nil
		return
	}
	l.f = f
	l.size = 0
}

func (l *Log) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}

// Tail 读取最近的审计条目（按行倒序取 limit 条后正序返回）。
func Tail(path string, limit int, filter string) ([]Entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var all []Entry
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\n' {
			continue
		}
		var e Entry
		if json.Unmarshal(raw[start:i], &e) == nil {
			if filter == "" || filter == "all" || e.Result == filter || e.Action == filter {
				all = append(all, e)
			}
		}
		start = i + 1
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}
