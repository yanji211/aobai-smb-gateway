//go:build !windows && !linux

// 既非 Windows 也非 Linux 时的空实现：保证可编译，运行时报未实现。
package platform

import (
	"errors"
	"time"
)

var errUnsupported = errors.New("platform: 该能力在当前平台未实现")

type Watcher struct {
	events   chan Event
	overflow chan Overflow
}

func NewWatcher(root string) (*Watcher, error) { return nil, errUnsupported }
func (w *Watcher) Events() <-chan Event        { return w.events }
func (w *Watcher) Overflow() <-chan Overflow   { return w.overflow }
func (w *Watcher) Close() error                { return nil }

func EnsureRules(rules []Rule) error                   { return errUnsupported }
func RemoveByPrefix(prefix string) error               { return nil }
func List(prefix string) ([]string, error)             { return nil, nil }
func FirewallRules(state string, extra ...Rule) []Rule { return nil }

func GetFileID(path string, isDir bool) (FileID, error) { return FileID{}, errUnsupported }
func VolumeSerial(path string) (uint64, error)          { return 0, errUnsupported }
func LongPath(p string) string                          { return p }
func IsAdmin() bool                                     { return false }
func Hardlink(existing, newLink string) error           { return errUnsupported }

func FreeSpace(path string) (free, total uint64, err error) { return 0, 0, errUnsupported }

func KillOtherInstances(exeName string) (int, error)       { return 0, errUnsupported }
func WaitProcessGone(exeName string, d time.Duration) bool { return true }
func SpawnDetached(exe string, args ...string) error       { return errUnsupported }
func RelaunchElevated(params string, hidden bool) error    { return errUnsupported }
func WaitPortFree(addr string, d time.Duration) bool       { return true }
