//go:build !windows

package platform

// 跨平台共用的类型定义。实现分别在 platform_windows 系与 linux / stub 里。

import (
	"fmt"
	"io"
	"os"
)

// FileID 是文件在所在卷上的稳定标识，用于识别"同一个文件被改名"。
type FileID struct {
	VolumeSerial uint64
	Serial       [16]byte
}

func (f FileID) String() string { return fmt.Sprintf("x:%d:%x", f.VolumeSerial, f.Serial) }
func (f FileID) IsZero() bool   { return f.VolumeSerial == 0 && f.Serial == [16]byte{} }

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

type Event struct {
	Op      Op
	Path    string
	OldPath string
}

type Overflow struct{ Root string }

// Rule 是一条防火墙规则的描述（Linux 下不使用，保留类型以共享调用方代码）。
type Rule struct {
	Name, Proto string
	Port        int
	Remote      string
	Profile     string
}

func (r Rule) String() string { return r.Name }

func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
