//go:build !windows

package vfs

import "os"

// openFile 在非 Windows 平台上就是 os.OpenFile：POSIX 的 rename/unlink 本来
// 就允许文件被打开时进行，不需要额外的共享位。保留同名函数只是为了两平台
// 共用一份调用点。
func openFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}
