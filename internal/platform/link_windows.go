//go:build windows

package platform

import (
	"fmt"
	"syscall"
	"unsafe"
)

var procCreateHardLinkW = kernel32.NewProc("CreateHardLinkW")

// Hardlink 同卷建硬链接，用于快照区零空间占用地保旧内容。
// 注意：硬链接与原文件共享 inode，原地覆盖后看到的是新内容——
// 所以它只在"写之前"执行才有意义（见 docs/02 第 6.1 节）。
func Hardlink(existing, newLink string) error {
	e, err := syscall.UTF16PtrFromString(LongPath(existing))
	if err != nil {
		return err
	}
	n, err := syscall.UTF16PtrFromString(LongPath(newLink))
	if err != nil {
		return err
	}
	r, _, e2 := procCreateHardLinkW.Call(
		uintptr(unsafe.Pointer(n)),
		uintptr(unsafe.Pointer(e)),
		0,
	)
	if r == 0 {
		return fmt.Errorf("CreateHardLinkW(%s -> %s): %v", existing, newLink, e2)
	}
	return nil
}

// FreeSpace 返回某路径所在卷的可用空间与总容量（字节）。
func FreeSpace(path string) (free, total uint64, err error) {
	p, err := syscall.UTF16PtrFromString(LongPath(path))
	if err != nil {
		return 0, 0, err
	}
	var freeForCaller, totalBytes, totalFree uint64
	r, _, e := procGetDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeForCaller)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return 0, 0, fmt.Errorf("GetDiskFreeSpaceExW(%s): %v", path, e)
	}
	return freeForCaller, totalBytes, nil
}
