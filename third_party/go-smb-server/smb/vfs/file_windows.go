//go:build windows

package vfs

import (
	"os"
	"syscall"
)

// openFile 语义等同 os.OpenFile，唯一区别是**永远**申请 FILE_SHARE_DELETE。
//
// 为什么不直接用 os.OpenFile：Go 的 syscall.Open 只在"打开已存在的文件"时才
// 带上共享删除权限，CREATE_NEW / CREATE_ALWAYS 打开时没有。而 SMB 的语义里
// "开着句柄改名 / 开着句柄删除"都是合法的（客户端典型流程：CREATE → SET_INFO
// 改名 → CLOSE，或者先打开再删）。少了这个共享位，MoveFileEx / DeleteFile 会
// 返回 ERROR_SHARING_VIOLATION，被库糊成 STATUS_ACCESS_DENIED，客户端看到的
// 就是莫名其妙的"拒绝访问"——本次本机验收里"改名失败"就是这么来的。
func openFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	// O_APPEND 必须走标准库：os.NewFile 造出来的句柄不带"追加"标记，
	// 追加写会变成覆盖写。追加打开本身也不参与改名/删除，不必优化。
	if flag&os.O_APPEND != 0 {
		return os.OpenFile(name, flag, perm)
	}
	pathp, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_WRONLY:
		access = syscall.GENERIC_WRITE
	case os.O_RDWR:
		access = syscall.GENERIC_READ | syscall.GENERIC_WRITE
	default:
		access = syscall.GENERIC_READ
	}

	var createmode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		createmode = syscall.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == os.O_CREATE|os.O_TRUNC:
		createmode = syscall.CREATE_ALWAYS
	case flag&os.O_CREATE != 0:
		createmode = syscall.OPEN_ALWAYS
	case flag&os.O_TRUNC != 0:
		createmode = syscall.TRUNCATE_EXISTING
		access |= syscall.GENERIC_WRITE
	default:
		createmode = syscall.OPEN_EXISTING
	}

	// FILE_FLAG_BACKUP_SEMANTICS 是"能不能打开目录"的开关：不带它，CreateFile
	// 对目录一律 ERROR_ACCESS_DENIED（列目录、建文件夹全废）。对普通文件它无副作用，
	// 所以统一带上，省掉"先 Stat 判断是不是目录"那一轮竞态。
	const attrs = syscall.FILE_ATTRIBUTE_NORMAL | syscall.FILE_FLAG_BACKUP_SEMANTICS

	h, err := syscall.CreateFile(pathp, access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, createmode, attrs, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}
