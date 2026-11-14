//go:build windows

// Package platform 隔离所有与操作系统强相关的实现：文件身份、变更监听、
// 防火墙、硬链接、服务封装。上层只依赖这里定义的接口（见 docs/01 第 6 节）。
package platform

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procGetFileInformationByHandleEx = kernel32.NewProc("GetFileInformationByHandleEx")
	procGetFileInformationByHandle   = kernel32.NewProc("GetFileInformationByHandle")
	procGetDiskFreeSpaceEx           = kernel32.NewProc("GetDiskFreeSpaceExW")
)

const (
	fileIDInfoClass = 18 // FileIdInfo

	accessReadAttributes = 0x0080
	shareReadWriteDelete = 0x0001 | 0x0002 | 0x0004
	openExisting         = 3
	flagBackupSemantics  = 0x02000000
	flagOpenReparsePoint = 0x00200000
)

// FileID 是文件的内容身份。Windows 上是卷序列号 + 128 位 FileID，
// 同卷移动不变（见 docs/02 第 1 节「文件身份三层」）。
type FileID struct {
	VolumeSerial uint64
	Serial       [16]byte
}

func (f FileID) String() string {
	return fmt.Sprintf("v2:%d:%x", f.VolumeSerial, f.Serial)
}

func (f FileID) IsZero() bool { return f.VolumeSerial == 0 && f.Serial == ([16]byte{}) }

type fileIDInfoRaw struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type byHandleFileInformation struct {
	FileAttributes     uint32
	CreationTime       syscall.Filetime
	LastAccessTime     syscall.Filetime
	LastWriteTime      syscall.Filetime
	VolumeSerialNumber uint32
	FileSizeHigh       uint32
	FileSizeLow        uint32
	NumberOfLinks      uint32
	FileIndexHigh      uint32
	FileIndexLow       uint32
}

// LongPath 给超长路径加 \\?\ 前缀。Windows 的 MAX_PATH 限制在深层目录下会咬人。
func LongPath(p string) string {
	if len(p) < 240 || len(p) >= 4 && p[:4] == `\\?\` {
		return p
	}
	if len(p) >= 2 && p[:2] == `\\` {
		return `\\?\UNC\` + p[2:]
	}
	return `\\?\` + p
}

// GetFileID 打开句柄取文件身份。目录需 FILE_FLAG_BACKUP_SEMANTICS，
// 且始终带 OPEN_REPARSE_POINT，避免跟着符号链接跑出共享根。
func GetFileID(path string, isDir bool) (FileID, error) {
	p, err := syscall.UTF16PtrFromString(LongPath(path))
	if err != nil {
		return FileID{}, err
	}
	attrs := uint32(flagOpenReparsePoint)
	if isDir {
		attrs |= flagBackupSemantics
	}
	h, err := syscall.CreateFile(p, accessReadAttributes, shareReadWriteDelete, nil, openExisting, attrs, 0)
	if err != nil {
		return FileID{}, err
	}
	defer syscall.CloseHandle(h)

	var raw fileIDInfoRaw
	r, _, e := procGetFileInformationByHandleEx.Call(
		uintptr(h), uintptr(fileIDInfoClass),
		uintptr(unsafe.Pointer(&raw)), unsafe.Sizeof(raw))
	if r != 0 {
		return FileID{VolumeSerial: raw.VolumeSerialNumber, Serial: raw.FileID}, nil
	}

	// 退化路径：老文件系统或某些重定向器不支持 FileIdInfo，用 64 位文件索引。
	var bh byHandleFileInformation
	r2, _, _ := procGetFileInformationByHandle.Call(uintptr(h), uintptr(unsafe.Pointer(&bh)))
	if r2 == 0 {
		return FileID{}, fmt.Errorf("GetFileInformationByHandleEx: %v", e)
	}
	var id FileID
	id.VolumeSerial = uint64(bh.VolumeSerialNumber)
	*(*uint32)(unsafe.Pointer(&id.Serial[0])) = bh.FileIndexLow
	*(*uint32)(unsafe.Pointer(&id.Serial[4])) = bh.FileIndexHigh
	return id, nil
}

// VolumeSerial 取某个路径所在卷的序列号。
func VolumeSerial(path string) (uint64, error) {
	id, err := GetFileID(path, true)
	if err != nil {
		return 0, err
	}
	return id.VolumeSerial, nil
}

var errUnsupported = errors.New("platform: 该能力在当前平台未实现")

// IsAdmin 检测当前进程是否具备管理员权限（防火墙与 net share 需要）。
func IsAdmin() bool {
	const tokenQuery = 0x0008
	const tokenElevation = 20
	procOpenProcessToken := advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation := advapi32.NewProc("GetTokenInformation")

	var token syscall.Handle
	r, _, _ := procOpenProcessToken.Call(
		^uintptr(0), // pseudo handle: 当前进程
		uintptr(tokenQuery), uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer syscall.CloseHandle(token)

	var elevated uint32
	var retLen uint32
	r2, _, _ := procGetTokenInformation.Call(uintptr(token), uintptr(tokenElevation),
		uintptr(unsafe.Pointer(&elevated)), unsafe.Sizeof(elevated), uintptr(unsafe.Pointer(&retLen)))
	return r2 != 0 && elevated != 0
}
