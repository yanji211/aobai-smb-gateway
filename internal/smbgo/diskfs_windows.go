//go:build windows

package smbgo

import (
	"syscall"
	"unsafe"
)

// Windows 侧取容量要自己调 kernel32：
// golang.org/x/sys/windows 没有导出 GetDiskFreeSpaceEx，而 os.Statfs 也不存在。
// 两个 API 分工是"字节数"与"簇结构"分开问，正好拼出 MS-FSCC 需要的
// AllocationUnits × SectorsPerUnit × BytesPerSector 三元组。
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetDiskFreeSpace   = kernel32.NewProc("GetDiskFreeSpaceW")
	procGetDiskFreeSpaceEx = kernel32.NewProc("GetDiskFreeSpaceExW")
)

// diskUnits 取共享根所在卷的总容量与可用容量。
// 口径与 Linux 版一致：单元 = 簇，每单元扇区数 = 簇字节/512，
// 于是 BytesPerSector 恒为 512，资源管理器的容量条与"此电脑"里看到的一致。
func diskUnits(root string) (fsUnits, uint32, uint32, bool) {
	if root == "" {
		return fsUnits{}, 0, 0, false
	}
	p, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return fsUnits{}, 0, 0, false
	}

	var freeAvail, total, totalFree uint64
	r, _, _ := procGetDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return fsUnits{}, 0, 0, false
	}

	var sectorsPerCluster, bytesPerSector, freeClusters, totalClusters uint32
	r, _, _ = procGetDiskFreeSpace.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&sectorsPerCluster)),
		uintptr(unsafe.Pointer(&bytesPerSector)),
		uintptr(unsafe.Pointer(&freeClusters)),
		uintptr(unsafe.Pointer(&totalClusters)))
	cluster := uint64(0)
	if r != 0 {
		cluster = uint64(sectorsPerCluster) * uint64(bytesPerSector)
	}
	if cluster == 0 {
		// 取不到簇结构时按 4K 折算，只影响容量显示，不影响读写。
		cluster = 4096
	}
	sectors := uint32(cluster / bytesPerSectorForReporting)
	if sectors == 0 {
		sectors = 1
	}
	return fsUnits{total: total / cluster, avail: freeAvail / cluster}, sectors, bytesPerSectorForReporting, true
}
