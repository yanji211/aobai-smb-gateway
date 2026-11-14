//go:build !windows

package smbgo

import "syscall"

// diskUnits 用 statfs 取共享根所在文件系统的总容量与可用容量。
// 单位统一成"分配单元"：单元大小取 f_frsize，每单元扇区数取 f_frsize/512，
// 这样与 Windows/samba 报数的方式一致（BytesPerSector 恒为 512）。
func diskUnits(root string) (fsUnits, uint32, uint32, bool) {
	if root == "" {
		return fsUnits{}, 0, 0, false
	}
	var sf syscall.Statfs_t
	if err := syscall.Statfs(root, &sf); err != nil {
		return fsUnits{}, 0, 0, false
	}
	frsize := uint64(sf.Frsize)
	if frsize == 0 {
		frsize = uint64(sf.Bsize)
	}
	if frsize == 0 {
		return fsUnits{}, 0, 0, false
	}
	sectors := uint32(frsize / bytesPerSectorForReporting)
	if sectors == 0 {
		sectors = 1
	}
	return fsUnits{total: sf.Blocks, avail: sf.Bavail}, sectors, bytesPerSectorForReporting, true
}
