//go:build !linux && !windows

package smbgo

import (
	"log/slog"
)

// 这个包只在 Linux / Windows 上使用：两个平台都由进程内的纯 Go SMB2/3
// 服务端提供共享（Linux 见 smbhost/hosted_linux.go，Windows 见
// smbhost/hosted_windows.go 的 go 引擎）。
//
// server.go 是跨平台编译的，它引用的 acceptLoop / relay 写在 proxy.go 里
// （带 //go:build linux || windows，因为那一层要处理报文改写）。没有这个文件，
// 其它平台上 `go build ./...` 会报 acceptLoop undefined。
func (s *Server) acceptLoop(log *slog.Logger, upstream string) {
	log.Warn("smbgo 的 SMB 服务端只支持 Linux 与 Windows，当前平台不会转发任何连接")
}
