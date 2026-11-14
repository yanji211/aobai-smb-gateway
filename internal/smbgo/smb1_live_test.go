package smbgo

// 内置 SMB1 通道的人工联调开关。
//
// 单测里没法凭空造一个"真客户端"，所以这里留一个只在显式给地址时才启动的
// 监听：本机跑起来后用 samba 的 smbclient（真正的 SMB1 实现）去打它，
// 才能验证协商/建树/列目录/读文件这些报文拼得对不对。
//
//	SMB1_LIVE_ADDR=0.0.0.0:1445 SMB1_LIVE_ROOT=/srv/share \
//	  go test ./internal/smbgo -run TestServeSMB1Live -v
//
// 不给 SMB1_LIVE_ADDR 时直接跳过，不影响常规测试。

import (
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func TestServeSMB1Live(t *testing.T) {
	addr := os.Getenv("SMB1_LIVE_ADDR")
	if addr == "" {
		t.Skip("设置 SMB1_LIVE_ADDR=0.0.0.0:1445 可启动内置 SMB1 通道做人工联调")
	}
	root := os.Getenv("SMB1_LIVE_ROOT")
	if root == "" {
		root = t.TempDir()
	}
	share := os.Getenv("SMB1_LIVE_SHARE")
	if share == "" {
		share = "share"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	t.Logf("内置 SMB1 通道已启动 %s root=%s share=%s", addr, root, share)

	stop := time.Now().Add(10 * time.Minute)
	for time.Now().Before(stop) {
		_ = ln.(*net.TCPListener).SetDeadline(stop)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
			first, _, err := readFrame(c)
			if err != nil {
				t.Logf("%s 首帧读取失败: %v", c.RemoteAddr(), err)
				return
			}
			_ = c.SetReadDeadline(time.Time{})
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
			log.Info("内置 SMB1 连接", "remote", c.RemoteAddr().String())
			if err := serveSMB1(c, first, root, share, true, log); err != nil {
				log.Warn("内置 SMB1 会话结束", "remote", c.RemoteAddr().String(), "err", err)
			}
		}(c)
	}
}
