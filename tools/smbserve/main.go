// 开发期用的小工具：把 smbgo 起在指定端口，方便在没有管理员权限的情况下
// 用 Windows 客户端（\\127.0.0.1@4450\share）验证协议兼容性。
//
// 它不参与发布，只用于本机联调：
//
//	go run ./tools/smbserve -root D:\fsgw\.tmp\smbtest -addr :4450 -user admin -pass changeme
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"fsgw/internal/smbgo"
)

func main() {
	root := flag.String("root", `D:\share`, "共享根目录")
	share := flag.String("share", "share", "共享名")
	addr := flag.String("addr", ":4450", "监听地址")
	user := flag.String("user", "", "账号（留空 = 纯来宾）")
	pass := flag.String("pass", "", "口令")
	readonly := flag.Bool("readonly", false, "只读")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	var accounts []smbgo.Account
	if *user != "" {
		accounts = append(accounts, smbgo.Account{Name: *user, NTHash: smbgo.NTHashBytes(*pass)})
	}

	s, err := smbgo.Start(smbgo.Options{
		Addr:     *addr,
		Root:     *root,
		Share:    *share,
		ReadOnly: *readonly,
		Accounts: accounts,
		Log:      logger,
	})
	if err != nil {
		logger.Error("启动失败", "err", err)
		os.Exit(1)
	}
	logger.Info("已启动", "addr", *addr, "share", *share, "root", *root)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	s.Stop()
}
