//go:build linux

package smbhost

// Linux 的 445 端口由本进程直接监听：网关进程跑起来就是唯一占用者，
// 关闭即释放，不存在"系统里另有一个 SMB 服务占着 445"这回事。
// 这两个函数只是为了让 hosted_go.go 的启动流程在两个平台写法一致。

func ensurePort445() error { return nil }

func releasePort445() {}
