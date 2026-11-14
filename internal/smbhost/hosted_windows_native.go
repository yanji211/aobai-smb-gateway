//go:build windows

package smbhost

// 「系统共享」引擎：用 net share 把共享根交给 Windows 自己的 SMB 服务端。
//
// 这条路线的优点是零协议风险（微软自己实现），缺点是网关不在写路径上、
// 免密要靠 ForceGuest 整机来宾模式，而 Win11 24H2+ 的客户端强制签名会直接
// 否决来宾会话。所以它现在只作为 engine: native 的显式选择，
// 以及 engine: auto 下自研服务端起不来时的兜底。

import (
	"fmt"
	"strings"
)

// nativeExists 判断共享是否已存在。
func nativeExists(name string) bool {
	out, err := run("net", "share")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.EqualFold(f[0], name) {
			return true
		}
	}
	return false
}

// nativeEnsureShare 幂等创建/更新共享。
// 共享层只放行 Everyone，真实写入能力由 NTFS 决定（见 guest_windows.go）：
// 免密模式下即使共享给了 FULL，Everyone 在 NTFS 上只有 RX 就还是只读。
func nativeEnsureShare(name, root string, writable bool) error {
	if err := validName(name); err != nil {
		return err
	}
	if nativeExists(name) {
		nativeRemoveShare(name)
	}
	grant := "/grant:Everyone,READ"
	if writable {
		grant = "/grant:Everyone,FULL"
	}
	out, err := run("net", "share", name+"="+root, grant, "/y")
	if err != nil {
		return fmt.Errorf("net share 失败（需要管理员权限）: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

// nativeRemoveShare 只删除本网关创建的共享；名字来自配置，不会误伤其它共享。
func nativeRemoveShare(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	if !nativeExists(name) {
		return nil
	}
	out, err := run("net", "share", name, "/delete", "/y")
	if err != nil {
		return fmt.Errorf("删除共享失败: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}
