//go:build !windows

package main

import "errors"

// openBrowser 在无桌面环境（Linux 服务器）里没有可拉起的浏览器。
// 调用方本来就先把 URL 打印出来了，这里只回一个明确的错误，不去猜 xdg-open 在不在。
func openBrowser(url string) error {
	return errors.New("当前平台没有桌面浏览器，请手动打开上面的地址")
}
