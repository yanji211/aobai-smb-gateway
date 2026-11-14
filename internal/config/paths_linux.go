//go:build linux

package config

// extraDefaultPaths 是 Linux 上的系统级配置位置。
//
// systemd 单元用 -config /etc/fsgw/config.yaml 启动，但手工执行
// `fsgw off` / `fsgw status` 时通常不带参数——不认这几个位置的话，
// 免密共享还开着却报"读取配置失败"，等于假关。
func extraDefaultPaths() []string {
	return []string{
		"/etc/fsgw/config.yaml",
		"/var/lib/fsgw/config.yaml",
	}
}
