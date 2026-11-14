//go:build !windows

package dlna

import (
	"net"
)

// listenSSDP 在非 Windows 平台直接用标准库加入组播。
// Linux/macOS 上多个 socket 可以同时加入同一组播组，不存在 Windows
// 「具体绑定优先」把包抢走的问题。
func listenSSDP(ifi *net.Interface, ifaceIP net.IP, port int) (*net.UDPConn, error) {
	group := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: port}
	return net.ListenMulticastUDP("udp4", ifi, group)
}
