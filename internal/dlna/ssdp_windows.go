//go:build windows

package dlna

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// listenSSDP 在 Windows 上必须绑到「具体网卡地址」，不能用通配地址。
//
// Windows 的 UDP 投递规则是「更具体的绑定优先」：系统的 SSDPSRV 服务占着
// <网卡IP>:1900，我们若绑 0.0.0.0:1900，组播包会全部投给 SSDPSRV，
// 自己一个都收不到——表现就是日志说「已加入组播」，但发 M-SEARCH 永远无应答。
//
// 所以这里对每块网卡单独建 socket：
//  1. SO_REUSEADDR，与 SSDPSRV 共存
//  2. 绑 <网卡IP>:1900
//  3. IP_ADD_MEMBERSHIP 加入 239.255.255.250
//  4. IP_MULTICAST_IF 指定发送网卡，保证 NOTIFY/200 OK 从对的接口出去
func listenSSDP(ifi *net.Interface, ifaceIP net.IP, port int) (*net.UDPConn, error) {
	ip4 := ifaceIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("非 IPv4 地址: %v", ifaceIP)
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(syscall.Handle(fd),
					syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp4",
		fmt.Sprintf("%s:%d", ip4.String(), port))
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("意外的连接类型 %T", pc)
	}

	rc, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, err
	}

	var joinErr, ifErr error
	var addr4 [4]byte
	copy(addr4[:], ip4)
	if err := rc.Control(func(fd uintptr) {
		h := syscall.Handle(fd)
		// 加入组播组
		mreq := &syscall.IPMreq{}
		copy(mreq.Multiaddr[:], ssdpGroup4[:])
		copy(mreq.Interface[:], ip4)
		joinErr = syscall.SetsockoptIPMreq(h, syscall.IPPROTO_IP,
			syscall.IP_ADD_MEMBERSHIP, mreq)
		// 发送走这块网卡；否则多网卡机器上 NOTIFY 可能从别的接口出去。
		ifErr = syscall.SetsockoptInet4Addr(h, syscall.IPPROTO_IP,
			ipMulticastIF, addr4)
	}); err != nil {
		conn.Close()
		return nil, err
	}
	if joinErr != nil {
		conn.Close()
		return nil, fmt.Errorf("加入组播: %w", joinErr)
	}
	// 发送接口设置失败只影响多网卡选路，不至于让发现能力整体失效。
	if ifErr != nil {
		// 交给调用方记日志，这里不返回错误。
		_ = ifErr
	}
	return conn, nil
}

// ipMulticastIF 是 IP_MULTICAST_IF，syscall 包没有导出。
const ipMulticastIF = 9

var ssdpGroup4 = [4]byte{239, 255, 255, 250}
