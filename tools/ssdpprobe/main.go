// ssdp_probe 诊断 SSDP 在本机能不能收到组播。
// 不改系统状态，不需要管理员权限，跑完 5 秒自动退出。
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const group = "239.255.255.250:1900"

func main() {
	gaddr, _ := net.ResolveUDPAddr("udp4", group)
	fmt.Println("组播组:", group)

	ifaces, _ := net.Interfaces()
	var target *net.Interface
	var targetIP net.IP
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					target, targetIP = &ifi, ip4
					break
				}
			}
		}
		if target != nil {
			break
		}
	}
	if target == nil {
		fmt.Println("没有可多播的网卡")
		return
	}
	fmt.Printf("选中网卡: %s (%s)\n\n", target.Name, targetIP)

	// 方案 A：标准库
	fmt.Println("[A] net.ListenMulticastUDP")
	connA, errA := net.ListenMulticastUDP("udp4", target, gaddr)
	if errA != nil {
		fmt.Println("    失败:", errA)
	} else {
		fmt.Println("    成功，本地地址:", connA.LocalAddr())
	}

	// 方案 B：自己建 socket，绑到网卡地址
	fmt.Println("[B] 自定义 socket：绑定网卡地址 + IP_ADD_MEMBERSHIP")
	connB, errB := customListen(targetIP)
	if errB != nil {
		fmt.Println("    失败:", errB)
	} else {
		fmt.Println("    成功，本地地址:", connB.LocalAddr())
	}

	// 两条连接同时收包
	got := make(chan string, 8)
	listen := func(tag string, c *net.UDPConn) {
		if c == nil {
			return
		}
		go func() {
			buf := make([]byte, 2048)
			for {
				c.SetReadDeadline(time.Now().Add(4500 * time.Millisecond))
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				got <- fmt.Sprintf("%s 收到 %d 字节: %.40s", tag, n, string(buf[:n]))
			}
		}()
	}
	listen("A", connA)
	listen("B", connB)

	// 从本机发一个 M-SEARCH，看谁收得到
	send, err := net.DialUDP("udp4", &net.UDPAddr{IP: targetIP}, gaddr)
	if err != nil {
		fmt.Println("发送 socket 创建失败:", err)
	} else {
		fmt.Fprintf(send, "M-SEARCH * HTTP/1.1\r\nHOST: %s\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n", group)
		fmt.Println("\n已从", targetIP, "发出 M-SEARCH，等待 4.5 秒…")
	}

	for i := 0; i < 5; i++ {
		select {
		case m := <-got:
			fmt.Println("  ", m)
		case <-time.After(900 * time.Millisecond):
		}
	}
	fmt.Println("结束")
	os.Exit(0)
}

const sioUDPConnReset = 0x9800000C

func customListen(ip4 net.IP) (*net.UDPConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("SO_REUSEADDR: %w", err)
	}
	var off, ret uint32
	syscall.WSAIoctl(syscall.Handle(fd), sioUDPConnReset,
		(*byte)(unsafe.Pointer(&off)), uint32(unsafe.Sizeof(off)), nil, 0, &ret, nil, 0)

	sa := &syscall.SockaddrInet4{Port: 1900}
	copy(sa.Addr[:], ip4)
	if err := syscall.Bind(syscall.Handle(fd), sa); err != nil {
		return nil, fmt.Errorf("bind %s:1900: %w", ip4, err)
	}

	mreq := &syscall.IPMreq{Multiaddr: [4]byte{239, 255, 255, 250}}
	copy(mreq.Interface[:], ip4)
	if err := syscall.SetsockoptIPMreq(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq); err != nil {
		return nil, fmt.Errorf("IP_ADD_MEMBERSHIP: %w", err)
	}
	f := os.NewFile(uintptr(fd), "ssdp")
	defer f.Close()
	pc, err := net.FilePacketConn(f)
	if err != nil {
		return nil, fmt.Errorf("FilePacketConn: %w", err)
	}
	c, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("不是 UDP")
	}
	return c, nil
}
