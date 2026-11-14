package dlna

import (
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	ssdpAddr   = "239.255.255.250:1900"
	ssdpMaxAge = 1800
)

// ssdpLink 是「一块网卡上的一个 SSDP socket」。
// 必须把网卡地址和 socket 绑在一起：多网卡机器上每块网卡都要用自己的
// 地址去宣告 LOCATION，否则电视拿到的是一个它根本路由不到的地址。
type ssdpLink struct {
	conn *net.UDPConn
	ip   string
}

// ssdpServer 只实现"能被发现"这一件事：应答 M-SEARCH、周期广播 alive、退出时 byebye。
type ssdpServer struct {
	ip      string
	port    int
	udn     string
	version string
	log     *slog.Logger

	conns []ssdpLink
	stop  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

func newSSDP(ip string, port int, udn, name string, log *slog.Logger) *ssdpServer {
	return &ssdpServer{
		ip:      ip,
		port:    port,
		udn:     udn,
		version: "0.1.0",
		log:     log,
		stop:    make(chan struct{}),
	}
}

// targets 返回要声明的 (NT, USN) 组合。
func (s *ssdpServer) targets() [][2]string {
	dev := "urn:schemas-upnp-org:device:MediaServer:1"
	svc := "urn:schemas-upnp-org:service:ContentDirectory:1"
	return [][2]string{
		{"upnp:rootdevice", "uuid:" + s.udn + "::upnp:rootdevice"},
		{"uuid:" + s.udn, "uuid:" + s.udn},
		{dev, "uuid:" + s.udn + "::" + dev},
		{svc, "uuid:" + s.udn + "::" + svc},
	}
}

func (s *ssdpServer) location() string {
	return s.locationOn(s.ip)
}

// locationOn 用指定网卡地址拼设备描述的 URL。
// 每个 socket 都传自己的地址：Hyper-V / VMware 之类虚拟网卡也在这台机器上，
// 用日志里那个"主 IP"给所有网卡发，等于让电视去拉一个跨网段的地址。
func (s *ssdpServer) locationOn(ip string) string {
	return fmt.Sprintf("http://%s:%d/rootDesc.xml", ip, s.port)
}

func (s *ssdpServer) serverHeader() string {
	return fmt.Sprintf("%s/10 UPnP/1.0 fsgw/%s", runtime.GOOS, s.version)
}

// Start 在每个可多播的网卡上加入组播组。
func (s *ssdpServer) Start() error {
	group, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	joined := 0
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		ifaceIP, ok := firstIPv4(ifi)
		if !ok {
			continue
		}
		// 平台相关：Windows 必须绑具体网卡地址，否则组播包会被系统
		// SSDPSRV 服务抢走（它占着 <网卡IP>:1900）。见 ssdp_windows.go。
		conn, err := listenSSDP(&ifi, ifaceIP, group.Port)
		if err != nil {
			s.log.Warn("加入组播失败", "iface", ifi.Name, "ip", ifaceIP, "err", err)
			continue
		}
		conn.SetReadBuffer(64 * 1024)
		link := ssdpLink{conn: conn, ip: ifaceIP.String()}
		s.conns = append(s.conns, link)
		joined++
		s.wg.Add(1)
		go s.serve(link)
	}
	if joined == 0 {
		return fmt.Errorf("没有可用的多播网卡")
	}
	s.log.Info("SSDP 已加入组播", "ifaces", joined, "group", ssdpAddr)
	s.notify("ssdp:alive")
	s.wg.Add(1)
	go s.beacon()
	return nil
}

// firstIPv4 取网卡的第一个 IPv4 地址。
func firstIPv4(ifi net.Interface) (net.IP, bool) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4, true
			}
		}
	}
	return nil, false
}

func (s *ssdpServer) Stop() {
	s.once.Do(func() {
		s.notify("ssdp:byebye")
		close(s.stop)
		for _, c := range s.conns {
			c.conn.Close()
		}
		s.wg.Wait()
	})
}

// beacon 每 10 分钟重播一次 alive，让设备缓存不过期。
func (s *ssdpServer) beacon() {
	defer s.wg.Done()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.notify("ssdp:alive")
		}
	}
}

func (s *ssdpServer) notify(nts string) {
	group, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return
	}
	for _, link := range s.conns {
		loc := s.locationOn(link.ip)
		for _, tg := range s.targets() {
			msg := strings.Join([]string{
				"NOTIFY * HTTP/1.1",
				"HOST: " + ssdpAddr,
				"CACHE-CONTROL: max-age=" + fmt.Sprint(ssdpMaxAge),
				"LOCATION: " + loc,
				"SERVER: " + s.serverHeader(),
				"NT: " + tg[0],
				"NTS: " + nts,
				"USN: " + tg[1],
				"", "",
			}, "\r\n")
			link.conn.WriteToUDP([]byte(msg), group)
		}
	}
}

func (s *ssdpServer) serve(link ssdpLink) {
	defer s.wg.Done()
	c := link.conn
	buf := make([]byte, 2048)
	for {
		select {
		case <-s.stop:
			return
		default:
		}

		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Windows 特有：广播/应答引发 ICMP port unreachable 后，
			// 下一次读会拿到 WSAECONNRESET(10054)。这里绝不能退出监听，
			// 否则一次广播就能把设备发现能力打掉。
			s.log.Debug("SSDP 读取错误，继续监听", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		req := string(buf[:n])
		if !strings.HasPrefix(req, "M-SEARCH") {
			continue
		}
		st := headerValue(req, "ST")
		if st == "" || !s.matchST(st) {
			continue
		}
		s.log.Debug("收到 M-SEARCH", "from", src.String(), "st", st, "iface_ip", link.ip)
		for _, msg := range s.searchResponses(st, link.ip) {
			c.WriteToUDP([]byte(msg), src)
		}
	}
}

func (s *ssdpServer) matchST(st string) bool {
	if st == "ssdp:all" {
		return true
	}
	for _, tg := range s.targets() {
		if tg[0] == st {
			return true
		}
	}
	return false
}

// searchResponses 对 ssdp:all 逐条应答，对具体 ST 只回一条。
// ip 是收到这条 M-SEARCH 的网卡地址，LOCATION 必须用它。
func (s *ssdpServer) searchResponses(st, ip string) []string {
	var out []string
	build := func(oneST, usn string) string {
		return strings.Join([]string{
			"HTTP/1.1 200 OK",
			"CACHE-CONTROL: max-age=" + fmt.Sprint(ssdpMaxAge),
			"DATE: " + time.Now().UTC().Format(httpTimeFormat),
			"EXT:",
			"LOCATION: " + s.locationOn(ip),
			"SERVER: " + s.serverHeader(),
			"ST: " + oneST,
			"USN: " + usn,
			"", "",
		}, "\r\n")
	}
	if st == "ssdp:all" {
		for _, tg := range s.targets() {
			out = append(out, build(tg[0], tg[1]))
		}
		return out
	}
	for _, tg := range s.targets() {
		if tg[0] == st {
			out = append(out, build(tg[0], tg[1]))
		}
	}
	return out
}

const httpTimeFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

func headerValue(req, key string) string {
	prefix := strings.ToUpper(key) + ":"
	for _, line := range strings.Split(req, "\r\n") {
		if strings.HasPrefix(strings.ToUpper(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}
