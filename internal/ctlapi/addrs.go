package ctlapi

import (
	"net"
	"strings"
)

// LocalHosts 返回本机所有可用于访问控制台的地址（不含回环）。
//
// 为什么要自动放行这些地址：Linux 服务器通常没有桌面环境，控制台只能从别的
// 机器用 IP 打开。而防 DNS rebinding 的 Host 校验必须有一份"什么 Host 算自己"
// 的清单——回环之外的合法名字就是本机的网卡地址。放行"字面 IP"不会削弱防护：
// 攻击者域名解析到本机后，Host 头仍然是攻击者域名，照样被拒。
func LocalHosts() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

// Advertise 把配置里的监听地址换成一个"别人真能打开"的 host:port。
//
// bind 写成 0.0.0.0:8444 / :8444 / [::]:8444 时，直接拼出来的 URL 是没法点的
// （0.0.0.0 不是可访问地址）。这里挑一张真实网卡的地址顶上去：优先私网 IPv4，
// 其次任意 IPv4，最后才是 IPv6。
func Advertise(bind string) string {
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return bind
	}
	host = strings.Trim(host, "[]")
	if host != "" && host != "0.0.0.0" && host != "::" {
		return net.JoinHostPort(host, port)
	}

	var v4, other string
	for _, ip := range LocalHosts() {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() == nil {
			if other == "" {
				other = ip
			}
			continue
		}
		if parsed.IsPrivate() && v4 == "" {
			v4 = ip
		}
		if v4 == "" {
			v4 = ip
		}
	}
	switch {
	case v4 != "":
		return net.JoinHostPort(v4, port)
	case other != "":
		return net.JoinHostPort(other, port)
	}
	return net.JoinHostPort("127.0.0.1", port)
}
