package dlna

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMediaMime(t *testing.T) {
	cases := map[string]string{
		"a.mp4":        "video/mp4",
		"影片.MKV":       "video/x-matroska",
		"周报.txt":       "",
		"2026 报价单.pdf": "",
		"封面.JPG":       "image/jpeg",
		"music.flac":   "audio/flac",
		"noext":        "",
	}
	for name, want := range cases {
		if got := mediaMime(name); got != want {
			t.Errorf("mediaMime(%q) = %q, 期望 %q", name, got, want)
		}
	}
}

func TestUpnpClass(t *testing.T) {
	if upnpClass("video/mp4") != "object.item.videoItem" {
		t.Error("视频类映射错误")
	}
	if upnpClass("audio/mpeg") != "object.item.audioItem.musicTrack" {
		t.Error("音频类映射错误")
	}
	if upnpClass("image/png") != "object.item.imageItem.photo" {
		t.Error("图片类映射错误")
	}
}

// DIDL 里的标题必须转义，否则带 & < > 的文件名会把 XML 弄坏。
func TestDIDLEscape(t *testing.T) {
	out := didl([]didlObject{{
		ID: "f:share:a&b", ParentID: "sh:share", Title: `a & b <c> "d"`,
		Class: "object.item.videoItem", Size: 10, Mime: "video/mp4",
		URL: "http://192.168.1.2:8200/media/share/a%26b.mp4",
	}})
	if strings.Contains(out, "<c>") {
		t.Errorf("标题未转义: %s", out)
	}
	if !strings.Contains(out, "&amp;") {
		t.Errorf("& 未转义: %s", out)
	}
	if !strings.Contains(out, `protocolInfo="http-get:*:video/mp4:*"`) {
		t.Errorf("protocolInfo 缺失: %s", out)
	}
}

// SSDP 应答必须带齐 LOCATION / ST / USN，否则电视不会认。
func TestSearchResponseShape(t *testing.T) {
	s := &ssdpServer{ip: "192.168.1.10", port: 8200, udn: "test-udn-1234"}

	one := s.searchResponses("upnp:rootdevice", "192.168.1.10")
	if len(one) != 1 {
		t.Fatalf("具体 ST 应只回 1 条，实际 %d", len(one))
	}
	for _, must := range []string{
		"HTTP/1.1 200 OK",
		"LOCATION: http://192.168.1.10:8200/rootDesc.xml",
		"ST: upnp:rootdevice",
		"USN: uuid:test-udn-1234::upnp:rootdevice",
		"EXT:",
	} {
		if !strings.Contains(one[0], must) {
			t.Errorf("应答缺少 %q\n%s", must, one[0])
		}
	}

	all := s.searchResponses("ssdp:all", "192.168.1.10")
	if len(all) != 4 {
		t.Errorf("ssdp:all 应回 4 条（rootdevice/uuid/device/service），实际 %d", len(all))
	}

	if s.matchST("urn:schemas-upnp-org:device:Printer:1") {
		t.Error("不应答无关设备类型")
	}
}

// UDN 是 SSDP 的去重键。同机重启必须不变（否则电视里会多出重复设备），
// 异机必须不同（否则两台机器只显示一台）。第二条是本轮线上问题的回归守卫：
// Windows 版和 Linux 版默认都叫"家庭共享:8200"，之前用 md5(名称+端口)
// 生成 UUID，两台机器完全撞车，电视就只认其中一个。
func TestResolveUDN(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()

	a1 := resolveUDN(dirA, "家庭共享", 8200)
	a2 := resolveUDN(dirA, "家庭共享", 8200)
	if a1 != a2 {
		t.Errorf("同一 data_dir 应得到稳定 UUID，否则每次重启电视里会多一个设备: %s / %s", a1, a2)
	}
	if !validUDN(a1) || len(a1) != 36 || strings.Count(a1, "-") != 4 {
		t.Errorf("UUID 格式不对: %s", a1)
	}
	if b := resolveUDN(dirB, "家庭共享", 8200); b == a1 {
		t.Errorf("两台机器（不同 data_dir）不能共用 %s，否则电视按 UUID 去重只会显示一台", a1)
	}
	// 名称/端口相同也不该影响唯一性——唯一性来自落盘的随机值。
	if resolveUDN(dirB, "别的名字", 9000) == a1 {
		t.Error("不同实例的 UUID 不应相同")
	}
}

func TestResolveUDNPersists(t *testing.T) {
	dir := t.TempDir()
	u := resolveUDN(dir, "家庭共享", 8200)
	b, err := os.ReadFile(filepath.Join(dir, "dlna_udn.txt"))
	if err != nil {
		t.Fatalf("UUID 应该落盘，否则每次重启都变: %v", err)
	}
	if strings.TrimSpace(string(b)) != u {
		t.Errorf("文件内容与返回不一致: %q vs %q", strings.TrimSpace(string(b)), u)
	}
	// 文件被写坏时要能自愈，而不是把畸形 UDN 播出去。
	if err := os.WriteFile(filepath.Join(dir, "dlna_udn.txt"), []byte("坏值\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := resolveUDN(dir, "家庭共享", 8200); !validUDN(got) {
		t.Errorf("文件损坏后应重新生成合法 UUID，实际 %q", got)
	}
}

func TestValidUDN(t *testing.T) {
	if !validUDN("ecc11607-5e24-6b7c-9e46-01ca5290922f") {
		t.Error("标准 UUID 应通过")
	}
	for _, bad := range []string{"", "abc", "ecc11607-5e24-6b7c-9e46", "zzc11607-5e24-6b7c-9e46-01ca5290922f",
		"ecc116075-e24-6b7c-9e46-01ca5290922f"} {
		if validUDN(bad) {
			t.Errorf("%q 不该通过", bad)
		}
	}
}

// 多网卡机器上"挑哪个 IP 宣告"决定了电视能不能连上：
// 挑到 Hyper-V 的 172.x 虚拟地址，电视会一直转圈然后放弃。
func TestIsVirtualIface(t *testing.T) {
	virtual := []string{
		"vEthernet (Default Switch)",
		"VMware Network Adapter VMnet8",
		"VirtualBox Host-Only Network",
		"docker0",
		"br-1a2b3c",
		"Tailscale",
		"wsl",
	}
	for _, n := range virtual {
		if !isVirtualIface(n) {
			t.Errorf("%q 应判为虚拟网卡", n)
		}
	}
	real := []string{"WLAN", "以太网", "Ethernet", "Wi-Fi", "enp3s0", "eth0"}
	for _, n := range real {
		if isVirtualIface(n) {
			t.Errorf("%q 是物理网卡，不该被排除", n)
		}
	}
}

func TestIsPrivateIPv4(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.10": true,
		"10.0.0.5":      true,
		"172.16.0.1":    true,
		"172.31.208.1":  true,
		"172.32.0.1":    false, // 172.32 已出 RFC1918 范围
		"8.8.8.8":       false,
		"169.254.1.1":   false,
	}
	for s, want := range cases {
		if got := isPrivateIPv4(net.ParseIP(s)); got != want {
			t.Errorf("%s 判定应为 %v，实际 %v", s, want, got)
		}
	}
}

// lanIPv4 必须给一个能对外用的地址，不能是回环。
func TestLanIPv4NotLoopback(t *testing.T) {
	if got := lanIPv4(); got == "127.0.0.1" {
		t.Skip("这台机器没有可用的局域网地址（CI 容器里正常）")
	} else if !isPrivateIPv4(net.ParseIP(got)) {
		t.Logf("挑到非私网地址 %s，仅提示，不判失败", got)
	}
}
