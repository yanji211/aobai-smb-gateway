package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 换共享根是"只改一行、其余原样"的操作：注释、别的共享、行尾说明都不能动。
// 这条测试守的就是这个承诺——整文件重写会把注释吃光，用户下次改配置就全靠猜。
func TestSaveShareRootKeepsEverythingElse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	src := `version: 1

# 数据目录：不要放进共享里
data_dir: /var/lib/fsgw

shares:
  - share_id: main
    root: /srv/share        # 原来的位置
    name: share
    writable: true

  - share_id: photo
    root: /srv/photo
    name: photo

# 这一段注释必须留着
index:
  debounce_content_ms: 400
`
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &Config{Path: p}
	if err := c.SaveShareRoot(p, "main", "/srv/new share"); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)

	for _, want := range []string{
		`root: '/srv/new share'`, // 含空格要加引号，否则 YAML 读回来会变样
		`root: /srv/photo`,       // 另一个共享没被顺手改掉
		"# 原来的位置",                // 行尾说明跟着走
		"# 这一段注释必须留着",
		"# 数据目录：不要放进共享里",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("结果里缺少 %q：\n%s", want, got)
		}
	}

	// 改完必须是能解析的 YAML，且值确实是新目录。
	// 这里不用 Load：它连目录存不存在、口令设没设都验，跟本次改动无关。
	var back Config
	if err := yaml.Unmarshal(raw, &back); err != nil {
		t.Fatalf("改完的配置读不回来: %v\n%s", err, got)
	}
	if len(back.Shares) != 2 {
		t.Fatalf("共享数量变了: %d", len(back.Shares))
	}
	if back.Shares[0].Root != "/srv/new share" {
		t.Fatalf("root 没生效: %q", back.Shares[0].Root)
	}
	if back.Shares[1].Root != "/srv/photo" {
		t.Fatalf("另一个共享被改了: %q", back.Shares[1].Root)
	}
}

// Windows 路径里的反斜杠在 YAML 双引号里必须转义，否则读回来会少字符。
func TestSaveShareRootWindowsPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	src := "shares:\n  - share_id: main\n    root: D:\\old\n    name: share\n"
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &Config{Path: p}
	if err := c.SaveShareRoot(p, "main", `D:\新 目录\照片`); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := yaml.Unmarshal(raw, &back); err != nil {
		t.Fatalf("读不回来: %v\n%s", err, raw)
	}
	if back.Shares[0].Root != `D:\新 目录\照片` {
		t.Fatalf("路径被改坏了: %q", back.Shares[0].Root)
	}
}

// 界面改目录（app.ValidateShareRoot）和启动校验（Config.Validate）
// 必须用同一套规则。这条测试盯的就是"界面改得动、重启起不来"那个坑：
// 用户目录曾经被整条禁掉，结果共享桌面上的文件夹改完就再也启动不了。
func TestCheckShareRoot(t *testing.T) {
	ok := []string{
		`D:/media`,
		`D:/docs`,
		`D:/share`,
		`D:/共享/照片`,
	}
	for _, p := range ok {
		if err := CheckShareRoot(p); err != nil {
			t.Errorf("%s 应该允许共享，却报了 %v", p, err)
		}
	}

	bad := map[string]string{
		`C:/`:                         "整个系统盘",
		`C:/Windows`:                  "系统目录",
		`C:/Windows/System32/drivers`: "系统目录下的子目录",
		`C:/Program Files\Some`:       "程序目录",
		`C:/Users`:                    "整个 Users",
		`C:/Users/example-user`:           "整个用户目录",
	}
	for p, why := range bad {
		if err := CheckShareRoot(p); err == nil {
			t.Errorf("%s（%s）应该被拒绝", p, why)
		}
	}
}

// 改设备名同样"只动一行"：dlna 段里的其它键、注释、别的段都不能变。
// 界面上点一下「改名」就会走这条路径，写坏了整份配置就废了。
func TestSaveDLNAFriendlyName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	src := `version: 1
data_dir: /var/lib/fsgw

dlna:
  enabled: true
  http_port: 8200
  friendly_name: 家庭共享   # 电视里显示的名字

# 下面这段注释必须留着
index:
  debounce_content_ms: 400
`
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &Config{Path: p}
	if err := c.SaveDLNAFriendlyName(p, "书房 共享"); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "friendly_name: '书房 共享'") {
		t.Errorf("没有写入新名字:\n%s", got)
	}
	if !strings.Contains(got, "# 电视里显示的名字") {
		t.Errorf("行尾注释被吃掉了:\n%s", got)
	}
	for _, keep := range []string{"http_port: 8200", "enabled: true", "# 下面这段注释必须留着"} {
		if !strings.Contains(got, keep) {
			t.Errorf("不该改动的内容丢了: %q\n%s", keep, got)
		}
	}

	// 必须还能被正常解析，且只改了名字。
	var back Config
	if err := yaml.Unmarshal(raw, &back); err != nil {
		t.Fatalf("改完的配置解析不了: %v", err)
	}
	if back.DLNA.FriendlyName != "书房 共享" {
		t.Errorf("解析后名字是 %q", back.DLNA.FriendlyName)
	}
	if back.DLNA.HTTPPort != 8200 {
		t.Errorf("端口不该变，实际 %d", back.DLNA.HTTPPort)
	}
}

// 配置里本来没有 friendly_name（用默认名）时，得能就地插一行，
// 而不是整份重写或者干脆不写。
func TestSaveDLNAFriendlyNameInserts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	src := `version: 1
data_dir: /var/lib/fsgw

dlna:
  enabled: true
  http_port: 8200

smb:
  enabled: true
`
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &Config{Path: p}
	if err := c.SaveDLNAFriendlyName(p, "客厅"); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(p)
	var back Config
	if err := yaml.Unmarshal(raw, &back); err != nil {
		t.Fatalf("插行后解析失败: %v\n%s", err, raw)
	}
	if back.DLNA.FriendlyName != "客厅" {
		t.Errorf("插行没生效，得到 %q\n%s", back.DLNA.FriendlyName, raw)
	}
	if back.SMB.Enabled != true {
		t.Error("插行不该影响后面的段")
	}
	// 插进去的行必须还在 dlna 段里（缩进对了），不能跑到顶层变成 dlna.friendly_name 的兄弟。
	if !strings.Contains(string(raw), "  friendly_name:") {
		t.Errorf("缩进不对:\n%s", raw)
	}
}
