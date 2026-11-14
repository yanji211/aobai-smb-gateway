package main

import (
	"reflect"
	"strings"
	"testing"

	"fsgw/internal/config"
)

// 提权走 ShellExecuteW，参数是一整串字符串；路径带空格时漏了引号，
// 用户点了「接管」就会什么都没发生，和原来的"没反应"一样难查。
func TestTakeoverParams(t *testing.T) {
	cases := []struct {
		name                string
		cfg                 string
		noTray, openUI, gui bool
		want                string
	}{
		{"最简（双击路径）", "", false, true, true, "takeover -open -gui"},
		{"带空格路径", `C:\a b\config.yaml`, true, false, false, `takeover -config "C:\a b\config.yaml" -notray`},
		{"全开", `D:\x\config.yaml`, true, true, true, `takeover -config "D:\x\config.yaml" -notray -open -gui`},
	}
	for _, c := range cases {
		got := takeoverParams(c.cfg, c.noTray, c.openUI, c.gui)
		if got != c.want {
			t.Errorf("%s: 得到 %q，期望 %q", c.name, got, c.want)
		}
	}
}

// 同一组开关在 argv 形式里必须和字符串形式一一对应。
func TestTakeoverArgs(t *testing.T) {
	got := takeoverArgs(`C:\a b\config.yaml`, true, true, true)
	want := []string{"-config", `C:\a b\config.yaml`, "-notray", "-open", "-gui"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("得到 %#v，期望 %#v", got, want)
	}
}

func TestFirstShareRoot(t *testing.T) {
	cfg := &config.Config{Path: `C:\pkg\config.yaml`, Shares: []config.Share{{Root: `C:\pkg\share`}}}
	if got := firstShareRoot(cfg); got != `C:\pkg\share` {
		t.Errorf("有共享配置时应返回配置值，得到 %q", got)
	}
	cfg.Shares = nil
	if got := firstShareRoot(cfg); !strings.HasSuffix(got, "share") {
		t.Errorf("无共享配置时应回退到包内 share，得到 %q", got)
	}
}

// 对话框必须把"没反应的原因"和两个按钮各自的后果都讲清楚。
func TestConflictMessage(t *testing.T) {
	cfg := &config.Config{
		Path:   `C:\pkg\config.yaml`,
		UI:     config.UI{Bind: "0.0.0.0:8444"},
		Shares: []config.Share{{Root: `C:\pkg\share`}},
	}
	msg := conflictMessage(cfg, "http://127.0.0.1:8444/")
	for _, want := range []string{"已经有", "没反应", "【是】", "【否】", `C:\pkg\share`, "http://127.0.0.1:8444/"} {
		if !strings.Contains(msg, want) {
			t.Errorf("提示文案缺少 %q", want)
		}
	}
}

// 非交互场景（CLI / 计划任务 / 服务端）绝不能弹框，否则进程会永久挂住。
func TestAskConflictSkippedWhenGUIOff(t *testing.T) {
	if got := askConflict("t", "b", false); got != choiceSkip {
		t.Errorf("allowGUI=false 应返回 choiceSkip，得到 %v", got)
	}
}
