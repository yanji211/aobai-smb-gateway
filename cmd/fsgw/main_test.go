package main

import (
	"reflect"
	"strings"
	"testing"
)

// 提权命令行拼错，用户双击后只会看到 UAC 一闪然后什么都没起来，
// 所以把这几个组合钉死。
func TestElevateParams(t *testing.T) {
	cases := []struct {
		name   string
		cfg    string
		noTray bool
		detach bool
		openUI bool
		want   string
	}{
		{"最简（双击路径）", "", false, true, true, "run -elevate -detach -open"},
		{"前台带配置", `D:\a b\config.yaml`, false, false, false, `run -elevate -config "D:\a b\config.yaml"`},
		{"后台无托盘", "", true, true, false, "run -elevate -notray -detach"},
		{"全开", `D:\x\config.yaml`, true, true, true, `run -elevate -config "D:\x\config.yaml" -notray -detach -open`},
	}
	for _, c := range cases {
		got := elevateParams(c.cfg, c.noTray, c.detach, c.openUI)
		if got != c.want {
			t.Errorf("%s: 得到 %q，期望 %q", c.name, got, c.want)
		}
		// 提权参数里必须带上 -elevate，否则子进程再检查一遍又要弹 UAC。
		if !strings.HasPrefix(got, "run -elevate") {
			t.Errorf("%s: 缺少 run -elevate 前缀: %q", c.name, got)
		}
	}
}

func TestDetachArgv(t *testing.T) {
	cases := []struct {
		name      string
		cfg       string
		noTray    bool
		openUI    bool
		noElevate bool
		want      []string
	}{
		{"最简", "", false, false, false, []string{"run", "-daemon"}},
		{"带配置", "config.yaml", false, false, false, []string{"run", "-daemon", "-config", "config.yaml"}},
		{"无托盘并开页面", "config.yaml", true, true, false, []string{"run", "-daemon", "-config", "config.yaml", "-notray", "-open"}},
		{"提权被否", "config.yaml", false, true, true, []string{"run", "-daemon", "-config", "config.yaml", "-open", "-noelevate"}},
	}
	for _, c := range cases {
		got := detachArgv(c.cfg, c.noTray, c.openUI, c.noElevate)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: 得到 %v，期望 %v", c.name, got, c.want)
		}
		// -daemon 必须在：否则子进程会再转一次后台，无限套娃。
		if len(got) < 2 || got[1] != "-daemon" {
			t.Errorf("%s: 缺少 -daemon 标记: %v", c.name, got)
		}
	}
}
