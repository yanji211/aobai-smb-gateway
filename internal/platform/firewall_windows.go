//go:build windows

package platform

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// Rule 描述一条入站放行规则。名字统一带 FSGW- 前缀，便于人工核查与一键清理。
type Rule struct {
	Name    string
	Proto   string // tcp | udp
	Port    int
	Remote  string // LocalSubnet | Any
	Profile string // private | domain,private
}

func (r Rule) String() string {
	return fmt.Sprintf("%s %s/%d %s", r.Name, strings.ToUpper(r.Proto), r.Port, r.Remote)
}

func netsh(args ...string) (string, error) {
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// Ensure 幂等：先按名字删除再新增，避免重复规则堆积。
func EnsureRules(rules []Rule) error {
	for _, r := range rules {
		netsh("advfirewall", "firewall", "delete", "rule", "name="+r.Name)
		out, err := netsh("advfirewall", "firewall", "add", "rule",
			"name="+r.Name,
			"dir=in",
			"action=allow",
			"protocol="+strings.ToUpper(r.Proto),
			"localport="+strconv.Itoa(r.Port),
			"remoteip="+r.Remote,
			"profile="+r.Profile,
			"enable=yes",
		)
		if err != nil {
			return fmt.Errorf("添加防火墙规则 %s 失败（需要管理员权限）: %v %s", r.Name, err, strings.TrimSpace(out))
		}
	}
	return nil
}

func RemoveByPrefix(prefix string) error {
	names, err := List(prefix)
	if err != nil {
		return err
	}
	var lastErr error
	for _, n := range names {
		if _, err := netsh("advfirewall", "firewall", "delete", "rule", "name="+n); err != nil {
			lastErr = fmt.Errorf("删除防火墙规则 %s 失败（需要管理员权限）: %v", n, err)
		}
	}
	return lastErr
}

// List 返回当前存在的、以 prefix 开头的规则名。
func List(prefix string) ([]string, error) {
	out, err := netsh("advfirewall", "firewall", "show", "rule", "name=all")
	if err != nil && !strings.Contains(out, "Rule Name") {
		return nil, fmt.Errorf("读取防火墙规则失败: %v", err)
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Rule Name:") {
			continue
		}
		n := strings.TrimSpace(strings.TrimPrefix(line, "Rule Name:"))
		if strings.HasPrefix(n, prefix) {
			names = append(names, n)
		}
	}
	return names, nil
}

// FirewallRules 返回某个开关状态应存在的规则集合。
// FirewallRules 返回该状态需要的放行规则。extra 用来追加"配置决定端口"的服务
// （比如快同步的 8445 可能被改成别的端口），这样规则跟着配置走，而不是写死两份。
func FirewallRules(state string, extra ...Rule) []Rule {
	var rules []Rule
	if state == "LAN" || state == "ALL" {
		rules = append(rules,
			Rule{Name: "FSGW-SMB-445", Proto: "tcp", Port: 445, Remote: "LocalSubnet", Profile: "private"},
			Rule{Name: "FSGW-DLNA-1900", Proto: "udp", Port: 1900, Remote: "LocalSubnet", Profile: "private"},
			Rule{Name: "FSGW-DLNA-8200", Proto: "tcp", Port: 8200, Remote: "LocalSubnet", Profile: "private"},
		)
	}
	if state == "WAN" || state == "ALL" {
		rules = append(rules, Rule{Name: "FSGW-WEBDAV-8443", Proto: "tcp", Port: 8443, Remote: "Any", Profile: "private"})
	}
	if state == "LAN" || state == "ALL" {
		rules = append(rules, extra...)
	}
	return rules
}
