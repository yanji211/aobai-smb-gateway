package config

// 客户端账号表单独存一个文件（smb_clients.yaml），不塞进 config.yaml。
//
// 原因很实际：面板上增删账号要频繁写文件，而 config.yaml 里全是手写的注释和
// 排版，yaml.Marshal 整文件重写一次就把注释全丢了。单独一个文件既好写、
// 也好备份、也好手工编辑。
//
// 口令不落盘：文件里只有 NT 哈希（NTOWFv1）。这是 NTLM 校验的必然要求，
// 也是能给出的最大程度的保护——拿到哈希仍然可以离线爆破，所以这个文件
// 按 0600 写，别放到共享目录里。

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// clientsFileName 是账号表文件名，固定放在 config.yaml 同目录。
const clientsFileName = "smb_clients.yaml"

// SMBClient 是一个登记过的 SMB 客户端账号。
type SMBClient struct {
	Name string `yaml:"name"`
	// NTHash 是 NTOWFv1 的十六进制（32 位）。可用 `fsgw smb nt-hash <口令>` 生成。
	NTHash  string `yaml:"nt_hash"`
	Note    string `yaml:"note,omitempty"`
	AddedAt string `yaml:"added_at,omitempty"`
}

type smbClientsFile struct {
	Clients []SMBClient `yaml:"clients"`
}

// ClientsPath 返回账号表文件路径（与 config.yaml 同目录）。
func ClientsPath(configPath string) string {
	if configPath == "" {
		return clientsFileName
	}
	return filepath.Join(filepath.Dir(configPath), clientsFileName)
}

// LoadClients 读取账号表。文件不存在视为空表（不是错误）。
func LoadClients(configPath string) ([]SMBClient, error) {
	p := ClientsPath(configPath)
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取 %s: %w", p, err)
	}
	var f smbClientsFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", p, err)
	}
	return f.Clients, nil
}

// SaveClients 原子写回账号表（临时文件 + rename，权限 0600）。
func SaveClients(configPath string, list []SMBClient) error {
	p := ClientsPath(configPath)
	out := append([]SMBClient(nil), list...)
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})

	head := "# 由控制台维护的 SMB 客户端账号表。\n" +
		"# 在控制台增删账号会自动重写本文件；手工改也行，改完重启 fsgw 生效。\n" +
		"# 这里只有 NT 哈希（NTOWFv1）没有明文口令。生成哈希：fsgw smb nt-hash <口令>\n"
	body, err := yaml.Marshal(smbClientsFile{Clients: out})
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(head), body...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
