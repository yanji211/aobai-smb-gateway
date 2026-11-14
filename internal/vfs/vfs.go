// Package vfs 是三个协议面的公共下层：路径规范化、白名单校验、穿越防护。
// 所有校验集中在这一个地方，不允许各协议各写一套（见 docs/01 第 8 节）。
package vfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"fsgw/internal/index"
	"fsgw/internal/platform"
)

var (
	ErrEscape    = errors.New("vfs: 路径试图跳出共享根")
	ErrIllegal   = errors.New("vfs: 路径包含非法字符")
	ErrNotShared = errors.New("vfs: 路径不在任何共享根内")
	ErrTooLong   = errors.New("vfs: 路径过长")
	ErrReadOnly  = errors.New("vfs: 该目录只读")
)

// Share 是一个共享根。
type Share struct {
	ShareID  string
	Name     string
	Root     string
	Writable bool
	Media    bool
}

type Resolved struct {
	Share Share
	Rel   string // 相对路径，正斜杠，保留原始大小写；根为 ""
	Key   string // 查询键：小写、正斜杠、无前后斜杠
	Abs   string // 绝对 Windows 路径
}

type VFS struct {
	shares []Share
	byName map[string]Share
}

func New(shares []Share) *VFS {
	v := &VFS{shares: shares, byName: map[string]Share{}}
	for _, s := range shares {
		v.byName[strings.ToLower(s.Name)] = s
	}
	return v
}

func (v *VFS) Shares() []Share { return v.shares }

func (v *VFS) ShareByName(name string) (Share, bool) {
	s, ok := v.byName[strings.ToLower(name)]
	return s, ok
}

// windowsReserved 是 Windows 上不能作为文件名的设备名。
var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true,
	"lpt1": true, "lpt2": true, "lpt3": true,
}

// CheckComponent 校验单个路径分量。
func CheckComponent(name string) error {
	if name == "" {
		return ErrIllegal
	}
	if name == "." || name == ".." {
		return ErrEscape
	}
	if strings.ContainsAny(name, `*?"<>|`) {
		return ErrIllegal
	}
	// 冒号在 NTFS 上意味着备用数据流（ADS），一律拒绝。
	if strings.Contains(name, ":") {
		return fmt.Errorf("%w: 不允许备用数据流 (ADS)", ErrIllegal)
	}
	// Windows 会静默去掉末尾的空格和点，直接拒绝而不是悄悄改名。
	if strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("%w: 名称不能以空格或点结尾", ErrIllegal)
	}
	base := name
	if i := strings.Index(base, "."); i >= 0 {
		base = base[:i]
	}
	if windowsReserved[strings.ToLower(base)] {
		return fmt.Errorf("%w: 使用了保留设备名 %s", ErrIllegal, name)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: 非法 UTF-8", ErrIllegal)
	}
	return nil
}

// FromURLPath 把 WebDAV 的 URL 路径（/<共享名>/<rel>）解析成共享内路径。
func (v *VFS) FromURLPath(urlPath string) (Resolved, error) {
	p := strings.TrimPrefix(urlPath, "/")
	if p == "" {
		return Resolved{}, ErrNotShared
	}
	parts := strings.Split(p, "/")
	name := parts[0]
	share, ok := v.ShareByName(name)
	if !ok {
		return Resolved{}, fmt.Errorf("%w: 未知共享 %q", ErrNotShared, name)
	}
	rel := strings.Join(parts[1:], "/")
	return v.Resolve(share, rel)
}

// Resolve 校验相对路径并给出绝对路径。
func (v *VFS) Resolve(share Share, rel string) (Resolved, error) {
	rel = strings.ReplaceAll(rel, `\`, "/")
	rel = strings.TrimPrefix(rel, "/")
	for strings.HasSuffix(rel, "/") {
		rel = strings.TrimSuffix(rel, "/")
	}
	if rel != "" {
		for _, seg := range strings.Split(rel, "/") {
			if err := CheckComponent(seg); err != nil {
				return Resolved{}, err
			}
		}
	}
	abs := share.Root
	if rel != "" {
		abs = filepath.Join(share.Root, filepath.FromSlash(rel))
	}
	if len(abs) > 32000 {
		return Resolved{}, ErrTooLong
	}
	// 二次确认：拼出来的绝对路径必须仍在共享根内。
	if !within(share.Root, abs) {
		return Resolved{}, ErrEscape
	}
	return Resolved{Share: share, Rel: rel, Key: index.KeyOf(rel), Abs: abs}, nil
}

func within(root, p string) bool {
	rootAbs, err1 := filepath.Abs(root)
	pAbs, err2 := filepath.Abs(p)
	if err1 != nil || err2 != nil {
		return false
	}
	rootAbs = strings.ToLower(filepath.Clean(rootAbs))
	pAbs = strings.ToLower(filepath.Clean(pAbs))
	if rootAbs == pAbs {
		return true
	}
	return strings.HasPrefix(pAbs, rootAbs+string(os.PathSeparator))
}

// IsWritable 判断某相对路径是否可写。子目录默认继承父级，允许显式覆盖。
func (v *VFS) IsWritable(r Resolved, overrides map[string]bool) bool {
	if !r.Share.Writable {
		return false
	}
	// 最长前缀匹配：越接近具体路径的规则优先。
	best, bestLen := r.Share.Writable, -1
	for path, w := range overrides {
		key := index.KeyOf(path)
		if key == "" {
			if bestLen < 0 {
				best, bestLen = w, 0
			}
			continue
		}
		if r.Key == key || strings.HasPrefix(r.Key, key+"/") {
			if runeLen(key) > bestLen {
				best, bestLen = w, runeLen(key)
			}
		}
	}
	return best
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

// EnsureLongPath 供调用方在真正访问磁盘前使用。
func EnsureLongPath(p string) string { return platform.LongPath(p) }
