// Package syncsvc 实现「快同步」的服务端：一条为批量传输而设计的 HTTP 协议。
//
// 它不替代 SMB，而是补 SMB 补不上的三件事：
//
//  1. 单文件并行：SMB 一条会话里的请求是串行的，客户端开多线程也只是排队；
//     这里每个块都是独立 PUT，同一个文件可以被多条连接同时写不同偏移。
//  2. 小文件合并：几百个 2KB 的文件走一次请求（bundle 帧），而不是几百次往返。
//  3. 断点续传：块落盘即记账（.map 位图），进程崩了、网断了，重跑只补缺的块。
//
// 落盘语义：先写 <root>/.fsgw-sync/<sid>/<fid>.part，全部块到齐、fsync 之后
// 才 rename 到最终路径。所以目标文件要么是旧的完整版本，要么是新的完整版本，
// 永远不会出现"半个文件"。
package syncsvc

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// stagingDirName 是暂存目录名，位于共享根内部（必须同一文件系统才能 rename）。
// 它被索引器跳过，不出现在共享列表里。
const stagingDirName = ".fsgw-sync"

// normalizeRel 把客户端给的文件路径规整成"相对路径"，并挡掉所有越界写法。
// 客户端可能来自 Windows（反斜杠）或 Linux（正斜杠），也可能被恶意构造。
func normalizeRel(rel string) (string, error) {
	r := strings.TrimSpace(rel)
	if r == "" {
		return "", fmt.Errorf("路径为空")
	}
	r = strings.ReplaceAll(r, "\\", "/")
	if strings.HasPrefix(r, "/") {
		return "", fmt.Errorf("不接受绝对路径：%s", rel)
	}
	// Windows 盘符 / UNC 残片
	if len(r) >= 2 && r[1] == ':' {
		return "", fmt.Errorf("不接受盘符路径：%s", rel)
	}
	r = path.Clean(r)
	if r == "." || r == ".." || strings.HasPrefix(r, "../") {
		return "", fmt.Errorf("路径越界：%s", rel)
	}
	for _, seg := range strings.Split(r, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("路径非法：%s", rel)
		}
		if strings.EqualFold(seg, stagingDirName) {
			return "", fmt.Errorf("不能同步到保留目录 %s", stagingDirName)
		}
		// 控制字符会让日志与审计记录不可读，也常有注入意图。
		for _, c := range seg {
			if c < 0x20 || c == 0x7f {
				return "", fmt.Errorf("路径含控制字符：%q", rel)
			}
		}
	}
	if len(r) > 2048 {
		return "", fmt.Errorf("路径过长：%d 字节", len(r))
	}
	return r, nil
}

// resolveUnder 把 root + dest + rel 合成绝对路径，并再次确认它没有跑出 root。
// 光靠 normalizeRel 不够：dest 本身来自请求体，也要走一遍。
func resolveUnder(root, dest, rel string) (string, error) {
	d, err := normalizeRelOrEmpty(dest)
	if err != nil {
		return "", err
	}
	r, err := normalizeRel(rel)
	if err != nil {
		return "", err
	}
	full := filepath.Join(root, filepath.FromSlash(d), filepath.FromSlash(r))
	// 最后一道：用相对路径回算，确认没有 .. 逃逸（含大小写/分隔符差异）。
	back, err := filepath.Rel(root, full)
	if err != nil {
		return "", fmt.Errorf("路径解析失败：%w", err)
	}
	if back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("路径越界：%s", rel)
	}
	return full, nil
}

func normalizeRelOrEmpty(v string) (string, error) {
	if strings.TrimSpace(v) == "" {
		return "", nil
	}
	return normalizeRel(v)
}

// stagingPath 返回某次会话里某个文件的暂存路径。
func stagingPath(root, sid, fid string) string {
	return filepath.Join(root, stagingDirName, sid, fid+".part")
}

func stagingMapPath(root, sid, fid string) string {
	return filepath.Join(root, stagingDirName, sid, fid+".map")
}

func sessionStagingDir(root, sid string) string {
	return filepath.Join(root, stagingDirName, sid)
}
