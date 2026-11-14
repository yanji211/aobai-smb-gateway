package smbgo

import "strings"

// macOS 的"影子文件"过滤。
//
// 为什么会有这些文件：macOS 把 HFS+/APFS 的元数据（窗口位置、图标布局、
// 资源分叉、扩展属性、废纸篓、Spotlight 索引）往任何非 Apple 卷上写一份
// 平铺副本，因为 SMB 卷没有 HFS+ 的属性空间。名字都是固定的：
//
//	.DS_Store                          Finder 的图标位置/窗口大小/排序方式
//	._foo.txt                          foo.txt 的 AppleDouble（资源分叉 + xattr）
//	.Trashes/ .TemporaryItems/         废纸篓与"移到废纸篓"的暂存
//	.Spotlight-V100/ .fseventsd/       Spotlight 索引与文件系统事件日志
//	.DocumentRevisions-V100/           版本浏览
//	.apdisk  .VolumeIcon.icns          网络卷图标与 AirPort 标记
//
// 对 Windows / Linux 客户端来说这些就是垃圾：资源管理器里满屏 "._xxx"，
// 复制目录时数量翻倍，备份与索引也跟着变脏。
//
// 处理策略（三层，见 README「Apple 元数据」）：
//  1. 列目录时过滤（默认开）——所有接入端都看不到。文件仍在磁盘上，mac 自己
//     按名字直接 OPEN，不依赖目录枚举，所以它的图标/标签照常工作；
//  2. 存量清理——`fsgw clean-meta` 扫描共享根删掉它们（先 --dry-run 看清单）；
//  3. mac 侧一劳永逸——`defaults write com.apple.desktopservices \
//     DSDontWriteNetworkStores -bool true`，Finder 从此不再往网络卷写
//     .DS_Store（Apple 官方开关，对 SMB 卷生效，重启 Finder 后起作用）。

// appleMetaNames 是"整名匹配"的那部分。全部小写存放，比对时把入参转小写：
// 这些名字在 HFS+/APFS 上大小写不敏感，实际出现过 .ds_store / .DS_STORE 混写。
var appleMetaNames = map[string]struct{}{
	".ds_store":                           {},
	".trashes":                            {},
	".temporaryitems":                     {},
	".spotlight-v100":                     {},
	".fseventsd":                          {},
	".documentrevisions-v100":             {},
	".apdisk":                             {},
	".volumeicon.icns":                    {},
	".com.apple.timemachine.donotpresent": {},
	".applefile":                          {}, // AppleDouble v2 的独立文件形态
	".appledouble":                        {},
}

// IsAppleMetaName 判断一个名字（也可以是完整路径）是不是 macOS 写的元数据。
//
// 路径形态也要认：`.Trashes/501/foo.pdf` 里的叶子是普通文件，但它躺在 mac 的
// 废纸篓里，整条路径同样属于元数据。判断按"任一段命中"来做。
func IsAppleMetaName(name string) bool {
	if name == "" {
		return false
	}
	// 热路径（目录枚举里绝大多数是裸名字）先走零分配的快速分支。
	if lastPathSep(name) < 0 {
		return isAppleMetaLeaf(name)
	}
	for _, seg := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if isAppleMetaLeaf(seg) {
			return true
		}
	}
	return false
}

// isAppleMetaLeaf 只判断最后一段（不带路径分隔符的名字）。
func isAppleMetaLeaf(name string) bool {
	if name == "" {
		return false
	}
	// `._` 前缀是 AppleDouble 的命名约定，要求点+下划线之后还有内容——
	// 一个恰好叫 "._" 的文件不常见，但也没必要为它特判。
	if len(name) > 2 && strings.HasPrefix(name, "._") {
		return true
	}
	_, ok := appleMetaNames[strings.ToLower(name)]
	return ok
}

// lastPathSep 返回最后一个路径分隔符的位置（Windows 与 POSIX 都算）。
func lastPathSep(s string) int {
	return strings.LastIndexAny(s, `/\`)
}

// hidesAppleMeta 判断这条连接要不要在目录枚举里剔掉 mac 的影子文件。
//
// 默认（hide / 未配置）只对"非 mac"隐藏：Windows、Linux、电视看到的是干净
// 目录，mac 自己照旧看得见——这点很关键。mac 找不到 .DS_Store 时不会认为
// "本来就没有"，而是每次进目录都新建一个再写一遍，结果是浏览一次写一次、
// 磁盘上小文件写入放大，而 Finder 的窗口布局反而存不住。
func (st *connState) hidesAppleMeta() bool {
	switch st.appleMeta {
	case "off":
		return false
	case "all":
		return true
	default: // "" 或 "hide"
		return st.client.Kind != ClientMacOS
	}
}

// filterAppleMeta 把 mac 元数据从目录项里剔掉，返回过滤后的切片与被剔掉的条数。
//
// 原地压缩（复用底层数组）而不是新建：目录枚举是热路径，大目录一次几千条，
// 每条都 append 一份 name 会白白复制几百 KB。
func filterAppleMeta(entries []dirEnt) ([]dirEnt, int) {
	out := entries[:0]
	for i := range entries {
		if IsAppleMetaName(utf16le(entries[i].name)) {
			continue
		}
		out = append(out, entries[i])
	}
	return out, len(entries) - len(out)
}
