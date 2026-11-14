package main

// fsgw clean-meta：清掉 macOS 在共享目录里留下的影子文件。
//
// 这些文件是 mac 自己写的（.DS_Store / ._xxx / .Trashes / .Spotlight-V100 …，
// 详见 internal/smbgo/applemeta.go）。服务端默认只在列目录里把它们藏起来，
// 磁盘上照旧留着——因为删掉会丢 mac 的窗口布局与 Finder 标签。
// 真到了"文件太多、备份太脏"的时候，用这条命令扫一遍清掉：
//
//	fsgw clean-meta                  # 只列清单（默认，不动文件）
//	fsgw clean-meta -v               # 清单逐条打印
//	fsgw clean-meta -force           # 真删
//	fsgw clean-meta -force -config /etc/fsgw/config.yaml
//
// 只删命中白名单的名字，且只删共享根之内的东西。符号链接不跟随——
// WalkDir 本身不跟随目录软链，命中白名单的链接按"文件"处理（删链接本身）。

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"fsgw/internal/smbgo"
)

type metaStats struct {
	files   int
	dirs    int
	bytes   int64
	failed  int
	removed int
	skipped int
}

func cmdCleanMeta(args []string) int {
	cfg, rest, err := loadConfig(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fset := flag.NewFlagSet("clean-meta", flag.ContinueOnError)
	dryRun := fset.Bool("dry-run", false, "只列清单（默认行为，预留此开关便于脚本显式表达意图）")
	force := fset.Bool("force", false, "真的删除（不加只列清单）")
	verbose := fset.Bool("v", false, "逐条打印命中项")
	if err := fset.Parse(rest); err != nil {
		return 2
	}
	doDelete := *force && !*dryRun

	if len(cfg.Shares) == 0 {
		fmt.Fprintln(os.Stderr, "配置里没有共享，没什么可清的")
		return 1
	}

	var total metaStats
	for _, sh := range cfg.Shares {
		root := sh.Root
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			fmt.Printf("跳过 %s（共享根不存在或不是目录：%v）\n", root, err)
			total.skipped++
			continue
		}
		fmt.Printf("共享 %s → %s\n", sh.Name, root)
		st := metaStats{}
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				// 单个目录读不了（权限/被删）不该中断整轮扫描。
				st.failed++
				if *verbose {
					fmt.Printf("  读取失败 %s: %v\n", p, err)
				}
				return nil
			}
			if p == root || !smbgo.IsAppleMetaName(d.Name()) {
				return nil
			}
			isDir := d.IsDir()
			size := int64(0)
			if isDir {
				size = dirSize(p)
			} else if fi, err := d.Info(); err == nil {
				size = fi.Size()
			}
			if isDir {
				st.dirs++
			} else {
				st.files++
			}
			st.bytes += size
			if *verbose || !doDelete {
				mark := ""
				if !doDelete {
					mark = "（将删除）"
				}
				fmt.Printf("  %s%s  %s\n", humanSize(size), mark, relPath(root, p))
			}
			if doDelete {
				if err := os.RemoveAll(p); err != nil {
					st.failed++
					fmt.Fprintf(os.Stderr, "  删除失败 %s: %v\n", p, err)
				} else {
					st.removed++
				}
			}
			if isDir {
				return fs.SkipDir // 整棵树已经处理过（或已删除）
			}
			return nil
		})
		if walkErr != nil {
			fmt.Fprintf(os.Stderr, "  扫描中断: %v\n", walkErr)
		}
		if doDelete {
			fmt.Printf("  已删除 %d 项（%d 个文件 + %d 个目录），释放 %s\n",
				st.removed, st.files, st.dirs, humanSize(st.bytes))
		} else {
			fmt.Printf("  命中 %d 个文件 + %d 个目录，合计 %s\n", st.files, st.dirs, humanSize(st.bytes))
		}
		if st.failed > 0 {
			fmt.Printf("  失败/跳过 %d 项\n", st.failed)
		}
		total.files += st.files
		total.dirs += st.dirs
		total.bytes += st.bytes
		total.failed += st.failed
		total.removed += st.removed
	}

	fmt.Println()
	if doDelete {
		fmt.Printf("合计：删除 %d 项（%d 文件 + %d 目录），释放 %s\n", total.removed, total.files, total.dirs, humanSize(total.bytes))
	} else {
		fmt.Printf("合计：%d 个文件 + %d 个目录，%s。加 -force 才会真的删。\n", total.files, total.dirs, humanSize(total.bytes))
		fmt.Println("提示：想让 mac 以后不再写这些文件，在 mac 上执行一次（重启 Finder 生效）：")
		fmt.Println("  defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true")
	}
	if total.failed > 0 {
		return 1
	}
	return 0
}

// dirSize 统计一棵子树的大小。命中白名单的目录（.Trashes 之类）通常不大，
// 但里面可能是几十万个已删文件的副本，所以要能报出真实体积。
func dirSize(root string) int64 {
	var n int64
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			n += fi.Size()
		}
		return nil
	})
	return n
}

// relPath 把绝对路径裁成相对共享根的形式，清单更好读。
func relPath(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return r
	}
	return p
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}
