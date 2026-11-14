package vfs

import (
	"strings"
	"testing"

	"fsgw/internal/index"
)

func testVFS() *VFS {
	return New([]Share{{ShareID: "main", Name: "share", Root: `D:\share`, Writable: true}})
}

// 穿越与非法名必须全部被拒（docs/03 T-40）。
func TestRejectIllegal(t *testing.T) {
	v := testVFS()
	cases := []string{
		`..\..\Windows\System32\cmd.exe`,
		`a/../../etc/passwd`,
		`file.txt:stream`,
		`CON`,
		`nul`,
		`com1`,
		`trailing `,
		`dot.`,
		`bad*name`,
	}
	for _, c := range cases {
		if _, err := v.Resolve(Share{ShareID: "main", Name: "share", Root: `D:\share`, Writable: true}, c); err == nil {
			t.Errorf("应拒绝但通过了: %q", c)
		}
	}
}

func TestAcceptNormal(t *testing.T) {
	v := testVFS()
	cases := []string{
		``,
		`文档/周报 001.txt`,
		`照片/2024/IMG_0001.jpg`,
		`媒体/影片/sample.mp4`,
	}
	for _, c := range cases {
		if _, err := v.Resolve(Share{ShareID: "main", Name: "share", Root: `D:\share`, Writable: true}, c); err != nil {
			t.Errorf("应通过但被拒: %q -> %v", c, err)
		}
	}
}

// URL 路径必须落在已配置的共享名下。
func TestFromURLPath(t *testing.T) {
	v := testVFS()
	if _, err := v.FromURLPath("/share/文档/a.txt"); err != nil {
		t.Fatalf("合法 URL 被拒: %v", err)
	}
	if _, err := v.FromURLPath("/other/a.txt"); err == nil {
		t.Fatal("未知共享应被拒")
	}
	if _, err := v.FromURLPath("/"); err == nil {
		t.Fatal("空路径应被拒")
	}
}

// 可写性按最长前缀判定，子目录可覆盖父级。
func TestWritableOverride(t *testing.T) {
	v := testVFS()
	sh := Share{ShareID: "main", Name: "share", Root: `D:\share`, Writable: true}
	over := map[string]bool{"private": false, "private/open": true}

	r, _ := v.Resolve(sh, "private/a.txt")
	if v.IsWritable(r, over) {
		t.Error("private 下应只读")
	}
	r2, _ := v.Resolve(sh, "private/open/b.txt")
	if !v.IsWritable(r2, over) {
		t.Error("private/open 下应可写")
	}
	r3, _ := v.Resolve(sh, "文档/c.txt")
	if !v.IsWritable(r3, over) {
		t.Error("其它目录应继承根的可写")
	}
}

// KeyOf 的规范化必须稳定：大小写、斜杠方向、前后斜杠都不影响。
func TestKeyOf(t *testing.T) {
	if index.KeyOf(`A\B\C`) != "a/b/c" {
		t.Errorf("KeyOf 规范化错误: %q", index.KeyOf(`A\B\C`))
	}
	if index.KeyOf("/x/") != "x" {
		t.Errorf("KeyOf 去边错误: %q", index.KeyOf("/x/"))
	}
	if !strings.EqualFold(index.KeyOf(`文档/A.txt`), index.KeyOf(`文档/a.TXT`)) {
		t.Error("大小写不敏感未生效")
	}
}
