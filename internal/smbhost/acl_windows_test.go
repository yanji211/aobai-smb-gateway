//go:build windows

package smbhost

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// icaclsNames 读目录 DACL 里出现的 Everyone 条数。
// 用 icacls 校验而不是自己再解析安全描述符，等于换一条独立路径验证
// Win32 写入的结果——自测自己写的结构体没有意义。
func icaclsEveryoneCount(t *testing.T, dir string) int {
	t.Helper()
	out, err := exec.Command("icacls", dir).Output()
	if err != nil {
		t.Fatalf("icacls 读取失败: %v", err)
	}
	// 中文系统上 icacls 的提示语是 GBK，但账户名 Everyone 是 ASCII，直接数即可。
	return strings.Count(string(out), "Everyone")
}

// TestEveryoneACE 验「授权 → 重复授权 → 撤销」这条链是可逆且幂等的。
// 这几步就是免密共享的全部权限操作：换共享目录会重跑授权，
// 关闭免密会跑撤销，任何一步幂等性破了都会留下多余的 ACE 或把权限改坏。
func TestEveryoneACE(t *testing.T) {
	// 不能用 t.TempDir()：它在 %TEMP% 下面，而 Temp 目录默认就带 Everyone，
	// 基线里混着继承来的 ACE，看不出这次改动到底做了什么。
	// 用户主目录不带 Everyone，建在这里基线才是干净的。
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("取不到用户目录: %v", err)
	}
	dir, err := os.MkdirTemp(home, "fsgw-acltest-")
	if err != nil {
		t.Skipf("建测试目录失败: %v", err)
	}
	defer os.RemoveAll(dir)

	if n := icaclsEveryoneCount(t, dir); n != 0 {
		t.Skipf("测试目录已带 Everyone（%d），换台机器再验", n)
	}
	if err := grantEveryoneFast(dir, true); err != nil {
		t.Fatalf("授予 Everyone 失败: %v", err)
	}
	if n := icaclsEveryoneCount(t, dir); n != 1 {
		t.Fatalf("授权后 Everyone ACE 数量应为 1，实际 %d", n)
	}
	// 幂等：再授予一次不该叠出第二条 ACE。
	if err := grantEveryoneFast(dir, true); err != nil {
		t.Fatalf("重复授予失败: %v", err)
	}
	if n := icaclsEveryoneCount(t, dir); n != 1 {
		t.Fatalf("重复授权后应仍是 1 条 ACE，实际 %d（会无限膨胀）", n)
	}
	if err := revokeEveryoneFast(dir); err != nil {
		t.Fatalf("撤销 Everyone 失败: %v", err)
	}
	if n := icaclsEveryoneCount(t, dir); n != 0 {
		t.Fatalf("撤销后不该再有 Everyone，实际 %d", n)
	}
	// 撤销也要幂等：没有 Everyone 时再撤一次不能报错。
	if err := revokeEveryoneFast(dir); err != nil {
		t.Fatalf("重复撤销应无害，实际报错: %v", err)
	}
}

// TestEveryoneMask 只读/可写两档权限必须真的有区别：
// 免密只读共享靠它来挡住客户端写入，映射错了等于"只读"名存实亡。
//
// 这里只能查"写专有位"（写数据 / 追加 / 改属性 / 删除）。不能拿
// FILE_GENERIC_WRITE 去按位与，因为 FILE_GENERIC_READ 本身就含
// SYNCHRONIZE(0x100000) 和 READ_CONTROL(0x20000)，两组掩码天然重叠。
func TestEveryoneMask(t *testing.T) {
	const (
		writeData       = 0x2
		appendData      = 0x4
		writeAttributes = 0x100
		deleteBit       = 0x10000
	)
	ro, rw := everyoneMask(false), everyoneMask(true)
	for _, bit := range []uint32{writeData, appendData, writeAttributes, deleteBit} {
		if ro&bit != 0 {
			t.Errorf("只读权限不该含 %#x: %#x", bit, ro)
		}
	}
	if ro&fileGenericRead == 0 || ro&fileGenericExecute == 0 {
		t.Errorf("只读权限必须能读能列目录: %#x", ro)
	}
	if rw&fileGenericWrite == 0 || rw&fileDelete == 0 {
		t.Errorf("可写权限必须含写/删: %#x", rw)
	}
	if rw&fileGenericRead == 0 {
		t.Errorf("可写权限当然也要能读: %#x", rw)
	}
}
