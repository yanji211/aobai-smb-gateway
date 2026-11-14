//go:build windows

package tray

import (
	"testing"
	"unsafe"
)

// 这些结构体是直接喂给 Shell_NotifyIcon 和 GetMessage 的裸内存，
// 字段偏移错一个字节，图标就会"添加成功但永远不出现"，且不报任何错。
// 所以用测试把布局钉死。
func TestWin32StructLayout(t *testing.T) {
	var nid notifyIconData
	if got, want := unsafe.Sizeof(nid), uintptr(976); got != want {
		t.Fatalf("NOTIFYICONDATA 大小 = %d，期望 %d", got, want)
	}
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"HWnd", unsafe.Offsetof(nid.HWnd), 8},
		{"UFlags", unsafe.Offsetof(nid.UFlags), 20},
		{"UCallbackMessage", unsafe.Offsetof(nid.UCallbackMessage), 24},
		{"HIcon", unsafe.Offsetof(nid.HIcon), 32},
		{"SzTip", unsafe.Offsetof(nid.SzTip), 40},
		{"DwState", unsafe.Offsetof(nid.DwState), 296},
		{"SzInfoTitle", unsafe.Offsetof(nid.SzInfoTitle), 820},
		{"HBalloonIcon", unsafe.Offsetof(nid.HBalloonIcon), 968},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s 偏移 = %d，期望 %d", c.name, c.got, c.want)
		}
	}

	var m msgT
	if got, want := unsafe.Sizeof(m), uintptr(48); got != want {
		t.Errorf("MSG 大小 = %d，期望 %d", got, want)
	}
	if unsafe.Offsetof(m.Message) != 8 || unsafe.Offsetof(m.WParam) != 16 ||
		unsafe.Offsetof(m.LParam) != 24 || unsafe.Offsetof(m.Time) != 32 ||
		unsafe.Offsetof(m.PtX) != 40 {
		t.Errorf("MSG 字段偏移不对: msg=%d wparam=%d lparam=%d time=%d pt=%d",
			unsafe.Offsetof(m.Message), unsafe.Offsetof(m.WParam), unsafe.Offsetof(m.LParam),
			unsafe.Offsetof(m.Time), unsafe.Offsetof(m.PtX))
	}

	var wc wndClassExW
	if got, want := unsafe.Sizeof(wc), uintptr(80); got != want {
		t.Errorf("WNDCLASSEXW 大小 = %d，期望 %d", got, want)
	}
	if got, want := unsafe.Offsetof(wc.LpfnWndProc), uintptr(8); got != want {
		t.Errorf("LpfnWndProc 偏移 = %d，期望 %d", got, want)
	}
	if got, want := unsafe.Offsetof(wc.LpszClassName), uintptr(64); got != want {
		t.Errorf("LpszClassName 偏移 = %d，期望 %d", got, want)
	}
}

func TestIconEmbedded(t *testing.T) {
	// ICO 头：reserved=0, type=1, count>=1
	if len(iconICO) < 6 {
		t.Fatalf("内嵌图标太小: %d 字节", len(iconICO))
	}
	if iconICO[2] != 1 || iconICO[3] != 0 {
		t.Errorf("图标类型不是 ICO: %v", iconICO[:4])
	}
	if n := int(iconICO[4]) | int(iconICO[5])<<8; n < 1 {
		t.Errorf("ICO 里没有图像: count=%d", n)
	}
}
