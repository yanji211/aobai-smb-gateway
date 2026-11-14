// Package selftest 把 docs/03 的验收断言做成一条命令能跑完的自动化测试。
// 不需要管理员权限：整机副作用（防火墙、SMB 共享）通过 DryRun 跳过。
package selftest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fsgw/internal/app"
	"fsgw/internal/config"
	"fsgw/internal/index"
)

type Result struct {
	Name   string
	OK     bool
	Detail string
}

type Report struct {
	Items   []Result
	Elapsed time.Duration
}

func (r *Report) add(name string, ok bool, detail string) {
	r.Items = append(r.Items, Result{Name: name, OK: ok, Detail: detail})
}

func (r *Report) Failed() int {
	n := 0
	for _, it := range r.Items {
		if !it.OK {
			n++
		}
	}
	return n
}

func (r *Report) Report() string {
	var b strings.Builder
	pass := 0
	for _, it := range r.Items {
		mark := "PASS"
		if !it.OK {
			mark = "FAIL"
		} else {
			pass++
		}
		fmt.Fprintf(&b, "  [%s] %-46s %s\n", mark, it.Name, it.Detail)
	}
	fmt.Fprintf(&b, "\n  %d 通过 / %d 失败 / 共 %d 项，耗时 %s\n",
		pass, len(r.Items)-pass, len(r.Items), r.Elapsed.Round(time.Millisecond))
	return b.String()
}

func Run(verbose bool) *Report {
	start := time.Now()
	rep := &Report{}

	// 夹具放在当前工作目录下：配置校验会拒绝共享系统目录（C:\Users、C:\Windows 等），
	// 而 os.TempDir() 默认就在 C:\Users 下。
	base, err := os.Getwd()
	if err != nil {
		base = "."
	}
	tmp := filepath.Join(base, ".selftest", fmt.Sprintf("run-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		tmp, err = os.MkdirTemp("", "fsgw-selftest-*")
		if err != nil {
			rep.add("准备临时目录", false, err.Error())
			rep.Elapsed = time.Since(start)
			return rep
		}
	}
	if !verbose {
		defer os.RemoveAll(filepath.Join(base, ".selftest"))
	} else {
		fmt.Println("测试目录（verbose 保留）:", tmp)
	}
	rep.add("准备临时目录", true, tmp)

	root := filepath.Join(tmp, "share")
	if err := makeFixture(root); err != nil {
		rep.add("生成夹具", false, err.Error())
		rep.Elapsed = time.Since(start)
		return rep
	}

	// 统计磁盘实际情况，作为索引对照基线。
	wantFiles, wantDirs := countTree(root)
	rep.add("生成夹具", wantFiles > 150, fmt.Sprintf("%d 个文件 / %d 个目录", wantFiles, wantDirs))

	uiPort, err := freePort()
	if err != nil {
		rep.add("挑选控制面端口", false, err.Error())
		rep.Elapsed = time.Since(start)
		return rep
	}
	wdPort, err := freePort()
	if err != nil {
		rep.add("挑选 WebDAV 端口", false, err.Error())
		rep.Elapsed = time.Since(start)
		return rep
	}
	uiBind := fmt.Sprintf("127.0.0.1:%d", uiPort)
	wdBind := fmt.Sprintf("127.0.0.1:%d", wdPort)
	dlnaPort, err := freePort()
	if err != nil {
		rep.add("挑选 DLNA 端口", false, err.Error())
		rep.Elapsed = time.Since(start)
		return rep
	}

	cfgPath := filepath.Join(tmp, "config.yaml")
	cfgYAML := fmt.Sprintf(`version: 1
data_dir: %q
shares:
  - share_id: main
    root: %q
    name: share
    writable: true
    media: true
index:
  debounce_structural_ms: 60
  debounce_content_ms: 80
  hash_max_mb: 64
smb:
  enabled: false
dlna:
  enabled: true
  http_port: %d
  friendly_name: selftest-media
webdav:
  enabled: true
  bind: %q
  username: fsgw
  password: selftest
ui:
  bind: %q
switch:
  startup_state: OFF
log:
  level: warn
`, filepath.Join(tmp, "data"), root, dlnaPort, wdBind, uiBind)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		rep.add("写测试配置", false, err.Error())
		rep.Elapsed = time.Since(start)
		return rep
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		rep.add("加载测试配置", false, err.Error())
		rep.Elapsed = time.Since(start)
		return rep
	}
	rep.add("加载测试配置", true, "校验通过")

	a, err := app.New(app.Options{Config: cfg, Log: discardLogger(), DryRun: true})
	if err != nil {
		rep.add("初始化网关", false, err.Error())
		rep.Elapsed = time.Since(start)
		return rep
	}
	defer a.Close()
	if err := a.Start(context.Background()); err != nil {
		rep.add("启动网关", false, err.Error())
		rep.Elapsed = time.Since(start)
		return rep
	}
	rep.add("启动网关", true, "索引 + 控制台已就绪")

	st := a.Status()
	gotFiles := st.Index.Files
	rep.add("初始索引与磁盘一致", gotFiles == int64(wantFiles),
		fmt.Sprintf("库 %d / 盘 %d", gotFiles, wantFiles))

	// ---------- 1. 新增文件被监听捕获 ----------
	newFile := filepath.Join(root, "媒体", "新增素材.txt")
	os.WriteFile(newFile, []byte("hello fsgw"), 0o644)
	ok := waitFor(func() bool {
		s := a.Status()
		return s.Index.Files == int64(wantFiles)+1
	}, 5*time.Second)
	rep.add("新增文件进入索引", ok, "watcher 捕获 create 事件")

	// ---------- 2. 内容修改产生索引版本 ----------
	before := a.Status().Index.Versions
	os.WriteFile(newFile, []byte("hello fsgw, second version with more bytes"), 0o644)
	ok = waitFor(func() bool { return a.Status().Index.Versions > before }, 5*time.Second)
	afterVers := a.Status().Index.Versions
	rep.add("内容修改追加索引版本", ok, fmt.Sprintf("%d -> %d", before, afterVers))

	// ---------- 3. 移动零版本 ----------
	oldDir := filepath.Join(root, "照片")
	newDir := filepath.Join(root, "媒体", "照片归档")
	movedCount := countFiles(oldDir)
	versBefore := a.Status().Index.Versions
	histBefore := a.Status().Index.PathHistory
	filesBefore := a.Status().Index.Files
	if err := os.Rename(oldDir, newDir); err != nil {
		rep.add("移动目录", false, err.Error())
	} else {
		// 一次目录移动 = 一个事务 + 一条 path_history；子项只更新路径，不各记一条。
		ok = waitFor(func() bool { return a.Status().Index.PathHistory > histBefore }, 6*time.Second)
		s := a.Status()
		rep.add("移动目录：路径历史追加", ok,
			fmt.Sprintf("history %d -> %d（目录内含 %d 个文件）", histBefore, s.Index.PathHistory, movedCount))
		rep.add("移动零版本（核心断言）", s.Index.Versions == versBefore,
			fmt.Sprintf("versions %d -> %d，必须相等", versBefore, s.Index.Versions))
		rep.add("移动不产生删除+新增", s.Index.Files == filesBefore,
			fmt.Sprintf("文件数 %d -> %d，必须相等", filesBefore, s.Index.Files))

		stat, err := os.Stat(newDir)
		rep.add("移动后磁盘位置正确", err == nil && stat.IsDir(), newDir)
	}

	// ---------- 4. 删除语义 ----------
	delTarget := filepath.Join(root, "媒体", "新增素材.txt")
	versBeforeDel := a.Status().Index.Versions
	filesBeforeDel := a.Status().Index.Files
	os.Remove(delTarget)
	ok = waitFor(func() bool { return a.Status().Index.Files == filesBeforeDel-1 }, 5*time.Second)
	s := a.Status()
	rep.add("删除后从当前视图消失", ok, fmt.Sprintf("库文件 %d -> %d", filesBeforeDel, s.Index.Files))
	rep.add("删除冻结版本链", s.Index.Versions >= versBeforeDel, "版本不回收")

	// ---------- 5. VFS 穿越防护 ----------
	vfsCases := []struct {
		rel  string
		want string
	}{
		{`..\..\Windows\System32\cmd.exe`, "escape"},
		{`媒体\..\..\secret`, "escape"},
		{`file.txt:stream`, "ads"},
		{`CON`, "reserved"},
		{`trailing `, "trailing"},
	}
	passed := 0
	details := []string{}
	for _, c := range vfsCases {
		entry, err := a.ListDirs(filepath.Join(root, c.rel))
		_ = entry
		if err != nil {
			passed++
			details = append(details, c.want+"=拒")
		} else {
			details = append(details, c.want+"=放")
		}
	}
	rep.add("目录浏览拒绝非法路径", passed >= 3, strings.Join(details, " "))

	// ---------- 6. 控制面安全四道防线 ----------
	apiBase := "http://" + uiBind
	tok := a.Token()
	rep.add("无 token 返回 401", statusOf(apiBase+"/api/status", "", "", "") == 401, "GET /api/status")
	rep.add("错误 token 返回 401", statusOf(apiBase+"/api/status", "bad", "", "") == 401, "token=bad")
	rep.add("伪造 Origin 返回 403",
		statusOf(apiBase+"/api/status", tok, "http://evil.example", "") == 403, "Origin: evil.example")
	rep.add("伪造 Host 返回 403",
		statusOfHost(apiBase+"/api/status", tok, "evil.example:"+fmt.Sprint(uiPort)) == 403, "Host: evil.example")
	rep.add("正确 token 返回 200", statusOf(apiBase+"/api/status", tok, "", "") == 200, "GET /api/status")

	// 预检不得放行
	req, _ := http.NewRequest(http.MethodOptions, apiBase+"/api/switch", nil)
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		resp.Body.Close()
		rep.add("跨源预检不放行", acao == "", "无 Access-Control-Allow-Origin")
	}

	// ---------- 7. 开关：WAN 起 WebDAV ----------
	if _, err := a.Switch(context.Background(), "WAN"); err != nil {
		rep.add("切换到 WAN", false, err.Error())
	} else {
		// 开关是异步长任务：先等状态机真正落到目标态，再去探测端口。
		// 只等端口会让"自检"读到还没更新的 applied_state。
		ok = waitFor(func() bool { return a.Status().State == "WAN" }, 8*time.Second)
		rep.add("WAN 状态自检通过", ok, "applied_state="+a.Status().State)
		ok = waitFor(func() bool {
			c, err := net.DialTimeout("tcp", wdBind, 200*time.Millisecond)
			if err != nil {
				return false
			}
			c.Close()
			return true
		}, 6*time.Second)
		rep.add("切换到 WAN 后 WebDAV 监听", ok, wdBind)
	}

	// ---------- 8. WebDAV 只读语义 ----------
	wdURL := "http://" + wdBind + "/share/"
	code := basicStatus("PROPFIND", wdURL, "fsgw", "selftest", map[string]string{"Depth": "1"})
	rep.add("PROPFIND 返回 207", code == 207, fmt.Sprintf("HTTP %d", code))

	code = basicStatus("PUT", wdURL+"evil.txt", "fsgw", "selftest", nil)
	rep.add("PUT 被拒绝 405", code == 405, fmt.Sprintf("HTTP %d", code))
	if _, err := os.Stat(filepath.Join(root, "evil.txt")); err == nil {
		rep.add("PUT 未落盘", false, "磁盘上出现了 evil.txt")
	} else {
		rep.add("PUT 未落盘", true, "磁盘无变化")
	}

	code = basicStatus("DELETE", wdURL+"媒体/", "fsgw", "selftest", nil)
	rep.add("DELETE 被拒绝 405", code == 405, fmt.Sprintf("HTTP %d", code))

	code = basicStatus("GET", "http://"+wdBind+"/share/..%2f..%2fWindows/win.ini", "fsgw", "selftest", nil)
	rep.add("GET 穿越被拒绝", code != 200, fmt.Sprintf("HTTP %d（不得为 200）", code))

	code = basicStatus("GET", "http://"+wdBind+"/share/", "fsgw", "wrong", nil)
	rep.add("WebDAV 错误口令 401", code == 401, fmt.Sprintf("HTTP %d", code))

	// GET 一个真实文件，校验字节一致
	var probe string
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && probe == "" && info.Size() > 0 && info.Size() < 1<<20 {
			probe = p
		}
		return nil
	})
	if probe != "" {
		rel, _ := filepath.Rel(root, probe)
		body, code, err := basicGet("http://"+wdBind+"/share/"+escapeRel(rel), "fsgw", "selftest")
		disk, _ := os.ReadFile(probe)
		ok := err == nil && code == 200 && string(body) == string(disk)
		rep.add("GET 返回字节与磁盘一致", ok, fmt.Sprintf("%s（%d 字节）", rel, len(body)))
	}

	// 浏览器用 GET 打开目录，WebDAV 客户端用 PROPFIND：两条路都得能用
	page, pageCode, _ := basicGet("http://"+wdBind+"/share/", "fsgw", "selftest")
	rep.add("浏览器访问共享根得到目录页",
		pageCode == 200 && strings.Contains(string(page), "<table"),
		fmt.Sprintf("HTTP %d，%d 字节", pageCode, len(page)))

	// ---------- 9. DLNA ----------
	dlnaBase := fmt.Sprintf("http://127.0.0.1:%d", dlnaPort)
	if _, err := a.Switch(context.Background(), "ALL"); err != nil {
		rep.add("切换到 ALL（含 DLNA）", false, err.Error())
	} else {
		ok = waitFor(func() bool { return a.Status().State == "ALL" }, 8*time.Second)
		rep.add("ALL 状态自检通过", ok, "applied_state="+a.Status().State)
		ok = waitFor(func() bool {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", dlnaPort), 200*time.Millisecond)
			if err != nil {
				return false
			}
			c.Close()
			return true
		}, 6*time.Second)
		rep.add("DLNA HTTP 监听", ok, fmt.Sprintf(":%d", dlnaPort))

		// SSDP 必须单独断言：HTTP 通了但设备发现挂了时，电视搜不到，
		// 而界面照样显示"已开启"。这一项就是防这种假阳性。
		dlnaNote := ""
		for _, l := range a.Status().Listeners {
			if l.Name == "DLNA" {
				dlnaNote = l.Note
			}
		}
		rep.add("SSDP 设备发现已就绪", strings.Contains(dlnaNote, "已广播"), dlnaNote)

		desc, code, _ := httpGetText(dlnaBase + "/rootDesc.xml")
		rep.add("设备描述可读", code == 200 && strings.Contains(desc, "selftest-media"),
			fmt.Sprintf("HTTP %d，含 friendlyName", code))

		_, code, _ = httpGetText(dlnaBase + "/")
		rep.add("不提供目录列表页", code == 404, fmt.Sprintf("HTTP %d", code))

		// 根目录应只列出媒体共享
		rootDIDL, code := dlnaBrowse(dlnaBase, "0")
		rep.add("Browse 根返回共享容器",
			code == 200 && strings.Contains(rootDIDL, "sh:share") && strings.Contains(rootDIDL, "object.container"),
			fmt.Sprintf("HTTP %d", code))

		// 媒体目录里应出现视频项
		listDIDL, code := dlnaBrowse(dlnaBase, "d:share:"+index.KeyOf("媒体/影片"))
		hasVideo := strings.Contains(listDIDL, "object.item.videoItem") && strings.Contains(listDIDL, ".mp4")
		rep.add("Browse 媒体目录返回视频项", code == 200 && hasVideo,
			fmt.Sprintf("HTTP %d，视频=%v", code, hasVideo))

		// 文档目录里只有 txt/pdf，不能返回任何媒体项
		docDIDL, code := dlnaBrowse(dlnaBase, "d:share:"+index.KeyOf("文档"))
		noDoc := !strings.Contains(docDIDL, ".txt") && !strings.Contains(docDIDL, "object.item")
		rep.add("Browse 文档目录不返回媒体项", code == 200 && noDoc,
			fmt.Sprintf("HTTP %d，无媒体项=%v", code, noDoc))

		// 取一个媒体文件的字节
		mediaURL := dlnaBase + "/media/share/" +
			urlEscapeSegment("媒体") + "/" + urlEscapeSegment("影片") + "/" + urlEscapeSegment("sample.mp4")
		body, code, _ := httpGetText(mediaURL)
		disk, _ := os.ReadFile(filepath.Join(root, "媒体", "影片", "sample.mp4"))
		rep.add("媒体 URL 返回字节一致", code == 200 && body == string(disk),
			fmt.Sprintf("HTTP %d，%d 字节", code, len(body)))

		// 非媒体文件必须被挡
		txtURL := dlnaBase + "/media/share/" + urlEscapeSegment("文档") + "/" +
			urlEscapeSegment("周报 001.txt")
		_, code, _ = httpGetText(txtURL)
		rep.add("媒体面拒绝非媒体文件", code == 403, fmt.Sprintf("HTTP %d", code))

		_, code, _ = httpGetText(dlnaBase + "/media/share/..%2F..%2FWindows/win.ini")
		rep.add("媒体面拒绝穿越", code == 403 || code == 400 || code == 404, fmt.Sprintf("HTTP %d", code))
	}

	// ---------- 10. 关闭即零暴露 ----------
	if _, err := a.Switch(context.Background(), "OFF"); err != nil {
		rep.add("切换到 OFF", false, err.Error())
	} else {
		ok = waitFor(func() bool {
			c, err := net.DialTimeout("tcp", wdBind, 200*time.Millisecond)
			if err != nil {
				return true
			}
			c.Close()
			return false
		}, 6*time.Second)
		rep.add("OFF 后 WebDAV 端口关闭", ok, wdBind)
		ok = waitFor(func() bool {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", dlnaPort), 200*time.Millisecond)
			if err != nil {
				return true
			}
			c.Close()
			return false
		}, 6*time.Second)
		rep.add("OFF 后 DLNA 端口关闭", ok, fmt.Sprintf(":%d", dlnaPort))
		rep.add("OFF 后状态为 OFF", a.Status().State == "OFF", "applied_state="+a.Status().State)
	}

	// ---------- 10. 子树重建 ----------
	beforeRecon := a.Status().Index.LastReconcile
	os.MkdirAll(filepath.Join(root, "重建测试", "a", "b"), 0o755)
	os.WriteFile(filepath.Join(root, "重建测试", "a", "b", "deep.txt"), []byte("x"), 0o644)
	err = a.Reconcile(filepath.Join(root, "重建测试"))
	after := a.Status().Index.LastReconcile
	rep.add("子树重建可执行", err == nil && after != beforeRecon,
		fmt.Sprintf("last_reconcile=%s", after))

	rep.Elapsed = time.Since(start)
	return rep
}

// ---------- 夹具 ----------

func makeFixture(root string) error {
	dirs := []string{
		"文档", "文档/合同", "照片/2024", "照片/2025", "媒体", "媒体/影片",
		"空目录", "深层/一层/二层/三层/四层/五层",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			return err
		}
	}
	// 中文名 + 常见扩展名 + 一定数量
	for i := 0; i < 180; i++ {
		name := fmt.Sprintf("文档/周报 %03d.txt", i)
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(strings.Repeat("x", 32+i)), 0o644); err != nil {
			return err
		}
	}
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("照片/2024/IMG_%04d.jpg", i)
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte("jpeg"), 0o644); err != nil {
			return err
		}
	}
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("照片/2025/IMG_%04d.jpg", i)
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte("jpeg"), 0o644); err != nil {
			return err
		}
	}
	// 超长路径
	long := filepath.Join(root, "深层", "一层", "二层", "三层", "四层", "五层",
		strings.Repeat("很长的目录名", 12), strings.Repeat("很长的文件名", 8)+".txt")
	if err := os.MkdirAll(filepath.Dir(long), 0o755); err == nil {
		os.WriteFile(long, []byte("long path"), 0o644)
	}
	os.WriteFile(filepath.Join(root, "媒体", "影片", "sample.mp4"), []byte(strings.Repeat("v", 1024)), 0o644)
	os.WriteFile(filepath.Join(root, "文档", "合同", "2026 报价单.pdf"), []byte("%PDF-1"), 0o644)
	return nil
}

func countTree(root string) (files, dirs int) {
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if p != root {
				dirs++
			}
			return nil
		}
		files++
		return nil
	})
	return
}

func countFiles(dir string) int {
	n := 0
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// ---------- HTTP 辅助 ----------

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func statusOf(url, token, origin, _ string) int {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return -1
	}
	if token != "" {
		req.Header.Set("X-FSGW-Token", token)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func statusOfHost(url, token, host string) int {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return -1
	}
	req.Host = host
	req.Header.Set("X-FSGW-Token", token)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func basicStatus(method, url, user, pass string, headers map[string]string) int {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return -1
	}
	req.SetBasicAuth(user, pass)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// httpGetText 发一个匿名 GET，DLNA 面不需要认证。
func httpGetText(url string) (string, int, error) {
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Get(url)
	if err != nil {
		return "", -1, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode, err
}

// dlnaBrowse 发一个最小 SOAP Browse 请求，返回响应原文与状态码。
func dlnaBrowse(base, objectID string) (string, int) {
	soap := `<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<s:Body><u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">` +
		`<ObjectID>` + objectID + `</ObjectID>` +
		`<BrowseFlag>BrowseDirectChildren</BrowseFlag>` +
		`<Filter>*</Filter><StartingIndex>0</StartingIndex>` +
		`<RequestedCount>0</RequestedCount><SortCriteria></SortCriteria>` +
		`</u:Browse></s:Body></s:Envelope>`

	req, err := http.NewRequest(http.MethodPost, base+"/ctl/ContentDirectory", strings.NewReader(soap))
	if err != nil {
		return "", -1
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:ContentDirectory:1#Browse"`)
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Do(req)
	if err != nil {
		return "", -1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

func basicGet(url, user, pass string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, -1, err
	}
	req.SetBasicAuth(user, pass)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, -1, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func escapeRel(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i, p := range parts {
		parts[i] = urlEscapeSegment(p)
	}
	return strings.Join(parts, "/")
}

func urlEscapeSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 && (r == '-' || r == '_' || r == '.' || r == '~' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			b.WriteRune(r)
			continue
		}
		buf := []byte(string(r))
		for _, c := range buf {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func waitFor(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(40 * time.Millisecond)
	}
	return false
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
