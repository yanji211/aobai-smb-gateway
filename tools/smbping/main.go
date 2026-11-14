// smbping 是一个独立的 SMB2/3 客户端验收工具。
//
// 为什么单独写：Windows 自带的 SMB 重定向器不支持 "\\host@port\share" 这种
// 带端口的写法，所以在没有管理员权限（抢不到 445）的情况下，本机无法用系统
// 客户端验证自研服务端。这里换用第三方纯 Go 客户端库，它是按微软文档逐条
// 实现的，拿它当"外部考官"，能把服务端的协议偏差如实打出来。
//
// 用法：
//
//	go run ./tools/smbping -addr 127.0.0.1:4450 -user admin -pass changeme
//	go run ./tools/smbping -addr 127.0.0.1:4450 -guest -bulk 300 -mb 64
//
// 退出码：0 全通过；1 有失败项。
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

var (
	failures []string
	mu       sync.Mutex
)

func fail(name string, err error) {
	mu.Lock()
	failures = append(failures, name+": "+err.Error())
	mu.Unlock()
	fmt.Printf("  [FAIL] %-22s %v\n", name, err)
}

func ok(name, detail string) {
	fmt.Printf("  [ OK ] %-22s %s\n", name, detail)
}

type client struct {
	sess *smb2.Session
	fs   *smb2.Share
}

func dial(addr, share, user, pass string, guest bool) (*client, error) {
	conn, err := net.DialTimeout("tcp", addr, 6*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	d := &smb2.Dialer{}
	if guest {
		d.Initiator = &smb2.NTLMInitiator{User: "", Password: ""}
	} else {
		d.Initiator = &smb2.NTLMInitiator{User: user, Password: pass}
	}
	sess, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMB 会话建立失败（协商/认证）: %w", err)
	}
	fs, err := sess.Mount(share)
	if err != nil {
		sess.Logoff()
		return nil, fmt.Errorf("挂载共享 %q 失败: %w", share, err)
	}
	return &client{sess: sess, fs: fs}, nil
}

func (c *client) Close() {
	if c == nil {
		return
	}
	if c.fs != nil {
		c.fs.Umount()
	}
	if c.sess != nil {
		c.sess.Logoff()
	}
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// 目录列举 + 元数据查询。Windows 资源管理器打开共享就是这一步，
// 只要 QUERY_DIRECTORY / QUERY_INFO 有偏差这里立刻报错。
func testList(c *client) {
	entries, err := c.fs.ReadDir(".")
	if err != nil {
		fail("列目录", err)
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
		if _, err := c.fs.Stat(e.Name()); err != nil && !strings.HasPrefix(e.Name(), ".") {
			fail("查询属性(根项)", fmt.Errorf("%s: %w", e.Name(), err))
		}
	}
	sort.Strings(names)
	detail := fmt.Sprintf("%d 项", len(names))
	if len(names) > 0 {
		shown := names
		if len(shown) > 6 {
			shown = shown[:6]
		}
		detail += "：" + strings.Join(shown, ", ")
	}
	ok("列目录+查询属性", detail)
}

// 小文件全生命周期：建 → 写 → 读 → 改名 → 删。
func testCRUD(c *client) {
	name := fmt.Sprintf("smbping-crud-%d.txt", time.Now().UnixNano())
	payload := []byte("hello win11 via fsgw\n" + strings.Repeat("0123456789abcdef", 400))

	f, err := c.fs.Create(name)
	if err != nil {
		fail("新建文件", err)
		return
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		fail("写入文件", err)
		return
	}
	if err := f.Close(); err != nil {
		fail("关闭文件", err)
		return
	}

	got, err := c.fs.ReadFile(name)
	if err != nil {
		fail("回读文件", err)
		return
	}
	if len(got) != len(payload) {
		fail("回读长度", fmt.Errorf("拿到 %d 字节，写入 %d 字节", len(got), len(payload)))
		return
	}
	if sha(got) != sha(payload) {
		fail("回读校验", errors.New("内容与写入不一致"))
		return
	}
	ok("新建+写入+回读", fmt.Sprintf("%d 字节，摘要一致", len(payload)))

	newName := name + ".renamed"
	if err := c.fs.Rename(name, newName); err != nil {
		fail("改名", err)
		return
	}
	if _, err := c.fs.Stat(newName); err != nil {
		fail("改名后查属性", err)
		return
	}
	if err := c.fs.Remove(newName); err != nil {
		fail("删除", err)
		return
	}
	if _, err := c.fs.Stat(newName); err == nil {
		fail("删除后仍存在", errors.New("文件还在"))
		return
	}
	ok("改名+删除", "改名生效，删除后不可见")
}

// 大文件：多 MB 流式写入再回读比对。这条最接近"复制大视频"的真实场景，
// 也是之前断连/0 字节问题暴露的位置（分配/写入/关闭的时序）。
func testLarge(c *client, mb int) {
	if mb <= 0 {
		return
	}
	name := fmt.Sprintf("smbping-big-%d.bin", time.Now().UnixNano())
	total := mb << 20
	const chunk = 1 << 20

	f, err := c.fs.Create(name)
	if err != nil {
		fail("大文件新建", err)
		return
	}
	w := sha256.New()
	buf := make([]byte, chunk)
	start := time.Now()
	for written := 0; written < total; written += chunk {
		if _, err := rand.Read(buf); err != nil {
			f.Close()
			c.fs.Remove(name)
			fail("大文件造数据", err)
			return
		}
		if _, err := f.Write(buf); err != nil {
			f.Close()
			c.fs.Remove(name)
			fail("大文件写入", fmt.Errorf("第 %d MiB: %w", written>>20, err))
			return
		}
		w.Write(buf)
	}
	if err := f.Sync(); err != nil {
		fail("大文件 Sync", err)
	}
	if err := f.Close(); err != nil {
		fail("大文件关闭", err)
		return
	}
	wDur := time.Since(start)

	fi, err := c.fs.Stat(name)
	if err != nil {
		fail("大文件查属性", err)
		return
	}
	if fi.Size() != int64(total) {
		fail("大文件大小", fmt.Errorf("服务端报 %d，写入 %d", fi.Size(), total))
		return
	}

	r, err := c.fs.Open(name)
	if err != nil {
		fail("大文件打开", err)
		return
	}
	defer func() {
		r.Close()
		c.fs.Remove(name)
	}()
	rs := sha256.New()
	start = time.Now()
	n, err := io.CopyBuffer(rs, r, make([]byte, chunk))
	if err != nil {
		fail("大文件回读", err)
		return
	}
	rDur := time.Since(start)
	if n != int64(total) {
		fail("大文件回读长度", fmt.Errorf("读到 %d，期望 %d", n, total))
		return
	}
	if hex.EncodeToString(rs.Sum(nil)) != hex.EncodeToString(w.Sum(nil)) {
		fail("大文件校验", errors.New("SHA256 不一致"))
		return
	}
	ok("大文件写入+回读", fmt.Sprintf("%d MiB，写 %.1f MB/s，读 %.1f MB/s，摘要一致",
		mb, float64(total)/wDur.Seconds()/1e6, float64(total)/rDur.Seconds()/1e6))
}

// 多文件：模拟"全选一个文件夹复制过去"。之前几十秒后断连、报
// "unexpected frame type" 就是在这个场景下暴露的帧错位。
func testBulk(c *client, count int, dirs int) {
	if count <= 0 {
		return
	}
	if dirs <= 0 {
		dirs = 1
	}
	base := fmt.Sprintf("smbping-bulk-%d", time.Now().UnixNano())
	if err := c.fs.Mkdir(base, 0755); err != nil {
		fail("批量-建目录", err)
		return
	}
	payload := bytes.Repeat([]byte("bulk-payload-"), 2048) // 24 KiB
	sums := map[string]string{}
	start := time.Now()
	for i := 0; i < count; i++ {
		sub := path.Join(base, fmt.Sprintf("d%02d", i%dirs))
		if i < dirs {
			if err := c.fs.Mkdir(sub, 0755); err != nil {
				fail("批量-建子目录", err)
				return
			}
		}
		p := path.Join(sub, fmt.Sprintf("f%04d.dat", i))
		body := append(payload, []byte(p)...)
		if err := c.fs.WriteFile(p, body, 0644); err != nil {
			fail("批量-写入", fmt.Errorf("%s: %w", p, err))
			return
		}
		sums[p] = sha(body)
	}
	wDur := time.Since(start)

	start = time.Now()
	bad := 0
	for p, want := range sums {
		got, err := c.fs.ReadFile(p)
		if err != nil {
			fail("批量-回读", fmt.Errorf("%s: %w", p, err))
			return
		}
		if sha(got) != want {
			bad++
		}
	}
	if bad > 0 {
		fail("批量-校验", fmt.Errorf("%d/%d 个文件内容不一致", bad, len(sums)))
		return
	}
	rDur := time.Since(start)
	ok("多文件写入+回读", fmt.Sprintf("%d 个文件 / %d 个子目录，写 %v，读+校验 %v",
		count, dirs, wDur.Round(time.Millisecond), rDur.Round(time.Millisecond)))

	// 清理：逐个删，再删目录。删除路径（FILE_DISPOSITION）是库最容易漏的一环。
	start = time.Now()
	for p := range sums {
		if err := c.fs.Remove(p); err != nil {
			fail("批量-删除", fmt.Errorf("%s: %w", p, err))
			return
		}
	}
	for i := 0; i < dirs; i++ {
		_ = c.fs.Remove(path.Join(base, fmt.Sprintf("d%02d", i)))
	}
	if err := c.fs.Remove(base); err != nil {
		fail("批量-删目录", err)
		return
	}
	ok("多文件删除", fmt.Sprintf("%d 个文件全部删除，用时 %v", count, time.Since(start).Round(time.Millisecond)))
}

// 并发会话：多个客户端同时读写，检查服务端会话隔离与句柄并发。
func testConcurrent(addr, share, user, pass string, guest bool, n int) {
	if n <= 1 {
		return
	}
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := dial(addr, share, user, pass, guest)
			if err != nil {
				errCh <- fmt.Errorf("会话 %d: %w", i, err)
				return
			}
			defer c.Close()
			name := fmt.Sprintf("smbping-conc-%d-%d.tmp", time.Now().UnixNano(), i)
			body := bytes.Repeat([]byte{byte('a' + i)}, 512*1024)
			if err := c.fs.WriteFile(name, body, 0644); err != nil {
				errCh <- fmt.Errorf("会话 %d 写入: %w", i, err)
				return
			}
			got, err := c.fs.ReadFile(name)
			if err != nil {
				errCh <- fmt.Errorf("会话 %d 回读: %w", i, err)
				return
			}
			if sha(got) != sha(body) {
				errCh <- fmt.Errorf("会话 %d 内容不一致", i)
				return
			}
			_ = c.fs.Remove(name)
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		fail("并发会话", err)
		return
	}
	ok("并发会话", fmt.Sprintf("%d 条会话并行读写，全部一致", n))
}

func main() {
	addr := flag.String("addr", "127.0.0.1:4450", "服务端地址 host:port")
	share := flag.String("share", "share", "共享名")
	user := flag.String("user", "admin", "账号")
	pass := flag.String("pass", "changeme", "口令")
	guest := flag.Bool("guest", false, "走来宾（免口令）")
	mb := flag.Int("mb", 64, "大文件大小 MiB（0=跳过）")
	bulk := flag.Int("bulk", 200, "多文件数量（0=跳过）")
	dirs := flag.Int("dirs", 10, "多文件用到的子目录数")
	conc := flag.Int("conc", 4, "并发会话数（<=1 跳过）")
	flag.Parse()

	fmt.Printf("SMB 客户端验收 → %s  共享 \\\\%s  账号 %s\n", *addr, *addr, pickStr(*guest, "(来宾)", *user))

	c, err := dial(*addr, *share, *user, *pass, *guest)
	if err != nil {
		fail("建立会话", err)
		summary()
		return
	}
	testList(c)
	testCRUD(c)
	testLarge(c, *mb)
	testBulk(c, *bulk, *dirs)
	c.Close()

	testConcurrent(*addr, *share, *user, *pass, *guest, *conc)
	summary()
}

func pickStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func summary() {
	fmt.Println()
	if len(failures) == 0 {
		fmt.Println("结论：全部通过。")
		os.Exit(0)
	}
	fmt.Printf("结论：%d 项失败\n", len(failures))
	for _, f := range failures {
		fmt.Println("  -", f)
	}
	os.Exit(1)
}
