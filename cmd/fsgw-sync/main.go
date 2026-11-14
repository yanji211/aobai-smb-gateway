// fsgw-sync 是「快同步」的客户端：把本地目录推到服务端的共享根里。
//
// 为什么不用资源管理器复制：
//   - SMB 一条会话里请求是串行的，开多线程也只是排队，带宽吃不满；
//   - 大文件断一次就得从头来；
//   - 小文件每个都要一次往返，几千个 2KB 文件能磨掉几分钟。
//
// 这里走自己的协议：文件切块并行传、小文件打包成一次请求、每块独立校验、
// 断点续传靠服务端的 .map 位图，重跑只补缺的块。
package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const clientVersion = "0.1.0"

type config struct {
	server      string
	token       string
	src         string
	dst         string
	root        string
	workers     int
	fileWorkers int
	chunkMB     int
	bundleKB    int
	watch       time.Duration
	dryRun      bool
	checksum    bool
	force       bool
	statePath   string
	verbose     bool
	excludes    multiFlag
	serverName  string
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

func main() {
	var cfg config
	flag.StringVar(&cfg.server, "server", "http://127.0.0.1:8445", "同步服务地址，如 http://192.0.2.11:8445")
	flag.StringVar(&cfg.token, "token", "", "同步 token（也可用 FSGW_SYNC_TOKEN 或 -token-file）")
	flag.StringVar(&cfg.src, "src", "", "本地源目录")
	flag.StringVar(&cfg.dst, "dst", "", "目标目录（相对共享根，留空=根）")
	flag.StringVar(&cfg.root, "root", "", "共享根 id/名字，留空用服务端第一个可写根")
	flag.IntVar(&cfg.workers, "workers", 8, "全局并发请求数")
	flag.IntVar(&cfg.fileWorkers, "file-workers", 4, "同时上传的大文件数")
	flag.IntVar(&cfg.chunkMB, "chunk-mb", 4, "分块大小 MB（0=用服务端默认）")
	flag.IntVar(&cfg.bundleKB, "bundle-kb", 256, "小于该尺寸的文件走打包通道")
	flag.DurationVar(&cfg.watch, "watch", 0, "常驻：每轮结束后隔多久再扫一次（0=只跑一次）")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "只对比不传输")
	flag.BoolVar(&cfg.checksum, "checksum", false, "按内容比对（慢），默认按大小+时间")
	flag.BoolVar(&cfg.force, "force", false, "忽略服务端判断，全部重传")
	flag.StringVar(&cfg.statePath, "state", "", "本地状态文件（默认 ~/.fsgw-sync/<key>.json）")
	flag.BoolVar(&cfg.verbose, "v", false, "打印每个文件")
	flag.Var(&cfg.excludes, "exclude", "排除规则（正则，可重复或逗号分隔）")
	tokenFile := flag.String("token-file", "", "从文件读 token")
	flag.Parse()

	if t := os.Getenv("FSGW_SYNC_TOKEN"); cfg.token == "" && t != "" {
		cfg.token = t
	}
	if cfg.token == "" && *tokenFile != "" {
		if b, err := os.ReadFile(*tokenFile); err == nil {
			cfg.token = strings.TrimSpace(string(b))
		}
	}
	if cfg.token == "" {
		fatal("缺少同步 token：用 -token 或 FSGW_SYNC_TOKEN 指定（服务端在 data_dir/sync.token）")
	}
	if cfg.src == "" {
		fatal("缺少 -src")
	}
	cfg.server = strings.TrimRight(cfg.server, "/")
	if cfg.workers < 1 {
		cfg.workers = 1
	}
	if cfg.fileWorkers < 1 {
		cfg.fileWorkers = 1
	}

	// 常驻模式下每轮都要重新扫：目录内容、状态文件都可能变。
	for {
		if err := runOnce(&cfg); err != nil {
			fmt.Fprintf(os.Stderr, "\n同步失败：%v\n", err)
			if cfg.watch <= 0 {
				os.Exit(1)
			}
		}
		if cfg.watch <= 0 {
			return
		}
		fmt.Fprintf(os.Stderr, "\n等待 %s 后开始下一轮…\n", cfg.watch)
		time.Sleep(cfg.watch)
	}
}

type entry struct {
	Rel   string
	Size  int64
	MTime int64
	Mode  int64
	SHA   string
}

type planItem struct {
	Rel   string
	FID   string
	Size  int64
	Act   string
	MTime int64
	Mode  int64
}

func runOnce(cfg *config) error {
	start := time.Now()
	excl := compileExcludes(cfg.excludes)

	files, err := scan(cfg.src, excl)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		fmt.Println("源目录没有可同步的文件")
		return nil
	}
	totalBytes := int64(0)
	for _, f := range files {
		totalBytes += f.Size
	}
	fmt.Printf("扫描完成：%d 个文件，%.2f MiB\n", len(files), float64(totalBytes)/(1<<20))

	c := newClient(cfg)
	info, err := c.info()
	if err != nil {
		return fmt.Errorf("连不上同步服务 %s：%w", cfg.server, err)
	}
	if cfg.chunkMB > 0 {
		info.ChunkSize = int64(cfg.chunkMB) << 20
	}
	if info.MaxFiles > 0 && len(files) > info.MaxFiles {
		return fmt.Errorf("源目录 %d 个文件，超过服务端单次清单上限 %d：用 -exclude 排除依赖/缓存目录，或按子目录分几次推（服务端可调 sync.max_files）",
			len(files), info.MaxFiles)
	}
	if cfg.verbose {
		fmt.Printf("服务端：%s  块大小 %.1f MiB\n", info.Protocol, float64(info.ChunkSize)/(1<<20))
	}

	st := loadState(cfg, c)
	sid, resumed, err := c.createSession(st.Session, cfg, files)
	if err != nil {
		return err
	}
	st.Session = sid
	saveState(cfg, st)
	if resumed {
		fmt.Printf("续传已有会话 %s\n", sid)
	}

	plan, err := c.plan(sid)
	if err != nil {
		return err
	}
	var todo []planItem
	skipped := 0
	var todoBytes int64
	byPath := map[string]entry{}
	for _, f := range files {
		byPath[f.Rel] = f
	}
	var planFail []string
	for _, p := range plan {
		if p.Act == "fail" {
			planFail = append(planFail, p.Rel)
			continue
		}
		if p.Act == "skip" && !cfg.force {
			skipped++
			continue
		}
		if e, ok := byPath[p.Rel]; ok {
			p.MTime, p.Mode = e.MTime, e.Mode
		}
		todo = append(todo, p)
		todoBytes += p.Size
	}
	forced := 0
	if cfg.force {
		for _, p := range plan {
			if p.Act == "skip" {
				forced++
			}
		}
	}
	if len(planFail) > 0 {
		fmt.Printf("服务端拒绝 %d 个路径（非法/越界），已跳过：%s\n", len(planFail), strings.Join(head(planFail, 3), ", "))
	}
	fmt.Printf("需要传输 %d 个文件（%.2f MiB），跳过 %d 个%s\n",
		len(todo), float64(todoBytes)/(1<<20), skipped, forceNote(forced))
	if cfg.dryRun || len(todo) == 0 {
		if len(todo) == 0 {
			if _, err := c.finish(sid); err != nil {
				return err
			}
			fmt.Println("已是最新，无需传输")
		}
		return nil
	}

	bundleLimit := int64(cfg.bundleKB) << 10
	var small, big []planItem
	for _, p := range todo {
		if p.Size <= bundleLimit {
			small = append(small, p)
		} else {
			big = append(big, p)
		}
	}

	prog := &progress{total: len(todo), bytesTotal: todoBytes}
	prog.start()

	var firstErr error
	var mu sync.Mutex
	note := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	// 小文件：打包上传。包大小上限 8MiB / 512 个，太大反而失去"少往返"的意义。
	if len(small) > 0 {
		if err := uploadBundles(c, sid, small, byPath, cfg, prog, note); err != nil {
			return err
		}
	}
	// 大文件：文件级并行，文件内部再按块并行。
	if len(big) > 0 {
		if err := uploadBigFiles(c, sid, big, byPath, cfg, info.ChunkSize, prog, note); err != nil {
			return err
		}
	}
	prog.stop()

	sum, err := c.finish(sid)
	if err != nil {
		return err
	}
	st.Session = ""
	saveState(cfg, st)

	cost := time.Since(start)
	rate := float64(todoBytes) / cost.Seconds() / (1 << 20)
	fmt.Printf("\n完成：上传 %d 个 / 跳过 %d 个 / 失败 %d 个，用时 %s，均速 %.1f MiB/s\n",
		sum.Done, sum.Skip, sum.Fail, cost.Round(time.Millisecond), rate)
	if sum.Fail > 0 {
		for _, e := range sum.Errors {
			fmt.Println("  ! " + e)
		}
		return fmt.Errorf("%d 个文件失败", sum.Fail)
	}
	if firstErr != nil {
		return firstErr
	}
	return nil
}

func head(v []string, n int) []string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

func forceNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("（-force：其中 %d 个本来可跳过）", n)
}

// ---- 扫描 ----

func scan(root string, excl *regexp.Regexp) ([]entry, error) {
	root = filepath.Clean(root)
	var out []entry
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// 单个文件没权限不该中断整次同步，但要让人知道。
			fmt.Fprintf(os.Stderr, "跳过无法读取的路径 %s: %v\n", p, err)
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".fsgw-sync" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if excl != nil && excl.MatchString(rel) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, entry{
			Rel: rel, Size: fi.Size(), MTime: fi.ModTime().Unix(), Mode: int64(fi.Mode().Perm()),
		})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, err
}

func compileExcludes(patterns []string) *regexp.Regexp {
	if len(patterns) == 0 {
		return nil
	}
	parts := make([]string, 0, len(patterns))
	for _, p := range patterns {
		parts = append(parts, "(?:"+p+")")
	}
	re, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "排除规则无效，已忽略：%v\n", err)
		return nil
	}
	return re
}

// ---- HTTP ----

type client struct {
	cfg  *config
	http *http.Client
	sem  chan struct{} // 全局并发闸门：真正限制"同时在飞的请求数"
}

type infoResp struct {
	Protocol  string `json:"protocol"`
	ChunkSize int64  `json:"chunk_size"`
	MaxFiles  int    `json:"max_files"`
	Verify    string `json:"verify"`
}

func newClient(cfg *config) *client {
	tr := &http.Transport{
		MaxIdleConns:        cfg.workers * 2,
		MaxIdleConnsPerHost: cfg.workers * 2,
		MaxConnsPerHost:     cfg.workers * 2,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // 传的是已压缩媒体文件，再压一遍白烧 CPU
		ForceAttemptHTTP2:   false,
	}
	return &client{cfg: cfg, http: &http.Client{Transport: tr}, sem: make(chan struct{}, cfg.workers)}
}

func (c *client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+c.cfg.token)
	req.Header.Set("User-Agent", "fsgw-sync/"+clientVersion)
	return c.http.Do(req)
}

func (c *client) info() (infoResp, error) {
	var out infoResp
	req, _ := http.NewRequest(http.MethodGet, c.cfg.server+"/v1/info", nil)
	resp, err := c.do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return out, errFromBody(resp)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

func (c *client) createSession(prev string, cfg *config, files []entry) (string, bool, error) {
	var buf bytes.Buffer
	w := bufio.NewWriterSize(&buf, 1<<20)
	hdr := map[string]any{"root": cfg.root, "dest": cfg.dst, "client": "fsgw-sync/" + clientVersion, "checksum": cfg.checksum}
	if prev != "" {
		hdr["session"] = prev
	}
	b, _ := json.Marshal(hdr)
	w.Write(b)
	w.WriteByte('\n')
	for _, f := range files {
		line, _ := json.Marshal(map[string]any{"p": f.Rel, "s": f.Size, "t": f.MTime, "m": f.Mode})
		w.Write(line)
		w.WriteByte('\n')
	}
	w.Flush()

	req, _ := http.NewRequest(http.MethodPost, c.cfg.server+"/v1/session", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", false, errFromBody(resp)
	}
	var out struct {
		SessionID string `json:"session_id"`
		Resumed   bool   `json:"resumed"`
		Total     int    `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", false, err
	}
	return out.SessionID, out.Resumed, nil
}

func (c *client) plan(sid string) ([]planItem, error) {
	req, _ := http.NewRequest(http.MethodGet, c.cfg.server+"/v1/session/"+sid+"/plan", nil)
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errFromBody(resp)
	}
	var out []planItem
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var v struct {
			P string `json:"p"`
			A string `json:"a"`
			F string `json:"f"`
			S int64  `json:"s"`
			W string `json:"why"`
		}
		if err := json.Unmarshal(line, &v); err != nil {
			continue
		}
		out = append(out, planItem{Rel: v.P, FID: v.F, Size: v.S, Act: v.A})
	}
	return out, sc.Err()
}

func (c *client) finish(sid string) (struct {
	Done, Skip, Fail int
	Errors           []string
}, error) {
	var out struct {
		Done, Skip, Fail int
		Errors           []string
	}
	req, _ := http.NewRequest(http.MethodPost, c.cfg.server+"/v1/session/"+sid+"/finish", strings.NewReader("{}"))
	resp, err := c.do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return out, errFromBody(resp)
	}
	var raw struct {
		Done   int      `json:"done"`
		Skip   int      `json:"skip"`
		Fail   int      `json:"fail"`
		Errors []string `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return out, err
	}
	out.Done, out.Skip, out.Fail, out.Errors = raw.Done, raw.Skip, raw.Fail, raw.Errors
	return out, nil
}

// ---- 小文件打包 ----

func uploadBundles(c *client, sid string, items []planItem, byPath map[string]entry, cfg *config, prog *progress, note func(error)) error {
	// 分包：目标 ~8MiB 或 512 个文件，先到者为准。
	const maxBytes = 8 << 20
	const maxFiles = 512
	var batches [][]planItem
	cur := make([]planItem, 0, maxFiles)
	var curBytes int64
	for _, it := range items {
		if len(cur) > 0 && (curBytes+it.Size > maxBytes || len(cur) >= maxFiles) {
			batches = append(batches, cur)
			cur = make([]planItem, 0, maxFiles)
			curBytes = 0
		}
		cur = append(cur, it)
		curBytes += it.Size
	}
	if len(cur) > 0 {
		batches = append(batches, cur)
	}

	jobs := make(chan []planItem)
	var wg sync.WaitGroup
	// 打包通道用少量连接就够：每个包已经摊薄了往返开销。
	n := cfg.fileWorkers
	if n < 2 {
		n = 2
	}
	if n > 4 {
		n = 4
	}
	var failed atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range jobs {
				if err := sendBundle(c, sid, batch, byPath, cfg); err != nil {
					failed.Add(int64(len(batch)))
					note(fmt.Errorf("打包上传失败（%d 个文件）：%w", len(batch), err))
					continue
				}
				var sz int64
				for _, it := range batch {
					sz += it.Size
				}
				prog.add(len(batch), sz)
			}
		}()
	}
	for _, b := range batches {
		jobs <- b
	}
	close(jobs)
	wg.Wait()
	if failed.Load() > 0 {
		return fmt.Errorf("%d 个小文件上传失败", failed.Load())
	}
	return nil
}

func sendBundle(c *client, sid string, batch []planItem, byPath map[string]entry, cfg *config) error {
	var buf bytes.Buffer
	buf.WriteString("FGB1")
	var total int64
	for _, it := range batch {
		e := byPath[it.Rel]
		f, err := os.Open(filepath.Join(cfg.src, filepath.FromSlash(it.Rel)))
		if err != nil {
			return err
		}
		data := make([]byte, e.Size)
		if _, err := io.ReadFull(f, data); err != nil {
			f.Close()
			return fmt.Errorf("%s: %w", it.Rel, err)
		}
		f.Close()
		hdr, _ := json.Marshal(map[string]any{
			"p": it.Rel, "s": e.Size, "t": e.MTime, "m": e.Mode,
			"h": sha256Hex(data),
		})
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(hdr)))
		buf.Write(l[:])
		buf.Write(hdr)
		buf.Write(data)
		total += e.Size
	}

	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		req, _ := http.NewRequest(http.MethodPost, c.cfg.server+"/v1/session/"+sid+"/bundle", bytes.NewReader(buf.Bytes()))
		req.ContentLength = int64(buf.Len())
		c.sem <- struct{}{}
		resp, err := c.do(req)
		<-c.sem
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode == 200 {
				// 200 不等于"都写了"：服务端可能跳过某些帧（校验失败/占用）。
				// 客户端必须自己核对，否则会出现"报告成功、文件却没落盘"。
				var out struct {
					Written int      `json:"written"`
					Failed  int      `json:"failed"`
					Frames  int      `json:"frames"`
					Errors  []string `json:"errors"`
				}
				if err := json.Unmarshal(body, &out); err != nil {
					return fmt.Errorf("服务端响应无法解析: %w", err)
				}
				if out.Written != len(batch) || out.Failed > 0 || out.Frames != len(batch) {
					msg := ""
					if len(out.Errors) > 0 {
						msg = "；首个错误：" + out.Errors[0]
					}
					return fmt.Errorf("打包只写入 %d/%d 个（服务端失败 %d）%s",
						out.Written, len(batch), out.Failed, msg)
				}
				return nil
			}
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			// 4xx 不是重试能解决的
			if resp.StatusCode < 500 {
				return lastErr
			}
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
	}
	return lastErr
}

// ---- 大文件 ----

func uploadBigFiles(c *client, sid string, items []planItem, byPath map[string]entry, cfg *config, chunkSize int64, prog *progress, note func(error)) error {
	jobs := make(chan planItem)
	var wg sync.WaitGroup
	for i := 0; i < cfg.fileWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				if err := uploadOne(c, sid, it, byPath[it.Rel], chunkSize, cfg, prog); err != nil {
					note(fmt.Errorf("%s: %w", it.Rel, err))
					continue
				}
			}
		}()
	}
	for _, it := range items {
		jobs <- it
	}
	close(jobs)
	wg.Wait()
	return nil
}

func uploadOne(c *client, sid string, it planItem, e entry, chunkSize int64, cfg *config, prog *progress) error {
	nchunks := 0
	if it.Size > 0 {
		nchunks = int((it.Size + chunkSize - 1) / chunkSize)
	}
	have := map[int]bool{}
	if got, err := c.fileState(sid, it.FID); err == nil {
		for _, i := range got.Have {
			have[i] = true
		}
		if len(have) > 0 {
			fmt.Fprintf(os.Stderr, "\n  续传 %s：已有 %d/%d 块\n", it.Rel, len(have), nchunks)
		}
	}

	f, err := os.Open(filepath.Join(cfg.src, filepath.FromSlash(it.Rel)))
	if err != nil {
		return err
	}
	defer f.Close()

	// 文件内部再并行：一个 4GB 文件在单连接上只能跑出一条 TCP 的速度，
	// 而 8 条连接才能真正把千兆/2.5G 网卡吃满。
	chunkWorkers := cfg.workers
	if chunkWorkers > nchunks {
		chunkWorkers = nchunks
	}
	if chunkWorkers < 1 {
		chunkWorkers = 1
	}
	idxCh := make(chan int)
	errCh := make(chan error, chunkWorkers)
	var wg sync.WaitGroup
	for w := 0; w < chunkWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range idxCh {
				if have[idx] {
					continue
				}
				off := int64(idx) * chunkSize
				n := chunkSize
				if it.Size-off < n {
					n = it.Size - off
				}
				buf := make([]byte, n)
				if _, err := f.ReadAt(buf, off); err != nil {
					errCh <- fmt.Errorf("读本地文件第 %d 块：%w", idx, err)
					return
				}
				if err := c.putChunk(sid, it.FID, idx, buf); err != nil {
					errCh <- err
					return
				}
				prog.addBytes(n)
			}
		}()
	}
	for i := 0; i < nchunks; i++ {
		idxCh <- i
	}
	close(idxCh)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
	}

	if err := c.commit(sid, it.FID, it.Size, e.MTime, e.Mode); err != nil {
		return err
	}
	prog.add(1, 0)
	if cfg.verbose {
		fmt.Fprintf(os.Stderr, "\n  ✓ %s (%.1f MiB)\n", it.Rel, float64(it.Size)/(1<<20))
	}
	return nil
}

func (c *client) fileState(sid, fid string) (struct {
	Have []int `json:"have"`
}, error) {
	var out struct {
		Have []int `json:"have"`
	}
	req, _ := http.NewRequest(http.MethodGet, c.cfg.server+"/v1/session/"+sid+"/file/"+fid+"/state", nil)
	resp, err := c.do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return out, errFromBody(resp)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

func (c *client) putChunk(sid, fid string, idx int, data []byte) error {
	url := fmt.Sprintf("%s/v1/session/%s/file/%s/chunk/%d", c.cfg.server, sid, fid, idx)
	sha := sha256Hex(data)
	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
		req.ContentLength = int64(len(data))
		req.Header.Set("X-Chunk-SHA256", sha)
		c.sem <- struct{}{}
		resp, err := c.do(req)
		<-c.sem
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
			lastErr = fmt.Errorf("块 %d: HTTP %d %s", idx, resp.StatusCode, strings.TrimSpace(string(body)))
			if resp.StatusCode < 500 {
				return lastErr
			}
		} else {
			lastErr = fmt.Errorf("块 %d: %w", idx, err)
		}
		time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
	}
	return lastErr
}

func (c *client) commit(sid, fid string, size, mtime, mode int64) error {
	body, _ := json.Marshal(map[string]any{"size": size, "mtime": mtime, "mode": mode})
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, _ := http.NewRequest(http.MethodPost, c.cfg.server+"/v1/session/"+sid+"/file/"+fid+"/commit", bytes.NewReader(body))
		c.sem <- struct{}{}
		resp, err := c.do(req)
		<-c.sem
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
			lastErr = errFromBodyRaw(resp.StatusCode, b)
			if resp.StatusCode < 500 {
				return lastErr
			}
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt) * 400 * time.Millisecond)
	}
	return lastErr
}

// ---- 进度与状态 ----

type progress struct {
	total      int
	done       int64
	bytes      int64
	bytesTotal int64
	started    time.Time
	stopCh     chan struct{}
	once       sync.Once
}

func (p *progress) start() {
	p.started = time.Now()
	p.stopCh = make(chan struct{})
	// 输出被重定向到文件/管道时，回车刷新的进度条只会变成一堆乱码行。
	// 只有真终端才画进度条，否则安静地跑（日志更干净，脚本也更好处理）。
	if fi, err := os.Stderr.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return
	}
	go func() {
		t := time.NewTicker(400 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-p.stopCh:
				return
			case <-t.C:
				p.render()
			}
		}
	}()
}

func (p *progress) stop() {
	if p.stopCh == nil {
		return
	}
	p.once.Do(func() { close(p.stopCh) })
	fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", 90)+"\r")
}

func (p *progress) add(files int, bytes int64) {
	p.done += int64(files)
	if bytes > 0 {
		p.bytes += bytes
	}
}

func (p *progress) addBytes(n int64) {
	p.bytes += n
}

func (p *progress) render() {
	el := time.Since(p.started).Seconds()
	if el <= 0 {
		return
	}
	rate := float64(p.bytes) / el / (1 << 20)
	pct := 0.0
	if p.bytesTotal > 0 {
		pct = float64(p.bytes) / float64(p.bytesTotal) * 100
	}
	fmt.Fprintf(os.Stderr, "\r  %5.1f%%  %6.1f/%6.1f MiB  %6.1f MiB/s  文件 %d/%d   ",
		pct, float64(p.bytes)/(1<<20), float64(p.bytesTotal)/(1<<20), rate, p.done, p.total)
}

type stateFile struct {
	Server  string            `json:"server"`
	Root    string            `json:"root"`
	Dest    string            `json:"dst"`
	Session string            `json:"session"`
	SHA     map[string]string `json:"sha,omitempty"`
}

func stateKey(cfg *config) string {
	h := sha1.Sum([]byte(cfg.server + "|" + cfg.root + "|" + cfg.dst + "|" + cfg.src))
	return hex.EncodeToString(h[:8])
}

func statePath(cfg *config) string {
	if cfg.statePath != "" {
		return cfg.statePath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "fsgw-sync-"+stateKey(cfg)+".json")
	}
	return filepath.Join(home, ".fsgw-sync", stateKey(cfg)+".json")
}

func loadState(cfg *config, c *client) stateFile {
	st := stateFile{Server: cfg.server, Root: cfg.root, Dest: cfg.dst}
	b, err := os.ReadFile(statePath(cfg))
	if err == nil {
		_ = json.Unmarshal(b, &st)
	}
	// 换了目标就别拿旧会话去续——那会把文件写到别处。
	if st.Server != cfg.server || st.Root != cfg.root || st.Dest != cfg.dst {
		st.Session = ""
	}
	return st
}

func saveState(cfg *config, st stateFile) {
	p := statePath(cfg)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	b, _ := json.MarshalIndent(st, "", "  ")
	_ = os.WriteFile(p, b, 0o600)
}

// ---- 小工具 ----

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func errFromBody(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return errFromBodyRaw(resp.StatusCode, b)
}

func errFromBodyRaw(code int, b []byte) error {
	var v struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(b, &v); err == nil && v.Error != "" {
		return fmt.Errorf("HTTP %d: %s", code, v.Error)
	}
	return fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(b)))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
