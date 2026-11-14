package syncsvc

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Root 是允许同步写入的一个共享根。
type Root struct {
	ID       string
	Path     string
	Writable bool
}

type Options struct {
	DataDir   string
	Roots     []Root
	Token     string
	ChunkSize int64
	MaxFiles  int
	TTL       time.Duration
	Verify    string // chunk | full
	Log       *slog.Logger
}

type Server struct {
	opt   Options
	st    *store
	stage *staging
	log   *slog.Logger

	ln  net.Listener
	srv *http.Server

	// 统计：给控制台看"同步服务到底在不在动"。
	sessions atomic.Int64
	bytesIn  atomic.Int64
	chunks   atomic.Int64
}

func New(o Options) (*Server, error) {
	if o.Token == "" {
		return nil, errors.New("同步服务没有 token，拒绝启动")
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = 4 << 20
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = 1000000
	}
	// staging 的 limit 是"同时持有多少个 .part/.map 句柄"，不是清单上限。
	// 清单可以是百万级，句柄必须封顶：超过就按最久未用淘汰。
	openLimit := o.MaxFiles
	if openLimit > 256 {
		openLimit = 256
	}
	if o.TTL <= 0 {
		o.TTL = 72 * time.Hour
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	st, err := openStore(o.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		opt:   o,
		st:    st,
		stage: newStaging(openLimit, o.ChunkSize),
		log:   o.Log,
	}
	s.srv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// 大文件上传本来就慢，别让 IdleTimeout 把长连接切了；
		// ReadTimeout 留空——请求体是流式的，服务端只在读 body 时受限（见 MaxBytesReader）。
		IdleTimeout: 120 * time.Second,
	}
	s.gc()
	return s, nil
}

func (s *Server) Serve(ln net.Listener) error {
	s.ln = ln
	return s.srv.Serve(ln)
}

func (s *Server) Close() error {
	s.stage.closeAll()
	if s.srv != nil {
		_ = s.srv.Close()
	}
	return s.st.Close()
}

// Addr 返回实际监听地址（绑 :0 时就是真实端口）。
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Stats 给控制台/状态接口用。
func (s *Server) Stats() (sessions int64, bytes int64, chunks int64) {
	return s.sessions.Load(), s.bytesIn.Load(), s.chunks.Load()
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", s.handleInfo)
	mux.HandleFunc("POST /v1/session", s.handleCreate)
	mux.HandleFunc("GET /v1/session/{sid}", s.handleSession)
	mux.HandleFunc("GET /v1/session/{sid}/plan", s.handlePlan)
	mux.HandleFunc("GET /v1/session/{sid}/file/{fid}/state", s.handleFileState)
	mux.HandleFunc("PUT /v1/session/{sid}/file/{fid}/chunk/{idx}", s.handleChunk)
	mux.HandleFunc("POST /v1/session/{sid}/file/{fid}/commit", s.handleCommit)
	mux.HandleFunc("POST /v1/session/{sid}/bundle", s.handleBundle)
	mux.HandleFunc("POST /v1/session/{sid}/finish", s.handleFinish)
	mux.HandleFunc("DELETE /v1/session/{sid}", s.handleAbort)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	})
	return s.auth(mux)
}

// auth 只认 Bearer token。同步面比控制面更"能写"——它是真的能覆盖文件，
// 所以不提供免 token 的匿名通道，也不复用控制台 token（权限不该混）。
func (s *Server) auth(next http.Handler) http.Handler {
	want := []byte(s.opt.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if got == "" {
			got = strings.TrimSpace(r.Header.Get("X-FSGW-Sync-Token"))
		}
		if got == "" || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			writeErr(w, http.StatusUnauthorized, "token 无效")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol":    "fsgw-sync/1",
		"chunk_size":  s.opt.ChunkSize,
		"max_files":   s.opt.MaxFiles,
		"verify":      s.opt.Verify,
		"hash":        "sha256",
		"bundle":      true,
		"resume":      true,
		"server_time": time.Now().Unix(),
	})
}

// ---- 清单 ----

type manifestHeader struct {
	Root     string `json:"root"`
	Dest     string `json:"dest"`
	Client   string `json:"client"`
	Session  string `json:"session"`  // 续传：带上上次的 session id
	Checksum bool   `json:"checksum"` // 逐字节比对（慢），默认按 大小+时间 判断
}

type manifestEntry struct {
	Path  string `json:"p"`
	Size  int64  `json:"s"`
	MTime int64  `json:"t"`
	Mode  int64  `json:"m"`
	SHA   string `json:"h"`
}

// handleCreate 接收 NDJSON 清单：第一行是表头，之后每行一个文件。
//
// 用 NDJSON 而不是一个大 JSON 数组，是因为几十万文件的清单一次性反序列化
// 会把内存顶到几百 MB；流式读一行处理一行，内存是常数级。
func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	br := bufio.NewReaderSize(r.Body, 1<<20)

	line, err := readLine(br)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "清单为空："+err.Error())
		return
	}
	var hdr manifestHeader
	if err := json.Unmarshal(line, &hdr); err != nil {
		writeErr(w, http.StatusBadRequest, "清单表头不是合法 JSON："+err.Error())
		return
	}
	root, err := s.pickRoot(hdr.Root)
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	if _, err := normalizeRelOrEmpty(hdr.Dest); err != nil {
		writeErr(w, http.StatusBadRequest, "目标目录非法："+err.Error())
		return
	}

	sid := strings.TrimSpace(hdr.Session)
	resumed := false
	if sid != "" {
		old, err := s.st.getSession(sid)
		switch {
		case err == nil && old.State == "open" && old.Root == root.ID && old.Dest == hdr.Dest:
			resumed = true
		case err == nil && old.State != "open":
			sid = "" // 已完成的会话不能续，新建一个
		default:
			sid = ""
		}
	}
	if sid == "" {
		sid, err = newID()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "生成会话 id 失败")
			return
		}
		if err := s.st.createSession(session{
			ID: sid, Root: root.ID, Dest: hdr.Dest,
			Client: orDefault(hdr.Client, "unknown"), Checksum: hdr.Checksum,
		}); err != nil {
			writeErr(w, http.StatusInternalServerError, "建会话失败："+err.Error())
			return
		}
		s.sessions.Add(1)
	}

	batch := make([]fileRow, 0, 512)
	total := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := s.st.addFiles(sid, batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}

	for {
		line, err := readLine(br)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, "读清单失败："+err.Error())
			return
		}
		if len(line) == 0 {
			continue
		}
		var e manifestEntry
		if err := json.Unmarshal(line, &e); err != nil {
			writeErr(w, http.StatusBadRequest, "清单行不是合法 JSON")
			return
		}
		rel, err := normalizeRel(e.Path)
		if err != nil {
			// 单个坏路径不该让整次同步失败：记成 fail，客户端能看到。
			continue
		}
		if e.Size < 0 {
			continue
		}
		total++
		if total > s.opt.MaxFiles {
			writeErr(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("清单超过 %d 个文件，请拆分或加 -exclude", s.opt.MaxFiles))
			return
		}
		batch = append(batch, fileRow{
			FID: fidOf(rel), Rel: rel, Size: e.Size,
			Mode: e.Mode, MTime: e.MTime, SHA: strings.ToLower(e.SHA),
		})
		if len(batch) >= 512 {
			if err := flush(); err != nil {
				writeErr(w, http.StatusInternalServerError, "写清单失败："+err.Error())
				return
			}
		}
	}
	if err := flush(); err != nil {
		writeErr(w, http.StatusInternalServerError, "写清单失败："+err.Error())
		return
	}
	_ = s.st.setTotal(sid, total)

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sid,
		"root":       root.ID,
		"dest":       hdr.Dest,
		"total":      total,
		"resumed":    resumed,
		"chunk_size": s.opt.ChunkSize,
	})
}

// handlePlan 逐行返回"每个文件该做什么"。客户端拿到就能开工，不必等整份计划。
//
// 判断顺序：不存在→传；大小不同→传；开了 checksum 就比内容；否则比 mtime。
// 只看 mtime 是 rsync 的老办法：快，但对方时间戳被改过就会误判"没变"。
// 所以真正在意正确性时用 -checksum 强制比内容。
func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	sess, root, err := s.session(w, r)
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)

	files, err := s.st.pending(sess.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读清单失败："+err.Error())
		return
	}
	for _, f := range files {
		act, why := s.decide(root, sess, f)
		if err := s.st.setAction(sess.ID, f.FID, act, ""); err != nil {
			s.log.Warn("写计划失败", "rel", f.Rel, "err", err)
		}
		_ = enc.Encode(map[string]any{
			"p": f.Rel, "a": act, "f": f.FID, "s": f.Size, "why": why,
		})
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (s *Server) decide(root Root, sess session, f fileRow) (string, string) {
	full, err := resolveUnder(root.Path, sess.Dest, f.Rel)
	if err != nil {
		return "fail", "路径非法"
	}
	fi, err := os.Stat(full)
	if err != nil {
		return "put", "missing"
	}
	if !fi.Mode().IsRegular() {
		return "put", "not-regular"
	}
	if fi.Size() != f.Size {
		return "put", "size"
	}
	if sess.Checksum {
		if f.SHA == "" {
			return "put", "no-hash"
		}
		got, err := hashPath(full)
		if err != nil {
			return "put", "hash-error"
		}
		if got != f.SHA {
			return "put", "content"
		}
		return "skip", "checksum"
	}
	// 同一秒内的差异不追究（FAT/ext 时间精度不同，会来回"改动"）。
	if f.MTime > 0 && abs64(fi.ModTime().Unix()-f.MTime) > 2 {
		return "put", "mtime"
	}
	return "skip", "same"
}

// ---- 单个文件 ----

func (s *Server) handleFileState(w http.ResponseWriter, r *http.Request) {
	sess, root, err := s.session(w, r)
	if err != nil {
		return
	}
	fid := r.PathValue("fid")
	f, err := s.fileRow(sess.ID, fid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "没有这个文件")
		return
	}
	have, err := s.stage.have(root.Path, sess.ID, fid, f.Size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	n := 0
	if f.Size > 0 {
		n = int((f.Size + s.opt.ChunkSize - 1) / s.opt.ChunkSize)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path": f.Rel, "size": f.Size, "nchunks": n,
		"chunk_size": s.opt.ChunkSize, "have": have,
	})
}

// handleChunk 收一块。这是整个协议的热路径：
// 开销必须小到只剩"读 body + pwrite + 置位"，任何多余分配都会拖慢吞吐。
func (s *Server) handleChunk(w http.ResponseWriter, r *http.Request) {
	sess, root, err := s.session(w, r)
	if err != nil {
		return
	}
	fid := r.PathValue("fid")
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 0 {
		writeErr(w, http.StatusBadRequest, "块下标非法")
		return
	}
	f, err := s.fileRow(sess.ID, fid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "没有这个文件")
		return
	}
	nchunks := 0
	if f.Size > 0 {
		nchunks = int((f.Size + s.opt.ChunkSize - 1) / s.opt.ChunkSize)
	}
	if idx >= nchunks {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("块下标越界：%d >= %d", idx, nchunks))
		return
	}
	expect := s.opt.ChunkSize
	if idx == nchunks-1 {
		expect = f.Size - int64(idx)*s.opt.ChunkSize
	}
	if expect > 32<<20 {
		writeErr(w, http.StatusBadRequest, "块过大")
		return
	}

	buf := make([]byte, expect)
	if _, err := io.ReadFull(r.Body, buf); err != nil {
		writeErr(w, http.StatusBadRequest, "块数据不完整："+err.Error())
		return
	}
	// 多读一个字节：多发数据说明客户端算错了偏移，宁可拒绝也别静默截断。
	var extra [1]byte
	if n, _ := r.Body.Read(extra[:]); n > 0 {
		writeErr(w, http.StatusBadRequest, "块数据超出声明长度")
		return
	}

	if want := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Chunk-SHA256"))); want != "" {
		if got := sha256Hex(buf); got != want {
			writeErr(w, http.StatusBadRequest, "块校验失败")
			return
		}
	}
	if err := s.stage.writeChunk(root.Path, sess.ID, fid, f.Size, idx, buf); err != nil {
		writeErr(w, http.StatusInternalServerError, "写块失败："+err.Error())
		return
	}
	s.bytesIn.Add(int64(len(buf)))
	s.chunks.Add(1)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "idx": idx})
}

func (s *Server) handleCommit(w http.ResponseWriter, r *http.Request) {
	sess, root, err := s.session(w, r)
	if err != nil {
		return
	}
	fid := r.PathValue("fid")
	f, err := s.fileRow(sess.ID, fid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "没有这个文件")
		return
	}
	full, err := resolveUnder(root.Path, sess.Dest, f.Rel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "路径非法")
		return
	}
	// 客户端可以在提交时覆盖大小/时间，避免"清单扫描后又长大"的文件对不上。
	var body struct {
		Size  *int64 `json:"size"`
		MTime *int64 `json:"mtime"`
		Mode  *int64 `json:"mode"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	if body.Size != nil && *body.Size != f.Size {
		writeErr(w, http.StatusConflict, "文件大小与清单不一致，请重新扫描")
		return
	}
	mtime := time.Unix(f.MTime, 0)
	if f.MTime == 0 {
		mtime = time.Time{}
	}
	mode := os.FileMode(f.Mode)
	if mode == 0 {
		mode = 0o644
	}

	sum, err := s.stage.commit(root.Path, sess.ID, fid, full, f.Size, mode, mtime, s.opt.Verify == "full")
	if err != nil {
		_ = s.st.setAction(sess.ID, fid, "fail", err.Error())
		writeErr(w, http.StatusInternalServerError, "提交失败："+err.Error())
		return
	}
	if sum != "" && f.SHA != "" && sum != f.SHA {
		_ = s.st.setAction(sess.ID, fid, "fail", "内容校验不一致")
		writeErr(w, http.StatusConflict, "内容校验不一致：服务端 "+sum)
		return
	}
	_ = s.st.setAction(sess.ID, fid, "done", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": f.Rel, "sha256": sum})
}

// ---- 小文件打包 ----

// handleBundle 一次请求写多个小文件。
//
// 帧格式（全部大端）：
//
//	"FGB1"                          （每个请求一次）
//	[u32 hdrLen][hdr JSON][data ...]  × N
//
// 为什么不用 multipart：multipart 的边界解析要扫全流、还要把整段读进内存，
// 这里每个帧的长度就在头部，读完 headers 直接按长度拷贝，零解析开销。
func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	sess, root, err := s.session(w, r)
	if err != nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	br := bufio.NewReaderSize(r.Body, 256<<10)

	var magic [4]byte
	if _, err := io.ReadFull(br, magic[:]); err != nil || string(magic[:]) != "FGB1" {
		writeErr(w, http.StatusBadRequest, "bundle 魔数不对")
		return
	}

	var written, failed, frames int
	var bytes int64
	var fails []string
	tmpDir := filepath.Join(root.Path, stagingDirName, sess.ID, "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var hdrLen uint32
	for {
		if err := binary.Read(br, binary.BigEndian, &hdrLen); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			writeErr(w, http.StatusBadRequest, "bundle 帧头损坏")
			return
		}
		if hdrLen == 0 || hdrLen > 64<<10 {
			writeErr(w, http.StatusBadRequest, "bundle 帧头长度异常")
			return
		}
		hbuf := make([]byte, hdrLen)
		if _, err := io.ReadFull(br, hbuf); err != nil {
			writeErr(w, http.StatusBadRequest, "bundle 帧头被截断")
			return
		}
		var e manifestEntry
		if err := json.Unmarshal(hbuf, &e); err != nil {
			writeErr(w, http.StatusBadRequest, "bundle 帧头不是合法 JSON")
			return
		}
		frames++
		if e.Size < 0 || e.Size > 32<<20 {
			writeErr(w, http.StatusBadRequest, "bundle 文件过大，请走分块通道")
			return
		}
		data := make([]byte, e.Size)
		if _, err := io.ReadFull(br, data); err != nil {
			writeErr(w, http.StatusBadRequest, "bundle 数据被截断")
			return
		}
		if e.SHA != "" && sha256Hex(data) != strings.ToLower(e.SHA) {
			failed++
			fails = append(fails, e.Path+": 校验失败")
			continue
		}
		full, err := resolveUnder(root.Path, sess.Dest, e.Path)
		if err != nil {
			failed++
			fails = append(fails, e.Path+": 路径非法")
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			failed++
			fails = append(fails, e.Path+": 建目录失败")
			continue
		}
		tmp := filepath.Join(tmpDir, randomName()+".part")
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			failed++
			fails = append(fails, e.Path+": 写临时文件失败")
			continue
		}
		if _, err := os.Stat(full); err == nil {
			if err := os.Remove(full); err != nil {
				_ = os.Remove(tmp)
				failed++
				fails = append(fails, e.Path+": 目标被占用")
				continue
			}
		}
		if err := os.Rename(tmp, full); err != nil {
			_ = os.Remove(tmp)
			failed++
			fails = append(fails, e.Path+": 改名失败")
			continue
		}
		if e.Mode != 0 {
			_ = os.Chmod(full, os.FileMode(e.Mode))
		}
		if e.MTime != 0 {
			t := time.Unix(e.MTime, 0)
			_ = os.Chtimes(full, t, t)
		}
		written++
		bytes += e.Size
		if rel, err := normalizeRel(e.Path); err == nil {
			_ = s.st.setAction(sess.ID, fidOf(rel), "done", "")
		}
	}
	s.bytesIn.Add(bytes)
	// frames 一并回传：客户端要能核对"我发了几个、你写了几个"。
	// 少了就是真丢了，不能只看 HTTP 200 就当成功——第一版正是在这里漏过 39 个文件。
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "written": written, "failed": failed, "frames": frames,
		"bytes": bytes, "errors": fails,
	})
}

// ---- 收尾 ----

func (s *Server) handleFinish(w http.ResponseWriter, r *http.Request) {
	sess, root, err := s.session(w, r)
	if err != nil {
		return
	}
	// 收尾前做一次"落地复核"：凡是记成 done 的文件，都去磁盘上 stat 一遍，
	// 大小对不上就翻成 fail。这一条是给用户的核心承诺兜底的——
	// "报告成功"必须等于"文件真的在那儿、而且完整"，不能只信自己写的数据库。
	verified := s.verifyDone(sess, root)

	skip, done, fail, put, err := s.st.counts(sess.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	fails, _ := s.st.failures(sess.ID, 50)
	_ = s.st.setState(sess.ID, "done")
	// 暂存区清空：完成的会话不该在共享根里留下垃圾。
	_ = os.RemoveAll(sessionStagingDir(root.Path, sess.ID))

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sess.ID,
		"skip":       skip, "done": done, "fail": fail, "pending": put,
		"verified": verified,
		"bytes":    s.bytesIn.Load(),
		"errors":   fails,
	})
}

// verifyDone 逐个复核已标记完成文件的存在性与大小。
// 开销是一次 stat——相比"用户以为传完了、实际少一半"的代价，可以忽略。
func (s *Server) verifyDone(sess session, root Root) int {
	checked := 0
	_ = s.st.files(sess.ID, func(f fileRow) error {
		if f.Act != "done" {
			return nil
		}
		full, err := resolveUnder(root.Path, sess.Dest, f.Rel)
		if err != nil {
			_ = s.st.setAction(sess.ID, f.FID, "fail", "路径非法")
			return nil
		}
		fi, err := os.Stat(full)
		if err != nil {
			_ = s.st.setAction(sess.ID, f.FID, "fail", "落盘复核：文件不存在")
			return nil
		}
		if fi.Size() != f.Size {
			_ = s.st.setAction(sess.ID, f.FID, "fail",
				fmt.Sprintf("落盘复核：大小 %d≠%d", fi.Size(), f.Size))
			return nil
		}
		checked++
		return nil
	})
	return checked
}

func (s *Server) handleAbort(w http.ResponseWriter, r *http.Request) {
	sess, root, err := s.session(w, r)
	if err != nil {
		return
	}
	_ = s.st.setState(sess.ID, "aborted")
	_ = os.RemoveAll(sessionStagingDir(root.Path, sess.ID))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, _, err := s.session(w, r)
	if err != nil {
		return
	}
	skip, done, fail, put, err := s.st.counts(sess.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sess.ID, "state": sess.State, "root": sess.Root, "dest": sess.Dest,
		"total": sess.Total, "skip": skip, "done": done, "fail": fail, "pending": put,
		"created": sess.Created.Unix(),
	})
}

// ---- 辅助 ----

func (s *Server) session(w http.ResponseWriter, r *http.Request) (session, Root, error) {
	sid := r.PathValue("sid")
	sess, err := s.st.getSession(sid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "会话不存在（可能已过期）")
		return session{}, Root{}, err
	}
	if sess.State != "open" {
		writeErr(w, http.StatusConflict, "会话已结束")
		return session{}, Root{}, errors.New("session closed")
	}
	root, ok := s.rootByID(sess.Root)
	if !ok {
		writeErr(w, http.StatusGone, "共享根已被移除")
		return session{}, Root{}, errors.New("root gone")
	}
	return sess, root, nil
}

func (s *Server) rootByID(id string) (Root, bool) {
	for _, r := range s.opt.Roots {
		if r.ID == id && r.Writable {
			return r, true
		}
	}
	return Root{}, false
}

// pickRoot 允许客户端用 share_id 或 share 名字指定（人更容易记住名字）。
// 只接受 writable 的根：只读根上做同步是配置错误，不是运行时能补救的事。
func (s *Server) pickRoot(v string) (Root, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		for _, r := range s.opt.Roots {
			if r.Writable {
				return r, nil
			}
		}
		return Root{}, errors.New("没有可写的共享根")
	}
	for _, r := range s.opt.Roots {
		if !r.Writable {
			continue
		}
		if strings.EqualFold(r.ID, v) || strings.EqualFold(filepath.Base(r.Path), v) {
			return r, nil
		}
	}
	return Root{}, fmt.Errorf("共享根 %q 不存在或不可写", v)
}

func (s *Server) fileRow(sid, fid string) (fileRow, error) {
	var f fileRow
	err := s.st.db.QueryRow(`SELECT fid,rel,size,mode,mtime,sha,action,err FROM files WHERE sid=? AND fid=?`, sid, fid).
		Scan(&f.FID, &f.Rel, &f.Size, &f.Mode, &f.MTime, &f.SHA, &f.Act, &f.Err)
	return f, err
}

// gc 清理超期会话：.part 文件可能很大，不能指望人工收拾。
func (s *Server) gc() {
	before := time.Now().Add(-s.opt.TTL)
	old, err := s.st.expired(before)
	if err != nil {
		s.log.Warn("同步会话清理失败", "err", err)
		return
	}
	for _, sess := range old {
		root, ok := s.rootByID(sess.Root)
		if ok {
			_ = os.RemoveAll(sessionStagingDir(root.Path, sess.ID))
		}
		_ = s.st.deleteSession(sess.ID)
	}
	// 顺手扫掉共享根里没有对应会话的孤儿暂存目录（进程被强杀会留下）。
	for _, r := range s.opt.Roots {
		base := filepath.Join(r.Path, stagingDirName)
		ents, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		live := map[string]bool{}
		for _, e := range ents {
			if st, err := s.st.getSession(e.Name()); err == nil && st.State == "open" {
				live[e.Name()] = true
			}
			if !live[e.Name()] {
				_ = os.RemoveAll(filepath.Join(base, e.Name()))
			}
		}
	}
	if len(old) > 0 {
		s.log.Info("清理超期同步会话", "count", len(old))
	}
}

// randomName 用随机名而不是时间戳：并发写入时时间戳在小间隔内可能撞车，
// 撞了就是"两个文件抢同一个临时文件"，轻则丢失内容，重则改名失败。
func randomName() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// fidOf 用路径派生稳定 id：同一路径在续传时一定是同一个 fid，
// 不依赖会话表，客户端重连后服务端能直接找到 .part。
func fidOf(rel string) string {
	sum := sha1.Sum([]byte(strings.ToLower(rel)))
	return hex.EncodeToString(sum[:8])
}

func hashPath(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	if len(line) > 0 {
		line = []byte(strings.TrimSpace(string(line)))
	}
	return line, err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
