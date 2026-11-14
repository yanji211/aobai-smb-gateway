// Package webdav 实现外部只读面：只注册 GET/HEAD/PROPFIND/OPTIONS，
// 其余方法一律 405（见 docs/01 第 10 节）。
package webdav

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"fsgw/internal/audit"
	"fsgw/internal/index"
	"fsgw/internal/vfs"
)

type Server struct {
	v       *vfs.VFS
	st      *index.Store
	log     *slog.Logger
	aud     *audit.Log
	creds   []Cred
	over    map[string]bool
	enabled bool
}

// Cred 是一条可登录的账号。口令要么给摘要 Hash，要么给明文 Password（启动时现算）。
type Cred struct {
	User     string
	Password string
	Hash     string
}

type Options struct {
	VFS      *vfs.VFS
	Store    *index.Store
	Log      *slog.Logger
	Audit    *audit.Log
	User     string
	Password string
	Hash     string
	// Creds 是额外账号列表，与上面的单账号写法取并集。
	Creds    []Cred
	Writable map[string]bool
}

func New(o Options) *Server {
	s := &Server{
		v:    o.VFS,
		st:   o.Store,
		log:  o.Log,
		aud:  o.Audit,
		over: o.Writable,
	}
	if o.User != "" {
		s.creds = append(s.creds, normalizeCred(Cred{User: o.User, Password: o.Password, Hash: o.Hash}))
	}
	for _, c := range o.Creds {
		s.creds = append(s.creds, normalizeCred(c))
	}
	// 摘掉空账号，避免 "" == "" 这种情况被放行。
	kept := s.creds[:0]
	for _, c := range s.creds {
		if c.User != "" && c.Hash != "" {
			kept = append(kept, c)
		}
	}
	s.creds = kept
	return s
}

// normalizeCred 补上摘要：给了 Hash 就用 Hash，否则拿明文现算。
func normalizeCred(c Cred) Cred {
	if c.Hash == "" && c.Password != "" {
		c.Hash = HashPassword(c.Password)
	}
	c.Password = ""
	return c
}

func (s *Server) Handler() http.Handler {
	return s.auth(http.HandlerFunc(s.route))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !s.check(u, p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="fsgw"`)
			s.record(r, "deny", "认证失败")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// check 遍历账号表逐个比对。每个账号都跑一次 VerifyPassword，
// 不因为用户名不匹配就提前返回，避免用响应时间探出"哪些账号存在"。
func (s *Server) check(user, pass string) bool {
	matched := false
	for _, c := range s.creds {
		if subtle.ConstantTimeCompare([]byte(user), []byte(c.User)) == 1 && VerifyPassword(pass, c.Hash) {
			matched = true
		}
	}
	return matched
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("DAV", "1")
		w.Header().Set("Allow", "OPTIONS, GET, HEAD, PROPFIND")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet, http.MethodHead:
		s.get(w, r)
	case "PROPFIND":
		s.propfind(w, r)
	default:
		// PUT / DELETE / MKCOL / MOVE / COPY / PROPPATCH / LOCK 全部拒绝。
		s.record(r, "deny", "方法未允许: "+r.Method)
		w.Header().Set("Allow", "OPTIONS, GET, HEAD, PROPFIND")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	res, err := s.v.FromURLPath(r.URL.Path)
	if err != nil {
		s.record(r, "deny", err.Error())
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 浏览器用 GET 打开目录，WebDAV 客户端用 PROPFIND。
	// 共享根本身在库里没有对应行，所以先判断"是不是目录"，再决定是列目录还是取文件。
	if res.Rel == "" || isDir(s.st, res.Key) {
		s.listing(w, r, res)
		return
	}

	row, err := s.st.ByPath(res.Key)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// 先查库确认，再回源读字节；读失败如实报错，不反向修正库。
	f, err := os.Open(vfs.EnsureLongPath(res.Abs))
	if err != nil {
		s.record(r, "error", "读取失败: "+err.Error())
		http.Error(w, "backend read failed", http.StatusBadGateway)
		return
	}
	defer f.Close()

	w.Header().Set("ETag", etagOf(row))
	if row.Hash.Valid {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	http.ServeContent(w, r, row.Name, time.Unix(0, row.MtimeNs), f)
	s.record(r, "ok", "GET "+res.Rel)
}

func (s *Server) propfind(w http.ResponseWriter, r *http.Request) {
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "1"
	}
	now := time.Now().UTC().Format(http.TimeFormat)

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<D:multistatus xmlns:D="DAV:">` + "\n")

	add := func(href, name string, isDir bool, size int64, mtime time.Time, etag string) {
		b.WriteString("  <D:response>\n")
		b.WriteString("    <D:href>" + esc(href) + "</D:href>\n")
		b.WriteString("    <D:propstat>\n      <D:prop>\n")
		b.WriteString("        <D:displayname>" + esc(name) + "</D:displayname>\n")
		if isDir {
			b.WriteString("        <D:resourcetype><D:collection/></D:resourcetype>\n")
		} else {
			b.WriteString("        <D:resourcetype/>\n")
			b.WriteString("        <D:getcontentlength>" + strconv.FormatInt(size, 10) + "</D:getcontentlength>\n")
		}
		b.WriteString("        <D:getlastmodified>" + mtime.UTC().Format(http.TimeFormat) + "</D:getlastmodified>\n")
		if etag != "" {
			b.WriteString("        <D:getetag>" + esc(etag) + "</D:getetag>\n")
		}
		b.WriteString("      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n")
		b.WriteString("  </D:response>\n")
	}

	if strings.Trim(r.URL.Path, "/") == "" {
		// 根：把共享列成集合，方便客户端挑。
		for _, sh := range s.v.Shares() {
			add("/"+url.PathEscape(sh.Name)+"/", sh.Name, true, 0, time.Now(), "")
		}
		b.WriteString("</D:multistatus>")
		s.writeXML(w, b.String())
		return
	}

	res, err := s.v.FromURLPath(r.URL.Path)
	if err != nil {
		s.record(r, "deny", err.Error())
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	hrefBase := "/" + url.PathEscape(res.Share.Name)
	if res.Rel != "" {
		hrefBase += "/" + escapePath(res.Rel)
	}

	// 共享根本身在库里没有对应行（'' 是隐式存在的根），这里直接合成一个 collection。
	if res.Rel == "" {
		rootHref := hrefBase + "/"
		add(rootHref, res.Share.Name, true, 0, time.Now(), "")
		if depth != "0" {
			children, err := s.st.ReadDir("")
			if err != nil {
				s.log.Warn("列举共享根失败", "err", err)
			}
			for _, c := range children {
				childIsDir := c.Kind == index.KindDir
				h := rootHref + escapeSegment(c.Name)
				if childIsDir {
					h += "/"
				}
				add(h, c.Name, childIsDir, c.Size, time.Unix(0, c.MtimeNs), etagOf(&c))
			}
		}
		b.WriteString("</D:multistatus>")
		s.record(r, "ok", "PROPFIND "+res.Share.Name)
		s.writeXML(w, b.String())
		return
	}

	row, err := s.st.ByPath(res.Key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	isDir := row.Kind == index.KindDir
	if isDir && !strings.HasSuffix(hrefBase, "/") {
		hrefBase += "/"
	}
	add(hrefBase, row.Name, isDir, row.Size, time.Unix(0, row.MtimeNs), etagOf(row))

	if isDir && depth != "0" {
		children, err := s.st.ReadDir(res.Key)
		if err != nil {
			s.log.Warn("列举目录失败", "path", res.Rel, "err", err)
		}
		for _, c := range children {
			childIsDir := c.Kind == index.KindDir
			h := hrefBase + escapeSegment(c.Name)
			if childIsDir {
				h += "/"
			}
			add(h, c.Name, childIsDir, c.Size, time.Unix(0, c.MtimeNs), etagOf(&c))
		}
	}

	b.WriteString("</D:multistatus>")
	_ = now
	s.record(r, "ok", "PROPFIND "+res.Rel)
	s.writeXML(w, b.String())
}

func (s *Server) writeXML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusMultiStatus)
	w.Write([]byte(body))
}

func (s *Server) record(r *http.Request, result, detail string) {
	if s.aud == nil {
		return
	}
	s.aud.Write(audit.Entry{
		Source: "webdav",
		Action: r.Method,
		Path:   r.URL.Path,
		Result: result,
		Detail: detail,
		Remote: r.RemoteAddr,
	})
}

func etagOf(f *index.FileRow) string {
	if f.Hash.Valid && len(f.Hash.String) >= 12 {
		return `"` + f.Hash.String[:12] + `"`
	}
	return fmt.Sprintf(`"%x-%x"`, f.MtimeNs, f.Size)
}

func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func escapePath(rel string) string {
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func escapeSegment(name string) string { return url.PathEscape(name) }

// isDir 判断路径是不是目录。查不到行时按"不是目录"处理。
func isDir(st *index.Store, key string) bool {
	row, err := st.ByPath(key)
	if err != nil {
		return false
	}
	return row.Kind == index.KindDir
}

// listing 给浏览器看的只读目录页。
// WebDAV 客户端走 PROPFIND，不受这个页面影响；这里只是让人能用浏览器看一眼。
func (s *Server) listing(w http.ResponseWriter, r *http.Request, res vfs.Resolved) {
	rows, err := s.st.ReadDir(res.Key)
	if err != nil {
		s.log.Warn("列举目录失败", "path", res.Rel, "err", err)
		http.Error(w, "listing failed", http.StatusInternalServerError)
		return
	}

	base := "/" + url.PathEscape(res.Share.Name)
	if res.Rel != "" {
		base += "/" + escapePath(res.Rel)
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>` + htmlEscape(displayName(res)) + `</title>`)
	b.WriteString(`<style>
body{font:14px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;margin:0;background:#f7f8fa;color:#1f2933}
.wrap{max-width:900px;margin:0 auto;padding:28px 20px}
h1{font-size:18px;margin:0 0 4px}
.sub{color:#5f6b7a;font-size:13px;margin-bottom:18px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e8ef;border-radius:10px;overflow:hidden}
th,td{padding:9px 14px;border-bottom:1px solid #eef1f6;text-align:left}
th{background:#fafbfd;color:#5f6b7a;font-size:12px}
tr:last-child td{border-bottom:0}
a{color:#2563eb;text-decoration:none}
a:hover{text-decoration:underline}
.size,.time{color:#5f6b7a;font-size:12.5px;white-space:nowrap}
.empty{color:#93a1b3;padding:26px;text-align:center}
.note{margin-top:16px;color:#93a1b3;font-size:12px}
</style></head><body><div class="wrap">`)

	title := displayName(res)
	b.WriteString("<h1>" + htmlEscape(title) + "</h1>")
	b.WriteString(`<div class="sub">只读共享 · 索引实时同步 · 共 ` + strconv.Itoa(len(rows)) + ` 项</div>`)

	b.WriteString(`<table><thead><tr><th>名称</th><th style="width:110px">大小</th><th style="width:170px">修改时间</th></tr></thead><tbody>`)
	if res.Rel != "" {
		b.WriteString(`<tr><td><a href="../">..</a></td><td class="size">-</td><td class="time">-</td></tr>`)
	}
	for _, row := range rows {
		name := row.Name
		href := base + "/" + escapeSegment(row.Name)
		if row.Kind == index.KindDir {
			name += "/"
			href += "/"
		}
		b.WriteString(`<tr><td><a href="` + htmlEscape(href) + `">` + htmlEscape(name) + `</a></td>`)
		if row.Kind == index.KindDir {
			b.WriteString(`<td class="size">-</td>`)
		} else {
			b.WriteString(`<td class="size">` + humanSize(row.Size) + `</td>`)
		}
		b.WriteString(`<td class="time">` + time.Unix(0, row.MtimeNs).Local().Format("2006-01-02 15:04") + `</td></tr>`)
	}
	if len(rows) == 0 {
		b.WriteString(`<tr><td class="empty" colspan="3">这个目录是空的</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<div class="note">这是只读视图。需要写入请走局域网 SMB 共享（\\\\主机\` + htmlEscape(res.Share.Name) + `）。</div>`)
	b.WriteString(`</div></body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(b.String()))
	s.record(r, "ok", "LIST "+res.Rel)
}

func displayName(res vfs.Resolved) string {
	if res.Rel == "" {
		return res.Share.Name
	}
	return res.Rel
}

func htmlEscape(s string) string { return html.EscapeString(s) }

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// HashPassword 生成 sha256$salt$hash 形式的口令摘要。
// 刻意不引第三方 bcrypt：本地单口令场景，十万次迭代足够了。
func HashPassword(pw string) string {
	if pw == "" {
		return ""
	}
	salt := make([]byte, 8)
	h := sha256.Sum256([]byte(fmt.Sprintf("fsgw-salt-%d-%s", time.Now().UnixNano(), pw)))
	copy(salt, h[:8])
	sum := derive(pw, salt)
	return "sha256$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(sum)
}

func VerifyPassword(pw, stored string) bool {
	if stored == "" {
		return false
	}
	parts := strings.Split(stored, "$")
	if len(parts) != 3 || parts[0] != "sha256" {
		return subtle.ConstantTimeCompare([]byte(pw), []byte(stored)) == 1
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := derive(pw, salt)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func derive(pw string, salt []byte) []byte {
	buf := append(append([]byte{}, salt...), []byte(pw)...)
	sum := sha256.Sum256(buf)
	for i := 0; i < 100000; i++ {
		c := sha256.Sum256(append(sum[:], salt...))
		sum = c
	}
	return sum[:]
}
