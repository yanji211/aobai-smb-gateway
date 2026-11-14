package ctlapi

// 控制台的"人"通道：用户名 + 口令登录，签发会话 cookie。
//
// 为什么要它：token 是机器凭据——48 位十六进制、存在服务器上、要 SSH 去 cat。
// 人工登录不该走这条路。控制台面向的是同一个使用者和同一批共享目录，账号就用
// 共享那套（WebDAV 账号 / SMB 账号），记一套口令即可。
//
// token 没有被删掉，它是"机器通道"：fsgw ui 自动带、脚本带 X-FSGW-Token、
// fsgw-sync 之类的外部工具也走它。两条通道并存，guard 认任意一条。

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "fsgw_sess"
	// sessionTTL 是"保持登录"勾上后的有效期；不勾就是浏览器会话 cookie，
	// 服务端仍给一个上限，免得关不掉的僵尸会话堆积。
	sessionTTL = 7 * 24 * time.Hour
	shortTTL   = 12 * time.Hour

	// 登录爆破防护：同一来源连续失败到阈值，锁一段时间。
	failLimit  = 5
	failWindow = 60 * time.Second
)

type session struct {
	User string    `json:"user"`
	Exp  time.Time `json:"exp"`
}

type loginFail struct {
	n     int
	until time.Time
}

// sessions 是会话表：sid → session。落盘是为了服务重启（升级二进制）后
// 不用重新登录，文件权限与 token 同为 0600。
type sessionStore struct {
	mu    sync.Mutex
	m     map[string]session
	fails map[string]*loginFail
	path  string
}

func newSessionStore(path string) *sessionStore {
	st := &sessionStore{m: map[string]session{}, fails: map[string]*loginFail{}, path: path}
	if path != "" {
		st.load()
	}
	return st
}

func (st *sessionStore) load() {
	raw, err := os.ReadFile(st.path)
	if err != nil {
		return
	}
	var m map[string]session
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	now := time.Now()
	for k, v := range m {
		if v.Exp.After(now) {
			st.m[k] = v
		}
	}
}

// saveLocked 必须持锁调用。
func (st *sessionStore) saveLocked() {
	if st.path == "" {
		return
	}
	now := time.Now()
	out := map[string]session{}
	for k, v := range st.m {
		if v.Exp.After(now) {
			out[k] = v
		} else {
			delete(st.m, k)
		}
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return
	}
	if dir := filepath.Dir(st.path); dir != "" {
		os.MkdirAll(dir, 0o755)
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	// WriteFile 的权限位对已存在的文件无效，显式再设一次：这份文件等价于
	// 一批可用会话，不能让同机其他用户读到。
	os.Chmod(tmp, 0o600)
	os.Rename(tmp, st.path)
}

func (st *sessionStore) create(user string, ttl time.Duration) (string, bool) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", false
	}
	sid := hex.EncodeToString(buf)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.m[sid] = session{User: user, Exp: time.Now().Add(ttl)}
	st.saveLocked()
	return sid, true
}

func (st *sessionStore) get(sid string) (session, bool) {
	if sid == "" {
		return session{}, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.m[sid]
	if !ok {
		return session{}, false
	}
	if !s.Exp.After(time.Now()) {
		delete(st.m, sid)
		return session{}, false
	}
	return s, true
}

func (st *sessionStore) drop(sid string) {
	if sid == "" {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.m[sid]; ok {
		delete(st.m, sid)
		st.saveLocked()
	}
}

// lockFor 返回还需等待的秒数；0 表示可以尝试。
func (st *sessionStore) lockFor(ip string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	f := st.fails[ip]
	if f == nil {
		return 0
	}
	if time.Now().Before(f.until) {
		return int(time.Until(f.until).Seconds()) + 1
	}
	return 0
}

func (st *sessionStore) noteFail(ip string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	f := st.fails[ip]
	if f == nil {
		f = &loginFail{}
		st.fails[ip] = f
	}
	f.n++
	if f.n >= failLimit {
		f.until = time.Now().Add(failWindow)
		f.n = 0
	}
}

func (st *sessionStore) clearFail(ip string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.fails, ip)
}

// ---------- HTTP ----------

// checkOrigin 是登录这几个接口共用的外围校验（Host / Origin），与 guard 一致。
func (s *Server) checkOrigin(w http.ResponseWriter, r *http.Request) bool {
	if !s.hostOK(r.Host) {
		http.Error(w, "bad host", http.StatusForbidden)
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && !s.originOK(o) {
		http.Error(w, "bad origin", http.StatusForbidden)
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

// handleLogin 是 POST /api/login：{username,password,remember}。
// 免 token（否则又回到"先找 token 才能登录"），但保留 Host / Origin 两道防线，
// 并加失败计数，浏览器里被诱导的跨源请求连口令都递不进来。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		return
	}
	if s.accounts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "本实例没有可用的共享账号，请改用访问令牌登录",
		})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Remember *bool  `json:"remember"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法 JSON"})
		return
	}
	ip := clientIP(r)
	if wait := s.sess.lockFor(ip); wait > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "口令错误次数太多，请 " + itoa(wait) + " 秒后再试",
		})
		return
	}
	user := strings.TrimSpace(req.Username)
	if user == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "用户名和口令都要填"})
		return
	}
	name, ok := s.accounts(user, req.Password)
	if !ok {
		s.sess.noteFail(ip)
		if s.log != nil {
			s.log.Warn("控制台登录失败", "user", user, "ip", ip)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "用户名或口令不对（用的是共享设置里的账号）",
		})
		return
	}
	s.sess.clearFail(ip)

	remember := true
	if req.Remember != nil {
		remember = *req.Remember
	}
	ttl := shortTTL
	if remember {
		ttl = sessionTTL
	}
	sid, ok := s.sess.create(name, ttl)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "会话创建失败，再试一次"})
		return
	}
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if remember {
		c.MaxAge = int(ttl / time.Second)
	}
	http.SetCookie(w, c)
	if s.log != nil {
		s.log.Info("控制台登录成功", "user", name, "ip", ip, "remember", remember)
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": name, "expires_in": int(ttl / time.Second)})
}

// handleLogout 是 POST /api/logout：清 cookie 与服务端会话。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sess.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleWhoAmI 是 GET /api/whoami：前端启动时问一句"我登着吗"，避免
// 拿 401 当"未登录"然后又去猜是不是 token 过期。免 token，只认 cookie。
func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		return
	}
	sess, ok := s.sessionOf(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       sess.User,
		"expires_in": int(time.Until(sess.Exp).Seconds()),
	})
}

func (s *Server) sessionOf(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	return s.sess.get(c.Value)
}

// tokenOK 判断请求是否带了正确的机器令牌（头优先，SSE 允许查询参数）。
func (s *Server) tokenOK(r *http.Request) bool {
	tok := r.Header.Get("X-FSGW-Token")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	if tok == "" || s.token == "" {
		return false
	}
	return subtleCompare(tok, s.token)
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
