package smbgo

// 本文件维护两张纯内存表，供控制台展示：
//
//	在线连接（Session）——谁连着、用哪个账号、连了多久；
//	登录尝试（Attempt）——谁来敲过门、结果是通过还是被拒。
//
// 为什么放在 smbgo 而不是 app 层：只有代理层同时掌握三样东西——客户端 IP、
// 客户端报上来的用户名、以及这次 SESSION_SETUP 的最终结果。内层库不暴露
// 这些信息（它的认证器连远端地址都拿不到），自己记一份最省事。
//
// 全部是尽力而为的观测数据：连接断了就消失，不落盘，重启即清空。
// 它只用于"看得见"，不参与任何鉴权判断——鉴权永远按账号表来。

import (
	"sort"
	"sync"
	"time"
)

// Session 是一条在线的 SMB 连接。
type Session struct {
	Remote string    `json:"remote"` // 客户端 IP:端口
	User   string    `json:"user"`   // 通过认证的账号（空 = 尚未认证）
	Guest  bool      `json:"guest"`  // 是否走来宾（免口令）通道
	Since  time.Time `json:"since"`
	Trees  []string  `json:"trees"` // 访问过的共享名

	// Client / ClientLabel 是识别出来的接入端（见 client.go）。
	// 放在会话上而不是只写日志，是因为"这台设备连不上"的第一现场就在这里：
	// 面板上看到它是 macOS，就知道该去查签名/SPNEGO，而不是查口令。
	Client      string `json:"client"`
	ClientLabel string `json:"client_label"`
}

// Attempt 是一次登录尝试。Result 取值：ok（账号口令通过）/ guest（来宾放行）/ denied（被拒）。
type Attempt struct {
	User   string    `json:"user"`
	Remote string    `json:"remote"`
	At     time.Time `json:"at"`
	Result string    `json:"result"`
}

const maxAttempts = 50

var (
	liveMu  sync.Mutex
	liveSeq uint64
	liveTab = map[uint64]*liveSession{}

	tryMu   sync.Mutex
	tryRing []Attempt
)

type liveSession struct {
	id      uint64
	remote  string
	user    string
	guest   bool
	since   time.Time
	trees   []string
	client  string
	clientL string
}

// openSession 登记一条新连接。relay 退出时调用 close。
func openSession(remote string) *liveSession {
	liveMu.Lock()
	defer liveMu.Unlock()
	liveSeq++
	l := &liveSession{id: liveSeq, remote: remote, since: time.Now()}
	liveTab[l.id] = l
	return l
}

func (l *liveSession) close() {
	if l == nil {
		return
	}
	liveMu.Lock()
	delete(liveTab, l.id)
	liveMu.Unlock()
}

// setUser 在认证有结果时写入。guest 只影响展示（来宾通道）。
func (l *liveSession) setUser(user string, guest bool) {
	if l == nil {
		return
	}
	liveMu.Lock()
	if user != "" {
		l.user = user
	}
	l.guest = guest
	liveMu.Unlock()
}

// setClient 记下识别出来的接入端。连接一建立就调用，认证结果之后才到，
// 所以它和 setUser 是两条独立的写入路径。
func (l *liveSession) setClient(info ClientInfo) {
	if l == nil {
		return
	}
	liveMu.Lock()
	l.client = string(info.Kind)
	l.clientL = info.Label
	liveMu.Unlock()
}

func (l *liveSession) addTree(tree string) {
	if l == nil || tree == "" || tree == "IPC$" {
		return
	}
	liveMu.Lock()
	for _, t := range l.trees {
		if t == tree {
			liveMu.Unlock()
			return
		}
	}
	l.trees = append(l.trees, tree)
	liveMu.Unlock()
}

// noteAttempt 记一次登录尝试。2 秒内同一个人同一结果的重复记录会被合并，
// 因为一轮握手可能产生多条 SESSION_SETUP 响应（挑战、收尾确认各一条）。
func noteAttempt(user, remote, result string) {
	tryMu.Lock()
	defer tryMu.Unlock()
	now := time.Now()
	if n := len(tryRing); n > 0 {
		last := tryRing[n-1]
		if last.User == user && last.Remote == remote &&
			last.Result == result && now.Sub(last.At) < 2*time.Second {
			return
		}
	}
	tryRing = append(tryRing, Attempt{User: user, Remote: remote, At: now, Result: result})
	if len(tryRing) > maxAttempts {
		tryRing = tryRing[len(tryRing)-maxAttempts:]
	}
}

// Sessions 返回当前在线连接，按建立时间升序。
func Sessions() []Session {
	liveMu.Lock()
	defer liveMu.Unlock()
	out := make([]Session, 0, len(liveTab))
	for _, l := range liveTab {
		trees := make([]string, len(l.trees))
		copy(trees, l.trees)
		out = append(out, Session{
			Remote:      l.remote,
			User:        l.user,
			Guest:       l.guest,
			Since:       l.since,
			Trees:       trees,
			Client:      l.client,
			ClientLabel: l.clientL,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out
}

// Attempts 返回最近的登录尝试，最新的在前。
func Attempts() []Attempt {
	tryMu.Lock()
	defer tryMu.Unlock()
	out := make([]Attempt, len(tryRing))
	for i, a := range tryRing {
		out[len(tryRing)-1-i] = a
	}
	return out
}
