package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fsgw/internal/audit"
	"fsgw/internal/platform"
	"fsgw/internal/syncsvc"
)

// startSync 拉起「快同步」服务。
//
// 它和 SMB/DLNA 一样属于局域网面：能覆盖文件的写通道不该脱离总开关常驻，
// 否则"OFF = 零暴露"就成了空话。
func (a *App) startSync() error {
	if !a.cfg.Sync.Enabled {
		return nil
	}
	if a.dry {
		return nil
	}
	a.srvMu.Lock()
	defer a.srvMu.Unlock()
	if a.syncSrv != nil {
		return nil
	}

	token, err := a.loadSyncToken()
	if err != nil {
		return err
	}
	roots := a.syncRoots()
	if len(roots) == 0 {
		return fmt.Errorf("没有可写共享根（sync.roots 或 shares[].writable）")
	}

	srv, err := syncsvc.New(syncsvc.Options{
		DataDir:   a.cfg.DataDir,
		Roots:     roots,
		Token:     token,
		ChunkSize: int64(a.cfg.Sync.ChunkMB) << 20,
		MaxFiles:  a.cfg.Sync.MaxFiles,
		TTL:       time.Duration(a.cfg.Sync.SessionTTLHours) * time.Hour,
		Verify:    a.cfg.Sync.Verify,
		Log:       a.log,
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", a.cfg.Sync.Bind)
	if err != nil {
		_ = srv.Close()
		return fmt.Errorf("同步服务监听 %s 失败: %w", a.cfg.Sync.Bind, err)
	}
	a.syncSrv, a.syncLn, a.syncToken = srv, ln, token
	go func() {
		if err := srv.Serve(ln); err != nil {
			a.log.Warn("同步服务退出", "err", err)
		}
	}()
	a.log.Info("快同步服务已启动", "addr", a.cfg.Sync.Bind,
		"chunk_mb", a.cfg.Sync.ChunkMB, "roots", len(roots))
	a.aud.Write(audit.Entry{
		Source: "sync", Action: "start", Result: "ok",
		Detail: fmt.Sprintf("监听 %s，块 %d MiB", a.cfg.Sync.Bind, a.cfg.Sync.ChunkMB),
	})
	return nil
}

// syncFirewallRules 让防火墙随配置放行同步端口。
// 端口来自 sync.bind，改端口不需要改代码。
func (a *App) syncFirewallRules() []platform.Rule {
	if !a.cfg.Sync.Enabled {
		return nil
	}
	_, portStr, err := net.SplitHostPort(a.cfg.Sync.Bind)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return nil
	}
	return []platform.Rule{{
		Name: "FSGW-SYNC-" + portStr, Proto: "tcp", Port: port,
		Remote: "LocalSubnet", Profile: "private",
	}}
}

func (a *App) stopSync() {
	a.srvMu.Lock()
	srv, ln := a.syncSrv, a.syncLn
	a.syncSrv, a.syncLn = nil, nil
	a.srvMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if srv != nil {
		_ = srv.Close()
		a.log.Info("快同步服务已停止")
	}
}

// syncRoots 把 shares 转成同步可用的根。
//
// 只放行 writable 的共享根：只读共享上「同步」本身就是配置矛盾，
// 与其运行时报错，不如启动时就不出现。
func (a *App) syncRoots() []syncsvc.Root {
	allow := map[string]bool{}
	for _, id := range a.cfg.Sync.Roots {
		allow[strings.ToLower(strings.TrimSpace(id))] = true
	}
	var out []syncsvc.Root
	for _, s := range a.cfg.Shares {
		if !s.Writable {
			continue
		}
		if len(allow) > 0 && !allow[strings.ToLower(s.ShareID)] {
			continue
		}
		out = append(out, syncsvc.Root{ID: s.ShareID, Path: s.Root, Writable: true})
	}
	return out
}

// loadSyncToken 与 control.token 同一套规则：0600 落盘，24 字节随机。
// 单独一把钥匙，是因为同步 token 只该拿到"往共享里写文件"的权限，
// 不该顺带拥有控制台那种"能关服务、能改配置"的能力。
func (a *App) loadSyncToken() (string, error) {
	p := filepath.Join(a.cfg.DataDir, "sync.token")
	if raw, err := os.ReadFile(p); err == nil {
		if t := strings.TrimSpace(string(raw)); len(t) >= 16 {
			return t, nil
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	t := hex.EncodeToString(buf)
	if err := os.MkdirAll(a.cfg.DataDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

// SyncToken 供 CLI 打印（本地用户才能读到这个文件）。
func (a *App) SyncToken() (string, error) {
	if a.syncToken != "" {
		return a.syncToken, nil
	}
	return a.loadSyncToken()
}

// SyncInfo 是给控制台看的一小块状态。
func (a *App) SyncInfo() (addr string, ready bool, sessions, bytes int64) {
	a.srvMu.Lock()
	srv := a.syncSrv
	a.srvMu.Unlock()
	if srv == nil {
		return a.cfg.Sync.Bind, false, 0, 0
	}
	sessions, bytes, _ = srv.Stats()
	return a.cfg.Sync.Bind, true, sessions, bytes
}
