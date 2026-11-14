package syncsvc

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// store 保存"这次同步到底传了哪些文件"。块级进度不在这里——它落在 .map 位图里，
// 因为位图必须跟着 .part 文件走（一起残留、一起清理），放进 DB 反而容易对不上。
type store struct {
	db *sql.DB
}

const syncSchema = `
CREATE TABLE IF NOT EXISTS sessions (
  id       TEXT PRIMARY KEY,
  root     TEXT NOT NULL,
  dest     TEXT NOT NULL,
  client   TEXT NOT NULL,
  created  INTEGER NOT NULL,
  updated  INTEGER NOT NULL,
  state    TEXT NOT NULL,           -- open | done | aborted
  total    INTEGER NOT NULL DEFAULT 0,
  checksum INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS files (
  sid      TEXT NOT NULL,
  fid      TEXT NOT NULL,
  rel      TEXT NOT NULL,           -- 相对 dest 的路径
  size     INTEGER NOT NULL,
  mode     INTEGER NOT NULL DEFAULT 0,
  mtime    INTEGER NOT NULL DEFAULT 0,
  sha      TEXT NOT NULL DEFAULT '',
  action   TEXT NOT NULL DEFAULT '',-- '' | skip | put | done | fail
  err      TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (sid, fid)
);
CREATE INDEX IF NOT EXISTS idx_files_sid_action ON files(sid, action);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state, updated);
`

func openStore(dataDir string) (*store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	p := filepath.Join(dataDir, "sync.db")
	dsn := "file:" + filepath.ToSlash(p) +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// 会话表的写入是低频的（每文件一两条），单连接足够，也顺手消掉 SQLITE_BUSY。
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(syncSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("建 sync 表失败: %w", err)
	}
	return &store{db: db}, nil
}

func (s *store) Close() error { return s.db.Close() }

type session struct {
	ID       string
	Root     string
	Dest     string
	Client   string
	State    string
	Total    int
	Checksum bool
	Created  time.Time
}

func (s *store) createSession(sess session) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO sessions(id,root,dest,client,created,updated,state,total,checksum)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		sess.ID, sess.Root, sess.Dest, sess.Client, now, now, "open", 0, boolInt(sess.Checksum))
	return err
}

func (s *store) getSession(id string) (session, error) {
	var out session
	var created, checksum int64
	err := s.db.QueryRow(`SELECT id,root,dest,client,created,state,total,checksum FROM sessions WHERE id=?`, id).
		Scan(&out.ID, &out.Root, &out.Dest, &out.Client, &created, &out.State, &out.Total, &checksum)
	out.Created = time.Unix(created, 0)
	out.Checksum = checksum != 0
	return out, err
}

func (s *store) setTotal(id string, n int) error {
	_, err := s.db.Exec(`UPDATE sessions SET total=?, updated=? WHERE id=?`, n, time.Now().Unix(), id)
	return err
}

func (s *store) setState(id, state string) error {
	_, err := s.db.Exec(`UPDATE sessions SET state=?, updated=? WHERE id=?`, state, time.Now().Unix(), id)
	return err
}

func (s *store) addFiles(sid string, rows []fileRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// 续传时清单会重发一遍：内容没变的文件保留原状态（done 就别再传），
	// 大小/时间/哈希变了才把 action 打回空，让它重新走一遍计划。
	stmt, err := tx.Prepare(`INSERT INTO files(sid,fid,rel,size,mode,mtime,sha) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(sid,fid) DO UPDATE SET
			action = CASE WHEN files.size<>excluded.size OR files.mtime<>excluded.mtime
			              OR files.sha<>excluded.sha THEN '' ELSE files.action END,
			size=excluded.size, mode=excluded.mode, mtime=excluded.mtime, sha=excluded.sha`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(sid, r.FID, r.Rel, r.Size, r.Mode, r.MTime, r.SHA); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

type fileRow struct {
	FID   string
	Rel   string
	Size  int64
	Mode  int64
	MTime int64
	SHA   string
	Act   string
	Err   string
}

func (s *store) setAction(sid, fid, action, errMsg string) error {
	_, err := s.db.Exec(`UPDATE files SET action=?, err=? WHERE sid=? AND fid=?`, action, errMsg, sid, fid)
	return err
}

// files 按插入顺序遍历（rowid 保持客户端清单顺序，便于进度条线性推进）。
func (s *store) files(sid string, fn func(fileRow) error) error {
	rows, err := s.db.Query(`SELECT fid,rel,size,mode,mtime,sha,action,err FROM files WHERE sid=? ORDER BY rowid`, sid)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var f fileRow
		if err := rows.Scan(&f.FID, &f.Rel, &f.Size, &f.Mode, &f.MTime, &f.SHA, &f.Act, &f.Err); err != nil {
			return err
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *store) pending(sid string) ([]fileRow, error) {
	rows, err := s.db.Query(`SELECT fid,rel,size,mode,mtime,sha,action,err FROM files WHERE sid=? AND action IN ('put','') ORDER BY rowid`, sid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fileRow
	for rows.Next() {
		var f fileRow
		if err := rows.Scan(&f.FID, &f.Rel, &f.Size, &f.Mode, &f.MTime, &f.SHA, &f.Act, &f.Err); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *store) counts(sid string) (skip, done, fail, put int, err error) {
	rows, err := s.db.Query(`SELECT action, COUNT(*) FROM files WHERE sid=? GROUP BY action`, sid)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		var n int
		if err = rows.Scan(&a, &n); err != nil {
			return
		}
		switch a {
		case "skip":
			skip = n
		case "done":
			done = n
		case "fail":
			fail = n
		case "put":
			put = n
		}
	}
	err = rows.Err()
	return
}

func (s *store) failures(sid string, limit int) ([]string, error) {
	rows, err := s.db.Query(`SELECT rel || ': ' || err FROM files WHERE sid=? AND action='fail' LIMIT ?`, sid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// expired 返回超期未完成的会话，供启动时清理（含它们留在共享根里的 .part）。
func (s *store) expired(before time.Time) ([]session, error) {
	rows, err := s.db.Query(`SELECT id,root,dest FROM sessions WHERE state='open' AND updated<?`, before.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []session
	for rows.Next() {
		var v session
		if err := rows.Scan(&v.ID, &v.Root, &v.Dest); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *store) deleteSession(sid string) error {
	if _, err := s.db.Exec(`DELETE FROM files WHERE sid=?`, sid); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, sid)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
