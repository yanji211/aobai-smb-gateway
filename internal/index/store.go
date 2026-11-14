// Package index 实现 SQLite 索引：数据库是唯一真相源，磁盘只是字节仓库。
// 读走独立连接池（query_only），写走单连接串行，见 docs/02 第 4 节。
package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const schemaVersion = "1"

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
  share_id   TEXT PRIMARY KEY,
  root_path  TEXT NOT NULL,
  root_key   TEXT NOT NULL,
  writable   INTEGER NOT NULL DEFAULT 1,
  media      INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS share_dirs (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  share_id TEXT NOT NULL,
  rel_path TEXT NOT NULL,
  path_key TEXT NOT NULL,
  writable INTEGER NOT NULL DEFAULT 1,
  media    INTEGER NOT NULL DEFAULT 0,
  UNIQUE(share_id, path_key)
);

CREATE TABLE IF NOT EXISTS objects (
  object_id     TEXT PRIMARY KEY,
  native_id     TEXT,
  first_seen_at INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  state         INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_objects_native ON objects(native_id);

CREATE TABLE IF NOT EXISTS files (
  file_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  share_id     TEXT NOT NULL,
  object_id    TEXT NOT NULL,
  parent_path  TEXT NOT NULL,
  name         TEXT NOT NULL,
  name_key     TEXT NOT NULL,
  path         TEXT NOT NULL,
  path_key     TEXT NOT NULL,
  kind         INTEGER NOT NULL,
  size         INTEGER NOT NULL DEFAULT 0,
  mtime_ns     INTEGER NOT NULL DEFAULT 0,
  content_hash TEXT,
  hash_state   INTEGER NOT NULL DEFAULT 0,
  status       INTEGER NOT NULL DEFAULT 0,
  last_source  INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_files_path   ON files(path_key);
CREATE UNIQUE INDEX IF NOT EXISTS ux_files_parent ON files(parent_path, name_key);
CREATE INDEX IF NOT EXISTS        ix_files_object ON files(object_id);

CREATE TABLE IF NOT EXISTS versions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id    TEXT NOT NULL,
  seq          INTEGER NOT NULL,
  size         INTEGER NOT NULL,
  mtime_ns     INTEGER NOT NULL,
  content_hash TEXT,
  change       INTEGER NOT NULL,
  source       INTEGER NOT NULL,
  recorded_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_versions_seq ON versions(object_id, seq);

CREATE TABLE IF NOT EXISTS path_history (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  from_path TEXT,
  to_path   TEXT,
  change    INTEGER NOT NULL,
  move_kind INTEGER NOT NULL DEFAULT 0,
  moved_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ph_object ON path_history(object_id, moved_at DESC);
CREATE INDEX IF NOT EXISTS ix_ph_from   ON path_history(from_path);

CREATE TABLE IF NOT EXISTS pending_moves (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  cookie      TEXT NOT NULL,
  change_type INTEGER NOT NULL,
  path        TEXT NOT NULL,
  path_key    TEXT NOT NULL,
  native_id   TEXT,
  seen_at     INTEGER NOT NULL,
  state       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS suppress (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  path_key        TEXT NOT NULL,
  expect_size     INTEGER,
  expect_mtime_ns INTEGER,
  expires_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
  snapshot_id  TEXT PRIMARY KEY,
  object_id    TEXT NOT NULL,
  version_id   INTEGER,
  content_hash TEXT,
  storage      TEXT NOT NULL,
  rel_path     TEXT NOT NULL,
  size         INTEGER NOT NULL,
  integrity    INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  pinned       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reconcile_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  root_path   TEXT NOT NULL,
  reason      TEXT NOT NULL,
  nodes_seen  INTEGER NOT NULL DEFAULT 0,
  inserted    INTEGER NOT NULL DEFAULT 0,
  updated     INTEGER NOT NULL DEFAULT 0,
  deleted     INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);
`

// Kind / Status 常量，与 docs/02 的注释保持一致。
const (
	KindFile = 0
	KindDir  = 1

	StatusActive  = 0
	StatusWriting = 1
	StatusStale   = 2
	StatusDeleted = 3

	SourceUnknown = 0
	SourceSMB     = 1
	SourceGateway = 2
	SourceLocal   = 3

	// versions.change
	ChangeWrite  = 1
	ChangeTrunc  = 2
	ChangeMeta   = 3
	ChangeAppear = 4

	// path_history.change
	PathCreate = 1
	PathMove   = 2
	PathRename = 3
	PathDelete = 4

	MoveNone        = 0
	MoveSameVolume  = 1
	MoveCrossOK     = 2
	MoveUnconfirmed = 3
)

type FileRow struct {
	FileID     int64
	ShareID    string
	ObjectID   string
	ParentPath string
	Name       string
	NameKey    string
	Path       string
	PathKey    string
	Kind       int
	Size       int64
	MtimeNs    int64
	Hash       sql.NullString
	HashState  int
	Status     int
	LastSource int
}

type ShareRow struct {
	ShareID  string
	Root     string
	RootKey  string
	Writable bool
	Media    bool
}

type Stats struct {
	Files          int64
	Dirs           int64
	Objects        int64
	Versions       int64
	PathHistory    int64
	PendingMoves   int64
	LastReconcile  time.Time
	LastReconcileN int64
}

type Store struct {
	w  *sql.DB
	r  *sql.DB
	mu sync.Mutex
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "fsgw.db")
	base := "file:" + filepath.ToSlash(dbPath)

	// PRAGMA 是连接级设置：连接池里每条新连接都要带上，所以写进 DSN。
	wdsn := base + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	rdsn := base + "?_pragma=busy_timeout(5000)&_pragma=query_only(1)"

	w, err := sql.Open("sqlite", wdsn)
	if err != nil {
		return nil, err
	}
	// 单写连接：从连接层保证只有一个 writer，避免 SQLITE_BUSY 抖动。
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)

	r, err := sql.Open("sqlite", rdsn)
	if err != nil {
		return nil, err
	}
	r.SetMaxOpenConns(8)

	s := &Store{w: w, r: r}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	var first error
	if s.r != nil {
		if err := s.r.Close(); err != nil {
			first = err
		}
	}
	if s.w != nil {
		if err := s.w.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *Store) migrate() error {
	if _, err := s.w.Exec(schemaSQL); err != nil {
		return fmt.Errorf("建表: %w", err)
	}
	var cur string
	err := s.r.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&cur)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.w.Exec(`INSERT INTO schema_meta(key,value) VALUES('schema_version',?)`, schemaVersion)
		return err
	case err != nil:
		return err
	case cur > schemaVersion:
		return fmt.Errorf("数据库 schema 版本 %s 高于程序支持的 %s，拒绝启动", cur, schemaVersion)
	}
	return nil
}

// Do 在单写连接上执行一个事务。所有写路径都必须经过这里。
func (s *Store) Do(fn func(tx *sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---------- 共享 ----------

func (s *Store) UpsertShare(shareID, root string, writable, media bool) error {
	rootKey := KeyOf("")
	return s.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO shares(share_id, root_path, root_key, writable, media, created_at)
			VALUES(?,?,?,?,?,?)
			ON CONFLICT(share_id) DO UPDATE SET root_path=excluded.root_path, writable=excluded.writable, media=excluded.media`,
			shareID, root, rootKey, boolInt(writable), boolInt(media), time.Now().UnixMilli())
		return err
	})
}

func (s *Store) Shares() ([]ShareRow, error) {
	rows, err := s.r.Query(`SELECT share_id, root_path, root_key, writable, media FROM shares ORDER BY share_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShareRow
	for rows.Next() {
		var x ShareRow
		var wr, md int
		if err := rows.Scan(&x.ShareID, &x.Root, &x.RootKey, &wr, &md); err != nil {
			return nil, err
		}
		x.Writable = wr != 0
		x.Media = md != 0
		out = append(out, x)
	}
	return out, rows.Err()
}

// PurgeShare 清掉一个共享的全部索引条目，返回删掉的文件行数。
//
// 换共享根目录时必须先清：files 的主键是相对路径（path_key），旧根下的行
// 不清掉，搜索和目录列表就会指着一批已经不存在的文件。
func (s *Store) PurgeShare(shareID string) (int64, error) {
	var n int64
	err := s.Do(func(tx *sql.Tx) error {
		// 临时表挂在写连接上，跨事务存活；先删再建，避免上一轮的残留。
		if _, err := tx.Exec(`DROP TABLE IF EXISTS temp.purge_objs`); err != nil {
			return err
		}
		if _, err := tx.Exec(`CREATE TEMP TABLE purge_objs AS
			SELECT DISTINCT object_id FROM files WHERE share_id = ?`, shareID); err != nil {
			return err
		}
		res, err := tx.Exec(`DELETE FROM files WHERE share_id = ?`, shareID)
		if err != nil {
			return err
		}
		if rows, err := res.RowsAffected(); err == nil {
			n = rows
		}
		if _, err := tx.Exec(`DELETE FROM versions
			WHERE object_id IN (SELECT object_id FROM purge_objs)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM path_history
			WHERE object_id IN (SELECT object_id FROM purge_objs)`); err != nil {
			return err
		}
		// 对象行只在没人再引用时才删：两个共享根可能覆盖同一批文件，
		// 顺手删掉会让另一个共享的版本链断掉。
		if _, err := tx.Exec(`DELETE FROM objects
			WHERE object_id IN (SELECT object_id FROM purge_objs)
			  AND object_id NOT IN (SELECT object_id FROM files)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM share_dirs WHERE share_id = ?`, shareID); err != nil {
			return err
		}
		_, err = tx.Exec(`DROP TABLE temp.purge_objs`)
		return err
	})
	return n, err
}

// ---------- 查询 ----------
func (s *Store) ByPath(pathKey string) (*FileRow, error) {
	row := s.r.QueryRow(`SELECT file_id, share_id, object_id, parent_path, name, name_key, path, path_key,
		kind, size, mtime_ns, content_hash, hash_state, status, last_source
		FROM files WHERE path_key=?`, pathKey)
	return scanFile(row)
}

// ReadDir 只查库，绝不 os.Stat（数据库是唯一真相源）。
func (s *Store) ReadDir(parentPathKey string) ([]FileRow, error) {
	rows, err := s.r.Query(`SELECT file_id, share_id, object_id, parent_path, name, name_key, path, path_key,
		kind, size, mtime_ns, content_hash, hash_state, status, last_source
		FROM files WHERE parent_path=? AND status<>? ORDER BY name_key`, parentPathKey, StatusDeleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileRow
	for rows.Next() {
		var f FileRow
		if err := rows.Scan(&f.FileID, &f.ShareID, &f.ObjectID, &f.ParentPath, &f.Name, &f.NameKey,
			&f.Path, &f.PathKey, &f.Kind, &f.Size, &f.MtimeNs, &f.Hash, &f.HashState, &f.Status, &f.LastSource); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) ChildByPath(pathKey string) (*FileRow, error) {
	return s.ByPath(pathKey)
}

// RowsUnder 返回某子树下的全部路径条目（不含 prefix 自身）。
// 用 substr 前缀比较而不是 LIKE，路径里可能出现 % 与 _。
func (s *Store) RowsUnder(prefixKey string) ([]FileRow, error) {
	if prefixKey == "" {
		return s.allRows()
	}
	prefix := prefixKey + "/"
	rows, err := s.r.Query(`SELECT file_id, share_id, object_id, parent_path, name, name_key, path, path_key,
		kind, size, mtime_ns, content_hash, hash_state, status, last_source
		FROM files WHERE substr(path_key, 1, ?) = ? AND status<>?
		ORDER BY path_key`, utf8.RuneCountInString(prefix), prefix, StatusDeleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectFiles(rows)
}

func (s *Store) allRows() ([]FileRow, error) {
	rows, err := s.r.Query(`SELECT file_id, share_id, object_id, parent_path, name, name_key, path, path_key,
		kind, size, mtime_ns, content_hash, hash_state, status, last_source
		FROM files WHERE status<>? ORDER BY path_key`, StatusDeleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectFiles(rows)
}

func collectFiles(rows *sql.Rows) ([]FileRow, error) {
	var out []FileRow
	for rows.Next() {
		var f FileRow
		if err := rows.Scan(&f.FileID, &f.ShareID, &f.ObjectID, &f.ParentPath, &f.Name, &f.NameKey,
			&f.Path, &f.PathKey, &f.Kind, &f.Size, &f.MtimeNs, &f.Hash, &f.HashState, &f.Status, &f.LastSource); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) Stats() (Stats, error) {
	var st Stats
	q := func(sqlText string, dst *int64) error {
		return s.r.QueryRow(sqlText).Scan(dst)
	}
	if err := q(`SELECT COUNT(*) FROM files WHERE kind=0 AND status<>3`, &st.Files); err != nil {
		return st, err
	}
	if err := q(`SELECT COUNT(*) FROM files WHERE kind=1 AND status<>3`, &st.Dirs); err != nil {
		return st, err
	}
	if err := q(`SELECT COUNT(*) FROM objects`, &st.Objects); err != nil {
		return st, err
	}
	if err := q(`SELECT COUNT(*) FROM versions`, &st.Versions); err != nil {
		return st, err
	}
	if err := q(`SELECT COUNT(*) FROM path_history`, &st.PathHistory); err != nil {
		return st, err
	}
	if err := q(`SELECT COUNT(*) FROM pending_moves WHERE state=0`, &st.PendingMoves); err != nil {
		return st, err
	}
	var ms int64
	var n int64
	err := s.r.QueryRow(`SELECT created_at, nodes_seen FROM reconcile_log ORDER BY id DESC LIMIT 1`).Scan(&ms, &n)
	if err == nil {
		st.LastReconcile = time.UnixMilli(ms)
		st.LastReconcileN = n
	}
	return st, nil
}

func (s *Store) VersionsOf(objectID string) ([]VersionRow, error) {
	rows, err := s.r.Query(`SELECT id, seq, size, mtime_ns, change, source, recorded_at
		FROM versions WHERE object_id=? ORDER BY seq DESC`, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VersionRow
	for rows.Next() {
		var v VersionRow
		if err := rows.Scan(&v.ID, &v.Seq, &v.Size, &v.MtimeNs, &v.Change, &v.Source, &v.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type VersionRow struct {
	ID         int64
	Seq        int64
	Size       int64
	MtimeNs    int64
	Change     int
	Source     int
	RecordedAt int64
}

// PathHistory 返回一个 object 的路径变更流水。
func (s *Store) PathHistory(objectID string) ([]PathEvent, error) {
	rows, err := s.r.Query(`SELECT from_path, to_path, change, move_kind, moved_at
		FROM path_history WHERE object_id=? ORDER BY id DESC`, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PathEvent
	for rows.Next() {
		var e PathEvent
		var from, to sql.NullString
		if err := rows.Scan(&from, &to, &e.Change, &e.MoveKind, &e.At); err != nil {
			return nil, err
		}
		e.From, e.To = from.String, to.String
		out = append(out, e)
	}
	return out, rows.Err()
}

type PathEvent struct {
	From     string
	To       string
	Change   int
	MoveKind int
	At       int64
}

// ---------- 写 ----------

var ErrNotFound = errors.New("index: 未找到")

func (s *Store) TouchObject(tx *sql.Tx, nativeID string) (string, error) {
	now := time.Now().UnixMilli()
	var id string
	err := tx.QueryRow(`SELECT object_id FROM objects WHERE native_id=?`, nativeID).Scan(&id)
	if err == nil {
		_, err = tx.Exec(`UPDATE objects SET last_seen_at=? WHERE object_id=?`, now, id)
		return id, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	id = NewObjectID()
	_, err = tx.Exec(`INSERT INTO objects(object_id, native_id, first_seen_at, last_seen_at, state)
		VALUES(?,?,?,?,0)`, id, nativeID, now, now)
	return id, err
}

type UpsertReq struct {
	ShareID    string
	ObjectID   string
	ParentPath string
	Name       string
	Kind       int
	Size       int64
	MtimeNs    int64
	Source     int
}

func (r UpsertReq) path() string {
	p := r.ParentPath
	if p == "" {
		return r.Name
	}
	return p + "/" + r.Name
}

// UpsertFile 插入或更新一条路径记录。返回是否新建。
func (s *Store) UpsertFile(tx *sql.Tx, req UpsertReq) (created bool, err error) {
	now := time.Now().UnixMilli()
	path := req.path()
	pathKey := KeyOf(path)
	nameKey := strings.ToLower(req.Name)

	var old struct {
		id     int64
		size   int64
		mtime  int64
		status int
	}
	e := tx.QueryRow(`SELECT file_id, size, mtime_ns, status FROM files WHERE path_key=?`, pathKey).
		Scan(&old.id, &old.size, &old.mtime, &old.status)
	switch {
	case e == nil:
		_, err = tx.Exec(`UPDATE files SET share_id=?, object_id=?, parent_path=?, name=?, name_key=?,
			path=?, kind=?, size=?, mtime_ns=?, status=?, last_source=?, updated_at=? WHERE file_id=?`,
			req.ShareID, req.ObjectID, req.ParentPath, req.Name, nameKey, path, req.Kind,
			req.Size, req.MtimeNs, StatusActive, req.Source, now, old.id)
		return false, err
	case errors.Is(e, sql.ErrNoRows):
		_, err = tx.Exec(`INSERT INTO files(share_id, object_id, parent_path, name, name_key, path, path_key,
			kind, size, mtime_ns, status, last_source, created_at, updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			req.ShareID, req.ObjectID, req.ParentPath, req.Name, nameKey, path, pathKey,
			req.Kind, req.Size, req.MtimeNs, StatusActive, req.Source, now, now)
		if err != nil {
			return false, err
		}
		_, err = tx.Exec(`INSERT INTO path_history(object_id, from_path, to_path, change, move_kind, moved_at)
			VALUES(?,?,?,?,0,?)`, req.ObjectID, nil, path, PathCreate, now)
		return true, err
	default:
		return false, e
	}
}

// MoveFile 是移动语义的核心：只改路径属性 + 追加路径历史，versions 零写入。
func (s *Store) MoveFile(tx *sql.Tx, oldPathKey, newPath, newParent string, kind int) (string, error) {
	now := time.Now().UnixMilli()
	var (
		fileID   int64
		objectID string
		oldPath  string
	)
	err := tx.QueryRow(`SELECT file_id, object_id, path FROM files WHERE path_key=?`, oldPathKey).
		Scan(&fileID, &objectID, &oldPath)
	if err != nil {
		return "", err
	}
	newName := baseName(newPath)
	_, err = tx.Exec(`UPDATE files SET parent_path=?, name=?, name_key=?, path=?, path_key=?, updated_at=?
		WHERE file_id=?`,
		newParent, newName, strings.ToLower(newName), newPath, KeyOf(newPath), now, fileID)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(`INSERT INTO path_history(object_id, from_path, to_path, change, move_kind, moved_at)
		VALUES(?,?,?,?,?,?)`, objectID, oldPath, newPath, PathMove, MoveSameVolume, now)
	if err != nil {
		return "", err
	}
	if kind == KindDir {
		if err := s.cascadeMove(tx, oldPathKey, newPath); err != nil {
			return "", err
		}
	}
	return objectID, nil
}

// cascadeMove 更新子项路径。用 substr 前缀比较而不是 LIKE，避免路径里出现通配符。
func (s *Store) cascadeMove(tx *sql.Tx, oldKey, newPath string) error {
	prefix := oldKey + "/"
	n := utf8.RuneCountInString(prefix)
	newKey := KeyOf(newPath)
	_, err := tx.Exec(`UPDATE files
		SET path = ? || substr(path, ?), path_key = ? || substr(path_key, ?), updated_at=?
		WHERE substr(path_key, 1, ?) = ?`,
		newPath, utf8.RuneCountInString(oldKey)+1,
		newKey, utf8.RuneCountInString(oldKey)+1,
		time.Now().UnixMilli(), n, prefix)
	return err
}

// AppendVersion 追加一条索引版本，seq 自增。
func (s *Store) AppendVersion(tx *sql.Tx, objectID string, size, mtimeNs int64, change, source int) (int64, error) {
	var seq int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq),0)+1 FROM versions WHERE object_id=?`, objectID).Scan(&seq); err != nil {
		return 0, err
	}
	_, err := tx.Exec(`INSERT INTO versions(object_id, seq, size, mtime_ns, change, source, recorded_at)
		VALUES(?,?,?,?,?,?,?)`, objectID, seq, size, mtimeNs, change, source, time.Now().UnixMilli())
	return seq, err
}

// MarkDeleted 标记删除并冻结版本链（版本不删，只是不再新增）。
func (s *Store) MarkDeleted(tx *sql.Tx, pathKey string) (string, error) {
	now := time.Now().UnixMilli()
	var (
		objectID string
		path     string
	)
	err := tx.QueryRow(`SELECT object_id, path FROM files WHERE path_key=?`, pathKey).Scan(&objectID, &path)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE files SET status=?, updated_at=? WHERE path_key=?`, StatusDeleted, now, pathKey); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE objects SET state=2 WHERE object_id=?`, objectID); err != nil {
		return "", err
	}
	_, err = tx.Exec(`INSERT INTO path_history(object_id, from_path, to_path, change, move_kind, moved_at)
		VALUES(?,?,?,?,0,?)`, objectID, path, nil, PathDelete, now)
	return objectID, err
}

func (s *Store) SetHash(objectID, hash string) error {
	return s.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE files SET content_hash=?, hash_state=2 WHERE object_id=?`, hash, objectID)
		return err
	})
}

func (s *Store) MarkHashSkipped(objectID string) error {
	return s.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE files SET hash_state=3 WHERE object_id=?`, objectID)
		return err
	})
}

func (s *Store) LogReconcile(root, reason string, seen, ins, upd, del int, dur time.Duration) error {
	return s.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO reconcile_log(root_path, reason, nodes_seen, inserted, updated, deleted, duration_ms, created_at)
			VALUES(?,?,?,?,?,?,?,?)`, root, reason, seen, ins, upd, del, dur.Milliseconds(), time.Now().UnixMilli())
		return err
	})
}

// ---------- 辅助 ----------

type rowScanner interface {
	Scan(dest ...any) error
}

func scanFile(row rowScanner) (*FileRow, error) {
	var f FileRow
	err := row.Scan(&f.FileID, &f.ShareID, &f.ObjectID, &f.ParentPath, &f.Name, &f.NameKey,
		&f.Path, &f.PathKey, &f.Kind, &f.Size, &f.MtimeNs, &f.Hash, &f.HashState, &f.Status, &f.LastSource)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// KeyOf 把相对路径规范化为查询键：小写、正斜杠、无前后斜杠。
// Windows 路径大小写不敏感，但显示名要保留原始大小写。
func KeyOf(rel string) string {
	s := strings.ReplaceAll(rel, `\`, "/")
	s = strings.Trim(s, "/")
	return strings.ToLower(s)
}

func baseName(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

func ParentOf(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return ""
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
