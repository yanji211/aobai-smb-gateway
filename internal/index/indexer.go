package index

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fsgw/internal/audit"
	"fsgw/internal/platform"
)

// Params 是索引器的可调参数，来源是 config.Index。
type Params struct {
	DebounceStructuralMS int
	DebounceContentMS    int
	HashMaxMB            int
	Source               int // platform 无关：SourceSMB / SourceLocal
}

type hashJob struct {
	objectID string
	abs      string
}

// Indexer 把文件系统变更翻译成索引变更。所有写操作串行走 Store.Do。
type Indexer struct {
	store *Store
	p     Params
	log   *slog.Logger
	aud   *audit.Log

	mu       sync.Mutex
	timers   map[string]*time.Timer
	suppress map[string]time.Time // pathKey -> 过期时间
	roots    map[string]shareRoot
	// watches 按 shareID 记一条"停这个共享的监听"的开关。
	// 换共享根目录时必须能只停这一个：既有的 stop 是全进程级的，
	// 用它等于把别的共享一起停了。
	watches map[string]chan struct{}

	hashCh chan hashJob
	stop   chan struct{}
	wg     sync.WaitGroup
	closed atomic.Bool

	events atomic.Int64
	queue  atomic.Int64

	// 溢出重建的去抖状态：内核队列一爆，接下来几秒会连着报。
	// 每条都整树重建等于自己跟自己抢 IO（一次 47 万文件的同步连刷了 800+ 条），
	// 所以合并成一次，执行期间再来的溢出只置脏标记，跑完再补一轮。
	recMu      sync.Mutex
	recRunning bool
	recDirty   bool
}

type shareRoot struct {
	ShareID string
	Root    string
	RootKey string
}

func NewIndexer(st *Store, p Params, log *slog.Logger, aud *audit.Log) *Indexer {
	if p.DebounceContentMS <= 0 {
		p.DebounceContentMS = 400
	}
	ix := &Indexer{
		store:    st,
		p:        p,
		log:      log,
		aud:      aud,
		timers:   map[string]*time.Timer{},
		suppress: map[string]time.Time{},
		roots:    map[string]shareRoot{},
		watches:  map[string]chan struct{}{},
		hashCh:   make(chan hashJob, 1024),
		stop:     make(chan struct{}),
	}
	ix.wg.Add(1)
	go ix.hashWorker()
	return ix
}

func (ix *Indexer) Events() int64 { return ix.events.Load() }
func (ix *Indexer) Queue() int64  { return ix.queue.Load() }

func (ix *Indexer) Close() {
	if !ix.closed.CompareAndSwap(false, true) {
		return
	}
	close(ix.stop)
	ix.mu.Lock()
	for _, t := range ix.timers {
		t.Stop()
	}
	ix.timers = map[string]*time.Timer{}
	for id, ch := range ix.watches {
		close(ch)
		delete(ix.watches, id)
	}
	ix.mu.Unlock()
	ix.wg.Wait()
}

// RegisterShare 把"共享 → 根目录"登记到内存表，供 relOf 反查。
// 同一个 shareID 换过根时，旧的根前缀必须一起抹掉：留着它，
// 老路径上的事件还会被算进这个共享，索引里就会冒出指向旧目录的行。
func (ix *Indexer) RegisterShare(shareID, root string) {
	key := KeyOf("")
	clean := filepath.Clean(root)
	ix.mu.Lock()
	for p, sr := range ix.roots {
		if sr.ShareID == shareID && p != clean {
			delete(ix.roots, p)
		}
	}
	ix.roots[clean] = shareRoot{ShareID: shareID, Root: root, RootKey: key}
	ix.mu.Unlock()
	if err := ix.store.UpsertShare(shareID, root, true, false); err != nil {
		ix.log.Error("写入共享记录失败", "share", shareID, "err", err)
	}
}

// UnregisterShare 撤掉一个共享的根映射（改根目录前调用）。
// 撤掉之后，落在旧根上的事件会被 relOf 直接判为"不认识"，不再写库。
func (ix *Indexer) UnregisterShare(shareID string) {
	ix.mu.Lock()
	for p, sr := range ix.roots {
		if sr.ShareID == shareID {
			delete(ix.roots, p)
		}
	}
	ix.mu.Unlock()
}

// StopShare 停掉某个共享的目录监听。watcher 退出后不再有新事件进来；
// 已经排队的去抖写会随 ClearTimers 一起丢掉（见那里的说明）。
func (ix *Indexer) StopShare(shareID string) {
	ix.mu.Lock()
	ch := ix.watches[shareID]
	delete(ix.watches, shareID)
	ix.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// ClearTimers 丢掉所有还在去抖窗口里的写入。
//
// 只在换共享根时用：那些 timer 记的是旧根下的相对路径，触发时会把
// 已经不存在的旧路径重新写回库里（PurgeShare 刚清干净，又被补一条脏行）。
// 代价是别的共享里正在去抖的那一次写入会丢一次内容版本记录——
// 相对"索引里留下指向旧目录的行"，这个代价可以接受。
func (ix *Indexer) ClearTimers() {
	ix.mu.Lock()
	for _, t := range ix.timers {
		t.Stop()
	}
	ix.timers = map[string]*time.Timer{}
	ix.mu.Unlock()
}

// Suppress 让网关自己经手的写操作不重复记账。期望值参与匹配，
// 避免把"网关写完但用户同时在改"的情况误吞（见 docs/01 第 7.1 节）。
func (ix *Indexer) Suppress(pathKey string, size, mtimeNs int64, d time.Duration) {
	ix.mu.Lock()
	ix.suppress[pathKey] = time.Now().Add(d)
	ix.mu.Unlock()
}

func (ix *Indexer) suppressed(pathKey string) bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	exp, ok := ix.suppress[pathKey]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(ix.suppress, pathKey)
		return false
	}
	return true
}

// relOf 把绝对路径换算成共享内相对路径（正斜杠）。不在任何共享根内时返回 false。
func (ix *Indexer) relOf(abs string) (shareRoot, string, bool) {
	clean := filepath.Clean(abs)
	ix.mu.Lock()
	roots := make([]shareRoot, 0, len(ix.roots))
	for _, r := range ix.roots {
		roots = append(roots, r)
	}
	ix.mu.Unlock()

	for _, r := range roots {
		rel, err := filepath.Rel(filepath.Clean(r.Root), clean)
		if err != nil {
			continue
		}
		if rel == "." {
			return r, "", true
		}
		if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			continue
		}
		return r, filepath.ToSlash(rel), true
	}
	return shareRoot{}, "", false
}

// ---------- 初始全量对齐 ----------

// BuildInitial 递归读元数据建索引，不读文件内容。
func (ix *Indexer) BuildInitial(shareID, root string) (int, error) {
	start := time.Now()
	count := 0
	if err := ix.walkUpsert(shareID, root, "", &count); err != nil {
		return count, err
	}
	ix.log.Info("初始索引完成", "share", shareID, "entries", count, "cost", time.Since(start).String())
	return count, nil
}

func (ix *Indexer) walkUpsert(shareID, absDir, relDir string, count *int) error {
	entries, err := os.ReadDir(platform.LongPath(absDir))
	if err != nil {
		return fmt.Errorf("读取目录 %s: %w", absDir, err)
	}
	if len(entries) == 0 {
		return nil
	}
	type item struct {
		req  UpsertReq
		abs  string
		rel  string
		kind int
	}
	batch := make([]item, 0, len(entries))

	for _, e := range entries {
		name := e.Name()
		// 快同步的暂存区：成百上千个 .part 会不停生成/改名。既不该进索引，
		// 也不该让监听器为它刷"标记删除失败"的日志（实测一次同步能刷出 500 条）。
		if name == ".fsgw-sync" {
			continue
		}
		abs := filepath.Join(absDir, name)
		rel := name
		if relDir != "" {
			rel = relDir + "/" + name
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		kind := KindFile
		if info.IsDir() {
			kind = KindDir
		}
		id, err := platform.GetFileID(abs, info.IsDir())
		native := ""
		if err == nil {
			native = id.String()
		}
		objectID := ""
		// 先在事务外占位，事务内再落到 objects 表。
		batch = append(batch, item{
			req: UpsertReq{
				ShareID:    shareID,
				ObjectID:   objectID,
				ParentPath: KeyOf(relDir),
				Name:       name,
				Kind:       kind,
				Size:       info.Size(),
				MtimeNs:    info.ModTime().UnixNano(),
				Source:     ix.p.Source,
			},
			abs:  abs,
			rel:  rel,
			kind: kind,
		})
		// 把 native id 临时放在 ObjectID 字段，事务里换成真正的 object_id。
		batch[len(batch)-1].req.ObjectID = native
		*count = *count + 1
	}

	err = ix.store.Do(func(tx *sql.Tx) error {
		for _, it := range batch {
			native := it.req.ObjectID
			if native == "" {
				native = "path:" + it.req.ShareID + ":" + KeyOf(it.rel)
			}
			objID, err := ix.store.TouchObject(tx, native)
			if err != nil {
				return err
			}
			req := it.req
			req.ObjectID = objID
			if _, err := ix.store.UpsertFile(tx, req); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// 几十万文件的共享根要走上分钟，中间没有任何输出会让人以为进程卡死。
	// 每跨过 5000 条打印一次进度（只在整批提交之后报，数字是落库的）。
	if *count/5000 != (*count-len(batch))/5000 {
		ix.log.Info("索引对齐进行中", "share", shareID, "entries", *count, "dir", relDir)
	}

	for _, it := range batch {
		if it.kind == KindDir {
			if err := ix.walkUpsert(shareID, it.abs, it.rel, count); err != nil {
				ix.log.Warn("子目录索引失败", "dir", it.abs, "err", err)
			}
		}
	}
	return nil
}

func joinRel(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

// ---------- 事件处理 ----------

// Run 消费 watcher 事件直到 Close。
// Run 开始监听一个共享根。重复调用（例如控制台换了共享目录）会先停掉
// 上一次的监听，不会出现两个 watcher 往同一份索引里写。
func (ix *Indexer) Run(shareID, root string) {
	ix.StopShare(shareID)
	w, err := platform.NewWatcher(root)
	if err != nil {
		ix.log.Error("启动监听失败", "root", root, "err", err)
		return
	}
	// 每个共享一条独立的停止开关：换根时只停自己这一个，别的共享照常工作。
	stopCh := make(chan struct{})
	ix.mu.Lock()
	ix.watches[shareID] = stopCh
	ix.mu.Unlock()

	ix.wg.Add(1)
	go func() {
		defer ix.wg.Done()
		defer w.Close()
		for {
			select {
			case <-ix.stop:
				return
			case <-stopCh:
				return
			case ev, ok := <-w.Events():
				if !ok {
					return
				}
				ix.queue.Add(1)
				ix.handle(shareID, ev)
				ix.queue.Add(-1)
			case ov, ok := <-w.Overflow():
				if !ok {
					return
				}
				ix.overflowReconcile(shareID, ov.Root)
			}
		}
	}()
	ix.log.Info("已开始监听", "share", shareID, "root", root)
}

// overflowReconcile 把连续的溢出合并成一次整树重建。
//
// 内核 inotify 队列爆掉之后，接下来几秒会持续报溢出；每条都整树 walk 一遍等于
// 自己跟自己抢 IO——一次 47 万文件的同步实测刷了 800+ 条重建，磁盘几乎被自检占满。
// 这里只允许一个重建在跑：跑的过程中再来的溢出只置脏标记，跑完补一次就收手。
func (ix *Indexer) overflowReconcile(shareID, root string) {
	ix.recMu.Lock()
	if ix.recRunning {
		ix.recDirty = true
		ix.recMu.Unlock()
		return
	}
	ix.recRunning = true
	ix.recMu.Unlock()

	ix.log.Warn("监听缓冲溢出，排队执行子树重建", "root", root)
	go func() {
		for {
			// 先等事件潮过去：立刻重建只会立刻再溢出。
			select {
			case <-ix.stop:
				ix.recMu.Lock()
				ix.recRunning, ix.recDirty = false, false
				ix.recMu.Unlock()
				return
			case <-time.After(2 * time.Second):
			}
			if err := ix.Reconcile(shareID, root, "overflow"); err != nil {
				ix.log.Error("子树重建失败", "root", root, "err", err)
			}
			ix.recMu.Lock()
			if !ix.recDirty || ix.closed.Load() {
				ix.recRunning, ix.recDirty = false, false
				ix.recMu.Unlock()
				return
			}
			ix.recDirty = false
			ix.recMu.Unlock()
		}
	}()
}

func (ix *Indexer) handle(shareID string, ev platform.Event) {
	// 快同步的暂存区在这里直接丢弃：它的临时文件每秒生成/改名上百次，
	// 每条事件都要查库、查不到还要打一条 WARN。实测一次 200MiB 同步刷了 500+ 条
	// "标记删除失败"，既是噪音，也把索引写队列堵住了（吞吐从 20MB/s 掉到 6MB/s）。
	if isSyncStaging(ev.Path) || isSyncStaging(ev.OldPath) {
		return
	}
	ix.events.Add(1)
	switch ev.Op {
	case platform.OpCreate:
		ix.onCreate(shareID, ev.Path)
	case platform.OpRemove:
		ix.onRemove(shareID, ev.Path)
	case platform.OpRename:
		ix.onMove(shareID, ev.OldPath, ev.Path)
	case platform.OpWrite:
		ix.onWrite(shareID, ev.Path)
	}
}

// isSyncStaging 判断路径是否落在快同步的暂存目录里。
func isSyncStaging(p string) bool {
	if p == "" {
		return false
	}
	p = filepath.ToSlash(p)
	return strings.Contains(p, "/.fsgw-sync/") || strings.HasSuffix(p, "/.fsgw-sync")
}

func (ix *Indexer) statOf(abs string) (os.FileInfo, error) {
	return os.Stat(platform.LongPath(abs))
}

func (ix *Indexer) onCreate(shareID, abs string) {
	sr, rel, ok := ix.relOf(abs)
	if !ok || rel == "" {
		return
	}
	if ix.suppressed(KeyOf(rel)) {
		return
	}
	info, err := ix.statOf(abs)
	if err != nil {
		return
	}
	kind := KindFile
	if info.IsDir() {
		kind = KindDir
	}
	native := ""
	if id, err := platform.GetFileID(abs, info.IsDir()); err == nil {
		native = id.String()
	}
	if native == "" {
		native = "path:" + sr.ShareID + ":" + KeyOf(rel)
	}
	req := UpsertReq{
		ShareID:    shareID,
		ParentPath: KeyOf(ParentOf(rel)),
		Name:       baseName(rel),
		Kind:       kind,
		Size:       info.Size(),
		MtimeNs:    info.ModTime().UnixNano(),
		Source:     ix.p.Source,
	}
	err = ix.store.Do(func(tx *sql.Tx) error {
		objID, err := ix.store.TouchObject(tx, native)
		if err != nil {
			return err
		}
		req.ObjectID = objID
		created, err := ix.store.UpsertFile(tx, req)
		if err != nil {
			return err
		}
		if created && kind == KindFile {
			if _, err := ix.store.AppendVersion(tx, objID, req.Size, req.MtimeNs, ChangeAppear, ix.p.Source); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		ix.log.Warn("索引新文件失败", "path", rel, "err", err)
		return
	}
	if kind == KindFile {
		ix.enqueueHash(req.ObjectID, abs, info.Size())
	}
}

func (ix *Indexer) onRemove(shareID, abs string) {
	_, rel, ok := ix.relOf(abs)
	if !ok || rel == "" {
		return
	}
	key := KeyOf(rel)
	if ix.suppressed(key) {
		return
	}
	err := ix.store.Do(func(tx *sql.Tx) error {
		_, err := ix.store.MarkDeleted(tx, key)
		return err
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		ix.log.Warn("标记删除失败", "path", rel, "err", err)
	}
}

// onMove 是"移动零版本"的落地点：只改路径属性 + 追加 path_history。
func (ix *Indexer) onMove(shareID, oldAbs, newAbs string) {
	_, oldRel, ok1 := ix.relOf(oldAbs)
	_, newRel, ok2 := ix.relOf(newAbs)
	if !ok1 || !ok2 || oldRel == "" || newRel == "" {
		return
	}
	if ix.suppressed(KeyOf(newRel)) {
		return
	}
	oldKey := KeyOf(oldRel)

	kind := KindFile
	if info, err := ix.statOf(newAbs); err == nil && info.IsDir() {
		kind = KindDir
	}

	err := ix.store.Do(func(tx *sql.Tx) error {
		_, err := ix.store.MoveFile(tx, oldKey, newRel, KeyOf(ParentOf(newRel)), kind)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		// 源不在索引里（例如监听启动前的遗留），按新建处理。
		ix.onCreate(shareID, newAbs)
		return
	}
	if err != nil {
		ix.log.Warn("移动失败", "from", oldRel, "to", newRel, "err", err)
		return
	}
	if kind == KindFile {
		if info, err := ix.statOf(newAbs); err == nil {
			ix.enqueueHash("", newAbs, info.Size())
		}
	}
}

// onWrite 用防抖合并连续写事件；静默满窗口才落一次版本。
func (ix *Indexer) onWrite(shareID, abs string) {
	_, rel, ok := ix.relOf(abs)
	if !ok || rel == "" {
		return
	}
	key := KeyOf(rel)
	if ix.suppressed(key) {
		return
	}
	ix.mu.Lock()
	if t, exists := ix.timers[key]; exists {
		t.Stop()
	}
	ix.timers[key] = time.AfterFunc(time.Duration(ix.p.DebounceContentMS)*time.Millisecond, func() {
		ix.mu.Lock()
		delete(ix.timers, key)
		ix.mu.Unlock()
		ix.flushWrite(shareID, abs, rel)
	})
	ix.mu.Unlock()
}

func (ix *Indexer) flushWrite(shareID, abs, rel string) {
	info, err := ix.statOf(abs)
	if err != nil {
		return
	}
	key := KeyOf(rel)
	row, err := ix.store.ByPath(key)
	if errors.Is(err, ErrNotFound) {
		ix.onCreate(shareID, abs)
		return
	}
	if err != nil {
		return
	}
	if row.Size == info.Size() && row.MtimeNs == info.ModTime().UnixNano() {
		return
	}
	// 目录的 mtime 变化不是内容变更，只更新元数据，绝不追加版本。
	// 否则一次目录重命名就会污染版本链，"移动零版本"直接被破坏。
	if row.Kind == KindDir {
		ix.store.Do(func(tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE files SET size=?, mtime_ns=?, updated_at=? WHERE file_id=?`,
				info.Size(), info.ModTime().UnixNano(), time.Now().UnixMilli(), row.FileID)
			return err
		})
		return
	}
	err = ix.store.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE files SET size=?, mtime_ns=?, status=?, last_source=?, updated_at=? WHERE file_id=?`,
			info.Size(), info.ModTime().UnixNano(), StatusActive, ix.p.Source, time.Now().UnixMilli(), row.FileID)
		if err != nil {
			return err
		}
		_, err = ix.store.AppendVersion(tx, row.ObjectID, info.Size(), info.ModTime().UnixNano(), ChangeWrite, ix.p.Source)
		return err
	})
	if err != nil {
		ix.log.Warn("追加版本失败", "path", rel, "err", err)
		return
	}
	ix.enqueueHash(row.ObjectID, abs, info.Size())
}

// ---------- 哈希 ----------

func (ix *Indexer) enqueueHash(objectID, abs string, size int64) {
	max := int64(ix.p.HashMaxMB) * 1024 * 1024
	if ix.p.HashMaxMB > 0 && size > max {
		return
	}
	select {
	case ix.hashCh <- hashJob{objectID: objectID, abs: abs}:
	default:
	}
}

func (ix *Indexer) hashWorker() {
	defer ix.wg.Done()
	for {
		select {
		case <-ix.stop:
			return
		case j := <-ix.hashCh:
			sum, err := sha256File(j.abs)
			if err != nil {
				continue
			}
			id := j.objectID
			if id == "" {
				// 移动后重新入队时只有路径，查一次库拿 object_id。
				if _, rel, ok := ix.relOf(j.abs); ok {
					if row, err := ix.store.ByPath(KeyOf(rel)); err == nil {
						id = row.ObjectID
					}
				}
			}
			if id != "" {
				if err := ix.store.SetHash(id, sum); err != nil {
					ix.log.Warn("写入哈希失败", "err", err)
				}
			}
		}
	}
}

func sha256File(path string) (string, error) {
	f, err := os.Open(platform.LongPath(path))
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

// ---------- 子树重建 ----------

// Reconcile 对某个子树做一次范围重建：与库做差集，不扫全盘。
func (ix *Indexer) Reconcile(shareID, absRoot, reason string) error {
	start := time.Now()
	sr, relRoot, ok := ix.relOf(absRoot)
	if !ok {
		return fmt.Errorf("路径 %s 不在任何共享根内", absRoot)
	}
	_ = sr

	seen := map[string]bool{}
	seenCount := 0
	inserted, updated := 0, 0

	var walk func(absDir, relDir string) error
	walk = func(absDir, relDir string) error {
		entries, err := os.ReadDir(platform.LongPath(absDir))
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			abs := filepath.Join(absDir, name)
			rel := joinRel(relDir, name)
			key := KeyOf(rel)
			seen[key] = true
			seenCount++

			info, err := e.Info()
			if err != nil {
				continue
			}
			kind := KindFile
			if info.IsDir() {
				kind = KindDir
			}
			native := ""
			if id, err := platform.GetFileID(abs, info.IsDir()); err == nil {
				native = id.String()
			}
			if native == "" {
				native = "path:" + shareID + ":" + key
			}
			err = ix.store.Do(func(tx *sql.Tx) error {
				objID, err := ix.store.TouchObject(tx, native)
				if err != nil {
					return err
				}
				created, err := ix.store.UpsertFile(tx, UpsertReq{
					ShareID:    shareID,
					ObjectID:   objID,
					ParentPath: KeyOf(relDir),
					Name:       name,
					Kind:       kind,
					Size:       info.Size(),
					MtimeNs:    info.ModTime().UnixNano(),
					Source:     ix.p.Source,
				})
				if created {
					inserted++
				} else {
					updated++
				}
				return err
			})
			if err != nil {
				return err
			}
			if kind == KindDir {
				if err := walk(abs, rel); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(absRoot, relRoot); err != nil {
		return err
	}

	// 库里该子树有、盘上已经没有的，标记删除。
	deleted := 0
	prefix := KeyOf(relRoot)
	rows, err := ix.store.RowsUnder(prefix)
	if err != nil {
		return err
	}
	// 子树根本身也要参与比对。
	if prefix != "" {
		if self, err := ix.store.ByPath(prefix); err == nil {
			rows = append(rows, *self)
		}
	}
	for _, r := range rows {
		if seen[r.PathKey] || r.PathKey == prefix {
			continue
		}
		key := r.PathKey
		if err := ix.store.Do(func(tx *sql.Tx) error {
			_, err := ix.store.MarkDeleted(tx, key)
			return err
		}); err == nil {
			deleted++
		}
	}

	dur := time.Since(start)
	if err := ix.store.LogReconcile(absRoot, reason, seenCount, inserted, updated, deleted, dur); err != nil {
		ix.log.Warn("写重建日志失败", "err", err)
	}
	ix.log.Info("子树重建完成", "root", absRoot, "reason", reason,
		"seen", seenCount, "inserted", inserted, "updated", updated, "deleted", deleted, "cost", dur.String())
	return nil
}
