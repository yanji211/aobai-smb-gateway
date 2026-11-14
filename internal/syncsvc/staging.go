package syncsvc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// staging 管理"正在拼装"的文件。
//
// 为什么不用内存位图：崩溃重启后内存就没了，而 .part/.map 文件留在盘上，
// 重跑时能直接算出"哪几块已经在了"。这是断点续传的全部秘密——没有别的。
type staging struct {
	mu        sync.Mutex
	open      map[string]*stagedFile // key = sid/fid
	limit     int
	chunkSize int64
}

type stagedFile struct {
	part *os.File
	bit  *os.File
	mu   sync.Mutex // 保护位图读改写
	used time.Time
}

func newStaging(limit int, chunkSize int64) *staging {
	if limit <= 0 {
		limit = 16
	}
	if chunkSize <= 0 {
		chunkSize = 4 << 20
	}
	return &staging{open: map[string]*stagedFile{}, limit: limit, chunkSize: chunkSize}
}

func (s *staging) key(sid, fid string) string { return sid + "/" + fid }

// acquire 拿到（或打开）某文件的暂存句柄。partSize 用来判断是否需要截断：
// 客户端用同一 fid 重传时，若目标大小变了，旧 .part 必须作废。
func (s *staging) acquire(root, sid, fid string, size int64) (*stagedFile, error) {
	k := s.key(sid, fid)
	s.mu.Lock()
	defer s.mu.Unlock()

	if f, ok := s.open[k]; ok {
		f.used = time.Now()
		return f, nil
	}

	dir := sessionStagingDir(root, sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	pp := stagingPath(root, sid, fid)
	part, err := os.OpenFile(pp, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if fi, err := part.Stat(); err == nil && size >= 0 && fi.Size() != 0 && fi.Size() > size {
		// 大小对不上（同一路径换了新内容）→ 旧进度作废。
		if err := part.Truncate(0); err != nil {
			part.Close()
			return nil, err
		}
		_ = os.Remove(stagingMapPath(root, sid, fid))
	}

	nchunks := 0
	if size > 0 {
		nchunks = int((size + s.chunkSize - 1) / s.chunkSize)
	}
	mp := stagingMapPath(root, sid, fid)
	bit, err := os.OpenFile(mp, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		part.Close()
		return nil, err
	}
	if err := bit.Truncate(int64((nchunks + 7) / 8)); err != nil {
		part.Close()
		bit.Close()
		return nil, err
	}

	f := &stagedFile{part: part, bit: bit, used: time.Now()}
	s.open[k] = f
	s.evictLocked()
	return f, nil
}

func (s *staging) evictLocked() {
	if len(s.open) <= s.limit {
		return
	}
	// 关掉最久没用的几个，直到回到上限以内（不是只关一个：批量会话会一次冲进来很多）。
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(s.open))
	for k, f := range s.open {
		all = append(all, kv{k, f.used})
	}
	for len(s.open) > s.limit {
		idx := 0
		for i := 1; i < len(all); i++ {
			if all[i].t.Before(all[idx].t) {
				idx = i
			}
		}
		k := all[idx].k
		if f, ok := s.open[k]; ok {
			f.part.Close()
			f.bit.Close()
			delete(s.open, k)
		}
		all = append(all[:idx], all[idx+1:]...)
		if len(all) == 0 {
			return
		}
	}
}

func (s *staging) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, f := range s.open {
		f.part.Close()
		f.bit.Close()
		delete(s.open, k)
	}
}

func (s *staging) forget(sid, fid string) {
	k := s.key(sid, fid)
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.open[k]; ok {
		f.part.Close()
		f.bit.Close()
		delete(s.open, k)
	}
}

// writeChunk 把一块写到指定偏移，并置位。已存在的块重复写是幂等的
// （客户端重传同一块不会破坏结果）。
func (s *staging) writeChunk(root, sid, fid string, size int64, idx int, data []byte) error {
	f, err := s.acquire(root, sid, fid, size)
	if err != nil {
		return err
	}
	off := int64(idx) * s.chunkSize
	if _, err := f.part.WriteAt(data, off); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return setBit(f.bit, idx)
}

// have 返回已收到的块下标。用于断点续传时告诉客户端"这些不用再传了"。
func (s *staging) have(root, sid, fid string, size int64) ([]int, error) {
	nchunks := 0
	if size > 0 {
		nchunks = int((size + s.chunkSize - 1) / s.chunkSize)
	}
	if nchunks == 0 {
		return nil, nil
	}
	f, err := s.acquire(root, sid, fid, size)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	buf := make([]byte, (nchunks+7)/8)
	n, err := f.bit.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	buf = buf[:n]
	out := make([]int, 0, nchunks)
	for i := 0; i < nchunks; i++ {
		if i/8 < len(buf) && buf[i/8]&(1<<(i%8)) != 0 {
			out = append(out, i)
		}
	}
	return out, nil
}

// ready 检查是否所有块都到齐。
func (s *staging) ready(root, sid, fid string, size int64) (bool, error) {
	nchunks := 0
	if size > 0 {
		nchunks = int((size + s.chunkSize - 1) / s.chunkSize)
	}
	if nchunks == 0 {
		return true, nil
	}
	have, err := s.have(root, sid, fid, size)
	if err != nil {
		return false, err
	}
	return len(have) == nchunks, nil
}

// commit 校验完整性、落盘、原子改名到最终路径。
// 返回值是（verify=full 时的）整文件 sha256，否则为空。
func (s *staging) commit(root, sid, fid, final string, size int64, mode os.FileMode, mtime time.Time, fullVerify bool) (string, error) {
	ok, err := s.ready(root, sid, fid, size)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("还有块没到齐，不能提交")
	}

	f, err := s.acquire(root, sid, fid, size)
	if err != nil {
		return "", err
	}
	if fi, statErr := f.part.Stat(); statErr != nil {
		return "", statErr
	} else if fi.Size() != size {
		return "", fmt.Errorf("暂存文件大小 %d 与声明 %d 不一致", fi.Size(), size)
	}

	// fsync：rename 只保证目录项原子，不保证数据已经落盘。
	// 掉电时可能得到一个"文件在、内容是空的"的经典事故，这一行就是防它。
	if err := f.part.Sync(); err != nil {
		return "", err
	}

	sum := ""
	if fullVerify {
		sum, err = hashFile(f.part)
		if err != nil {
			return "", err
		}
	}

	s.forget(sid, fid)
	_ = f.part.Close()
	_ = f.bit.Close()

	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return "", err
	}
	// Windows 上 rename 到已存在的文件会失败，先删掉旧的。
	// 时间窗口内旧文件会被短暂移除——这是"覆盖写"的固有代价，SMB 也一样。
	if _, statErr := os.Stat(final); statErr == nil {
		if rmErr := os.Remove(final); rmErr != nil {
			return "", fmt.Errorf("目标文件被占用，无法替换：%w", rmErr)
		}
	}
	pp := stagingPath(root, sid, fid)
	if err := os.Rename(pp, final); err != nil {
		return "", err
	}
	if mode != 0 {
		_ = os.Chmod(final, mode)
	}
	if !mtime.IsZero() {
		_ = os.Chtimes(final, mtime, mtime)
	}
	_ = os.Remove(stagingMapPath(root, sid, fid))
	return sum, nil
}

func setBit(f *os.File, idx int) error {
	if idx < 0 {
		return fmt.Errorf("块下标非法：%d", idx)
	}
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, int64(idx/8)); err != nil && err != io.EOF {
		return err
	}
	buf[0] |= 1 << (idx % 8)
	_, err := f.WriteAt(buf, int64(idx/8))
	return err
}

func hashFile(f *os.File) (string, error) {
	h := sha256.New()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256Hex 是给小文件与单块校验用的一次性哈希。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
