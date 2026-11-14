package index

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewObjectID 生成内容身份 ID。用时间前缀 + 随机后缀，
// 既保证唯一，也让 ID 大致按创建顺序排序（便于排查）。
func NewObjectID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 兜底：时间纳秒填充，避免返回空 ID。
		ns := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			b[i] = byte(ns >> (8 * (7 - i)))
		}
	}
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	return hex.EncodeToString(b)
}
