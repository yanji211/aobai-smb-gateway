package transport

import (
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	HeaderLen     = 4
	MaxMessageLen = 16 << 20
)

var ErrFrameTooLarge = errors.New("transport: frame exceeds maximum length")

func readUint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func writeUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

type FramedConn struct {
	r       io.Reader
	w       io.Writer
	rawConn net.Conn
	readBuf []byte
	hdrBuf  [HeaderLen]byte

	// 读进度。上层（smb/server 的 serveConn）为了及时回写异步响应，给底层连接设了
	// 200ms 的读截止时间，超时就 continue 再来一轮。若此时正读到一半（报文头 2/4 字节，
	// 或 1MB WRITE 的帧体传到一半），原来的 io.ReadFull 会整体失败并把已收字节丢掉，
	// 下一轮从帧中间重新找头——于是把 SMB2 报文里的 0xFE（\xfeSMB 的 F）当成帧类型字节，
	// 报 "unexpected frame type byte 0xfe" 并断链。这里把读进度记下来，超时后可以原地续读。
	hdrRead  int // 已读到的头字节数（0..HeaderLen）
	bodyLen  int // 正在读取的帧体长度，>0 表示帧体未读完
	bodyRead int // 帧体已读字节数
}

func NewFramedConn(c net.Conn) *FramedConn {
	fc := &FramedConn{r: c, w: c, rawConn: c}
	readBuf := make([]byte, 0, 64<<10)
	fc.readBuf = readBuf[:0]
	return fc
}

// isTimeout 判断错误是不是"读超时"——上层据此决定是重试还是断开。
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (f *FramedConn) ReadMessage() ([]byte, error) {
	// 上一轮在读帧体时超时了，直接续读，不再重新找帧头。
	if f.bodyLen > 0 {
		return f.readBody()
	}

	for f.hdrRead < HeaderLen {
		n, err := f.r.Read(f.hdrBuf[f.hdrRead:])
		if n > 0 {
			f.hdrRead += n
		}
		if err != nil {
			if f.hdrRead == 0 {
				return nil, fmt.Errorf("transport: read frame header: %w", err)
			}
			// 头只读到一半：保留进度，让上层超时重试时接着读。
			return nil, fmt.Errorf("transport: read frame header (%d/%d): %w", f.hdrRead, HeaderLen, err)
		}
	}

	if f.hdrBuf[0] != 0x00 {
		f.hdrRead = 0
		return nil, fmt.Errorf("transport: unexpected frame type byte 0x%02x", f.hdrBuf[0])
	}
	n := int(readUint24(f.hdrBuf[1:]))
	f.hdrRead = 0
	if n == 0 {
		f.readBuf = f.readBuf[:0]
		return f.readBuf, nil
	}
	if n > MaxMessageLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	if cap(f.readBuf) < n {
		f.readBuf = make([]byte, n)
	} else {
		f.readBuf = f.readBuf[:n]
	}
	f.bodyLen = n
	f.bodyRead = 0
	return f.readBody()
}

// readBody 把当前帧的帧体读完；超时则保留进度返回，下轮 ReadMessage 续读。
func (f *FramedConn) readBody() ([]byte, error) {
	for f.bodyRead < f.bodyLen {
		n, err := f.r.Read(f.readBuf[f.bodyRead:f.bodyLen])
		if n > 0 {
			f.bodyRead += n
		}
		if err != nil {
			if isTimeout(err) && f.bodyRead < f.bodyLen {
				return nil, fmt.Errorf("transport: read frame body (%d/%d): %w", f.bodyRead, f.bodyLen, err)
			}
			f.bodyLen, f.bodyRead = 0, 0
			return nil, fmt.Errorf("transport: read frame body: %w", err)
		}
	}
	f.bodyLen, f.bodyRead = 0, 0
	return f.readBuf, nil
}

func (f *FramedConn) WriteMessage(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("transport: cannot write empty frame")
	}
	if uint32(len(payload)) > MaxMessageLen {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	f.hdrBuf[0] = 0x00
	writeUint24(f.hdrBuf[1:], uint32(len(payload)))

	if _, err := f.w.Write(f.hdrBuf[:]); err != nil {
		return fmt.Errorf("transport: write frame header: %w", err)
	}
	if _, err := f.w.Write(payload); err != nil {
		return fmt.Errorf("transport: write frame body: %w", err)
	}
	return nil
}

func (f *FramedConn) Underlying() net.Conn { return f.rawConn }

func ReadFrame(r io.Reader, buf *[]byte) ([]byte, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("transport: read frame header: %w", err)
	}
	if hdr[0] != 0x00 {
		return nil, fmt.Errorf("transport: unexpected frame type byte 0x%02x", hdr[0])
	}
	n := int(readUint24(hdr[1:]))
	if n == 0 {
		*buf = (*buf)[:0]
		return *buf, nil
	}
	if n > MaxMessageLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	if cap(*buf) < n {
		*buf = make([]byte, n)
	} else {
		*buf = (*buf)[:n]
	}
	if _, err := io.ReadFull(r, *buf); err != nil {
		return nil, fmt.Errorf("transport: read frame body (%d bytes): %w", n, err)
	}
	return *buf, nil
}

func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("transport: cannot write empty frame")
	}
	if uint32(len(payload)) > MaxMessageLen {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	var hdr [HeaderLen]byte
	hdr[0] = 0x00
	writeUint24(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("transport: write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("transport: write frame body: %w", err)
	}
	return nil
}
