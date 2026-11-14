//go:build linux || windows

package smbgo

// 兼容层的回归测试：这两个补丁直接决定 Linux 能不能挂载，
// 而且都属于"改字节"的活，偏移错一位客户端就解析成垃圾，所以逐字段盯。

import (
	"encoding/binary"
	"testing"
)

// smb2Frame 拼一个带 NetBIOS 头的 SMB2 报文。
func smb2Frame(cmd uint16, mid uint64, body []byte) []byte {
	hdr := make([]byte, smb2HeaderLen)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:], smb2HeaderLen)
	binary.LittleEndian.PutUint16(hdr[12:], cmd)
	binary.LittleEndian.PutUint32(hdr[16:], smb2FlagResponse)
	binary.LittleEndian.PutUint64(hdr[24:], mid)

	out := make([]byte, nbHeaderLen)
	out = append(out, hdr...)
	out = append(out, body...)
	fixNBLength(out)
	return out
}

// 内层对 VALIDATE_NEGOTIATE_INFO 的回包长这样：把实参当输入填、输出长度为 0。
// 内核照规范解析就得到空数据，于是判定"协商结果被篡改"。
func TestFixValidateNegotiateInfo(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.client = ClientInfo{Kind: ClientLinuxCIFS}
	st.comp = compatFor(ClientLinuxCIFS)

	var guid [16]byte
	for i := range guid {
		guid[i] = byte(0xA0 + i)
	}
	st.mu.Lock()
	st.haveNego = true
	st.negoCaps = 0x00000004
	st.negoGuid = guid
	st.negoSecMode = 1
	st.negoDialect = 0x0300
	st.mu.Unlock()

	var fileID [16]byte
	for i := range fileID {
		fileID[i] = 0xFF
	}
	st.noteIoctl(4, ioctlReq{code: fsctlValidateNegotiateInfo, fileID: fileID})

	// 内层那种坏响应：StructureSize 写成 57、InputCount=26、OutputCount=0。
	body := make([]byte, 48)
	binary.LittleEndian.PutUint16(body[0:], 57)
	binary.LittleEndian.PutUint32(body[4:], fsctlValidateNegotiateInfo)
	copy(body[8:24], fileID[:])
	binary.LittleEndian.PutUint32(body[24:], 120) // InputOffset
	binary.LittleEndian.PutUint32(body[28:], 26)  // InputCount
	frame := smb2Frame(smb2CmdIoctl, 4, body)

	out, ok := fixValidateNegotiateInfo(frame, st)
	if !ok {
		t.Fatal("应该重建这条响应")
	}
	if len(out) != nbHeaderLen+smb2HeaderLen+48+24 {
		t.Fatalf("总长度不对: %d", len(out))
	}
	h := out[nbHeaderLen:]
	if st := binary.LittleEndian.Uint32(h[8:]); st != 0 {
		t.Errorf("状态应为成功，实际 0x%08x", st)
	}
	b := h[smb2HeaderLen:]
	if got := binary.LittleEndian.Uint16(b[0:]); got != 49 {
		t.Errorf("StructureSize 应为 49（响应），实际 %d", got)
	}
	if got := binary.LittleEndian.Uint32(b[4:]); got != fsctlValidateNegotiateInfo {
		t.Errorf("CtlCode 不对: 0x%08x", got)
	}
	if got := string(b[8:24]); got != string(fileID[:]) {
		t.Error("FileId 必须沿用请求里的，否则客户端认为是别的管道")
	}
	if got := binary.LittleEndian.Uint32(b[32:]); got != 112 {
		t.Errorf("OutputOffset 应为 112，实际 %d", got)
	}
	if got := binary.LittleEndian.Uint32(b[36:]); got != 24 {
		t.Errorf("OutputCount 应为 24，实际 %d", got)
	}
	if got := binary.LittleEndian.Uint32(b[40:]); got != 1 {
		t.Errorf("Flags 应为 SMB2_0_IOCTL_IS_FSCTL(1)，实际 %d", got)
	}

	data := b[48:]
	if got := binary.LittleEndian.Uint32(data[0:]); got != 0x00000004 {
		t.Errorf("Capabilities 与协商不一致: 0x%08x", got)
	}
	if string(data[4:20]) != string(guid[:]) {
		t.Error("ServerGuid 与协商不一致，内核会报 security settings mismatch")
	}
	if got := binary.LittleEndian.Uint16(data[20:]); got != 1 {
		t.Errorf("SecurityMode 与协商不一致: %d", got)
	}
	if got := binary.LittleEndian.Uint16(data[22:]); got != 0x0300 {
		t.Errorf("Dialect 与协商不一致: 0x%04x", got)
	}
}

// 没记录协商结果时不能瞎编：宁可不改，也不能回一组零值让内核判失败。
func TestFixValidateNegotiateInfoNeedsNego(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.comp = compatFor(ClientLinuxCIFS)
	st.noteIoctl(4, ioctlReq{code: fsctlValidateNegotiateInfo})
	body := make([]byte, 48)
	binary.LittleEndian.PutUint16(body[0:], 57)
	binary.LittleEndian.PutUint32(body[4:], fsctlValidateNegotiateInfo)
	if _, ok := fixValidateNegotiateInfo(smb2Frame(smb2CmdIoctl, 4, body), st); ok {
		t.Error("没协商记录时不该重建")
	}
}

// 连接不是这个 ioctl 时不许动，否则会误伤别的请求。
func TestFixValidateNegotiateInfoOtherIOCTL(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.comp = compatFor(ClientLinuxCIFS)
	st.mu.Lock()
	st.haveNego = true
	st.mu.Unlock()
	st.noteIoctl(4, ioctlReq{code: fsctlDFSGetReferrals})

	body := make([]byte, 48)
	binary.LittleEndian.PutUint16(body[0:], 57)
	if _, ok := fixValidateNegotiateInfo(smb2Frame(smb2CmdIoctl, 4, body), st); ok {
		t.Error("DFS 的 ioctl 不该被当成 validate negotiate")
	}
}

// 内核会问的两种文件系统信息类：必须回合法的结构，否则
// "get root inode failed"，挂载直接 abort。
func TestFixFilesystemProbeInfo(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.comp = compatFor(ClientLinuxCIFS)

	// 内层的失败响应：9 字节 ERROR 体。
	errBody := make([]byte, 9)
	binary.LittleEndian.PutUint16(errBody[0:], 9)

	st.noteQueryInfo(9, qinfoReq{infoType: infoTypeFilesystem, class: fileFsDeviceInformation})
	out, ok := fixVolumeInfo(smb2Frame(smb2CmdQueryInfo, 9, errBody), st)
	if !ok {
		t.Fatal("FileFsDeviceInformation 应被补齐")
	}
	h := out[nbHeaderLen:]
	if s := binary.LittleEndian.Uint32(h[8:]); s != 0 {
		t.Fatalf("状态应改为成功，实际 0x%08x", s)
	}
	b := h[smb2HeaderLen:]
	if n := binary.LittleEndian.Uint32(b[4:]); n != 8 {
		t.Fatalf("设备信息应为 8 字节，实际 %d", n)
	}
	data := b[8:]
	if got := binary.LittleEndian.Uint32(data[0:]); got != fileDeviceDisk {
		t.Errorf("DeviceType 应为 FILE_DEVICE_DISK(7)，实际 %d", got)
	}
	if got := binary.LittleEndian.Uint32(data[4:]); got&fileDeviceIsMounted == 0 {
		t.Errorf("Characteristics 应含 FILE_DEVICE_IS_MOUNTED，实际 0x%08x", got)
	}

	st.noteQueryInfo(11, qinfoReq{infoType: infoTypeFilesystem, class: fileFsSectorSizeInformation})
	out2, ok := fixVolumeInfo(smb2Frame(smb2CmdQueryInfo, 11, errBody), st)
	if !ok {
		t.Fatal("FileFsSectorSizeInformation 应被补齐")
	}
	b2 := out2[nbHeaderLen+smb2HeaderLen:]
	if n := binary.LittleEndian.Uint32(b2[4:]); n != 28 {
		t.Fatalf("扇区信息应为 28 字节，实际 %d", n)
	}
	if got := binary.LittleEndian.Uint32(b2[8:]); got != bytesPerSectorForReporting {
		t.Errorf("逻辑扇区应为 512，实际 %d", got)
	}
	if got := binary.LittleEndian.Uint32(b2[12:]); got == 0 {
		t.Error("物理扇区不能是 0，客户端会拒绝用它做对齐")
	}
}

// Windows 不查这两类，保持原样：万一以后库改好了，Windows 走的就是库的答案。
func TestFixFilesystemProbeInfoSkippedForWindows(t *testing.T) {
	st := newConnState("/tmp", "share", nil, nil)
	st.comp = compatFor(ClientWindows)
	st.noteQueryInfo(9, qinfoReq{infoType: infoTypeFilesystem, class: fileFsDeviceInformation})
	errBody := make([]byte, 9)
	binary.LittleEndian.PutUint16(errBody[0:], 9)
	if _, ok := fixVolumeInfo(smb2Frame(smb2CmdQueryInfo, 9, errBody), st); ok {
		t.Error("Windows 路径不该被改写")
	}
}
