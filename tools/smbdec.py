#!/usr/bin/env python3
"""把 SMB 抓包解成可读的命令流（纯标准库，无 scapy 依赖）。

用法：
    python tools/smbdec.py x.pcap             # 逐帧列出命令/状态/关键字段
    python tools/smbdec.py x.pcap create      # 只展开 CREATE：路径、FileId、CreateContexts
    python tools/smbdec.py x.pcap nego        # 只展开协商：方言表、能力位、3.1.1 上下文

配合 `FSGW_SMB_TRACE=1` 或 `tcpdump -i lo -U -s 0 -w x.pcap port <port>` 使用。
抓包文件在环回上必须用 `-U`（否则缓冲里没有内容），且写文件时归 tcpdump 用户，
普通用户读不了就 `sudo cp` 一份。

`nego` 模式专门用来回答"这台机器到底是什么客户端"：Windows 与 mac 的首包
（SMB1 探测）一字不差，只能靠"之后有没有补发 SMB2 协商 + 能力位/加密套件"
分开。它会把每个 TCP 连接里 SMB1 探测包与 SMB2 协商请求全部列出来。

几个"照 SMB2 规范写但客户端不认"的偏移，都在这里标了注释——排查时先怀疑这些：
  * 协商响应：ServerGuid 在 body[8:24]（不是 28..44）
  * 协商响应：SecurityBufferOffset 在 body[56]，DialectRevision 在 body[4]
  * 协商请求：Capabilities 在 body[8]（响应里在 24，两者布局不同）
  * VALIDATE_NEGOTIATE_INFO 输出恰好 24 字节：Capabilities/SecurityMode/Dialect 顺序见下
"""
import struct
import sys

CMD = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT",
       5: "CREATE", 6: "CLOSE", 7: "FLUSH", 8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL",
       12: "ECHO", 13: "QUERY_DIRECTORY", 14: "CHANGE_NOTIFY", 15: "QUERY_INFO", 16: "SET_INFO"}

# SMB1 命令号只列一个：客户端连 445 时唯一会发的 SMB1 包就是 NEGOTIATE 探测。
SMB1_CMD = {0x72: "NEGOTIATE(探测)"}

# SMB 3.1.1 的 NegotiateContext 类型与常见取值
CTX = {1: "PREAUTH_INTEGRITY", 2: "ENCRYPTION", 3: "COMPRESSION", 5: "NETNAME", 6: "TRANSPORT"}
CIPHER = {0x0001: "AES-128-CCM", 0x0002: "AES-128-GCM", 0x0003: "AES-256-CCM", 0x0004: "AES-256-GCM"}
COMP_ALG = {0x0000: "NONE", 0x0001: "LZNT1", 0x0002: "LZ77", 0x0003: "LZ77+Huffman"}
HASH_ALG = {0x0001: "SHA-512"}


def u16(b, o): return struct.unpack("<H", b[o:o + 2])[0]
def u32(b, o): return struct.unpack("<I", b[o:o + 4])[0]
def u64(b, o): return struct.unpack("<Q", b[o:o + 8])[0]


def strip_link(raw, link):
    """剥链路层，返回 IP 包。linktype 见 pcap 头。"""
    if link == 1:                                  # Ethernet
        if len(raw) < 14 or struct.unpack(">H", raw[12:14])[0] != 0x0800:
            return None
        return raw[14:]
    if link == 113:                                # LINUX_SLL
        return raw[16:] if struct.unpack(">H", raw[14:16])[0] == 0x0800 else None
    if link == 276:                                # LINUX_SLL2
        return raw[20:] if struct.unpack(">H", raw[0:2])[0] == 0x0800 else None
    if link == 0:                                  # NULL / loopback
        return raw[4:] if struct.unpack("<I", raw[:4])[0] == 2 else None
    return None


def read_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        raise SystemExit("不是 pcap：文件只有 %d 字节（tcpdump 忘了 -U？）" % len(data))
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xa1b2c3d4, 0x4d3cb21a):
        end = "<"
    elif magic in (0xd4c3b2a1, 0xa1b23c4d):
        end = ">"
    else:
        raise SystemExit("不是 pcap：magic=%s" % hex(magic))
    vmaj, vmin, _tz, _sig, _snap, link = struct.unpack(end + "HHiIII", data[4:24])
    off, pkts = 24, []
    while off + 16 <= len(data):
        _ts, _tu, incl, _orig = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        if off + incl > len(data):
            break
        pkts.append(data[off:off + incl])
        off += incl
    return vmaj, vmin, link, pkts


def streams(pkts, link):
    """按四元组聚合 TCP 载荷，再按序号拼回去（去重传重叠）。"""
    buckets = {}
    for raw in pkts:
        ip = strip_link(raw, link)
        if not ip or len(ip) < 20 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0f) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack(">HH", tcp[0:4])
        seq = struct.unpack(">I", tcp[4:8])[0]
        payload = tcp[(tcp[12] >> 4) * 4:]
        if not payload:
            continue
        key = (".".join(str(b) for b in ip[12:16]), sport, ".".join(str(b) for b in ip[16:20]), dport)
        buckets.setdefault(key, []).append((seq, payload))
    for key, items in buckets.items():
        items.sort(key=lambda x: x[0])
        buf, nxt = bytearray(), None
        for seq, payload in items:
            if nxt is None:
                buf += payload
                nxt = seq + len(payload)
                continue
            end = seq + len(payload)
            if end <= nxt:
                continue
            if seq < nxt:
                payload = payload[nxt - seq:]
            buf += payload
            nxt = end
        yield key, bytes(buf)


def frames(buf):
    """SMB 走 NetBIOS-over-TCP：4 字节大端长度 + 报文。"""
    i = 0
    while i + 4 <= len(buf):
        ln = int.from_bytes(buf[i:i + 4], "big")
        if ln == 0 or ln > 8 * 1024 * 1024:
            i += 1
            continue
        if i + 4 + ln > len(buf):
            break
        yield buf[i + 4:i + 4 + ln]
        i += 4 + ln


def smb2(fr):
    """返回 (cmd, status, flags, msgid, body)；不是 SMB2 返回 None。"""
    if len(fr) < 64 or fr[0] != 0xFE or fr[1:4] != b"SMB":
        return None
    return u16(fr, 12), u32(fr, 8), u32(fr, 16), u64(fr, 24), fr[64:]


def dec_create_req(body):
    nameoff, namelen = u16(body, 44), u16(body, 46)
    ctxoff, ctxlen = u32(body, 48), u32(body, 52)
    name = body[nameoff - 64:nameoff - 64 + namelen].decode("utf-16-le", "replace") if namelen else ""
    return name, dec_ctxs(body, ctxoff, ctxlen)


def _pick(body, ctxStart, off, ln):
    """取 CreateContext 里的名字/数据。

    坑：MS-SMB2 说 NameOffset / DataOffset 从 **SMB2 头**起算，但内核 CIFS 实测是
    从 **CreateContext 结构自身**起算（noff=16 就是紧跟在 16 字节头之后）。
    两种都试，谁落在报文范围内用谁。
    """
    if ln == 0:
        return b""
    raw = body[ctxStart + off:ctxStart + off + ln]
    if len(raw) < ln:
        raw = body[ctxStart + off - 64:ctxStart + off - 64 + ln]
    return raw


def _ctxname(raw):
    """上下文名实际是 ASCII（QFid / MxAc / AlSi / DHnQ），规范写着 Unicode——
    全是可打印字节就按 ASCII 读，否则按 UTF-16LE。"""
    if raw and all(32 <= b < 127 for b in raw):
        return raw.decode("ascii", "replace")
    return raw.decode("utf-16-le", "replace").rstrip("\x00")


def dec_ctxs(body, ctxoff, ctxlen):
    out = {}
    if not ctxlen:
        return out
    e = max(ctxoff - 64, 0)
    end = min(e + ctxlen, len(body))
    while e + 16 <= end:
        nxt, noff, nlen = u32(body, e), u16(body, e + 4), u16(body, e + 6)
        doff, dlen = u16(body, e + 10), u32(body, e + 12)
        nm = _ctxname(_pick(body, e, noff, nlen))
        out[nm] = _pick(body, e, doff, dlen)[:32].hex()
        if nxt == 0:
            break
        e += nxt
    return out


def dec_create_resp(body):
    return {
        "CreateAction": {0: "SUPERSEDED", 1: "OPENED", 2: "CREATED", 3: "OVERWRITTEN"}.get(u32(body, 4), u32(body, 4)),
        "EndOfFile": u64(body, 48),
        "FileAttributes": "0x%08x" % u32(body, 56),
        "FileId": body[64:80].hex() if len(body) >= 80 else "",
        "ctx": dec_ctxs(body, u32(body, 80), u32(body, 84)),
    }


def dec_nego_ctxs(body):
    """解 SMB 3.1.1 的 NegotiateContexts（请求方向）。

    上下文偏移从 **SMB2 头**起算（body 里减 64），每个上下文 8 字节头，
    按 8 字节对齐往后走。这几个值既是"客户端支持什么"的清单，也是识别
    客户端的指纹：mac Big Sur 报 2 个加密套件，Windows 报 4 个。
    """
    if len(body) < 36:
        return []
    cnt, off = u16(body, 32), u32(body, 28)
    if cnt == 0 or off < 64:
        return []
    e, out = off - 64, []
    for _ in range(cnt):
        if e + 8 > len(body):
            break
        ctype, dlen = u16(body, e), u16(body, e + 2)
        d = body[e + 8:e + 8 + dlen]
        info = ""
        if ctype == 1 and len(d) >= 4:                 # PREAUTH_INTEGRITY
            # 顺序是 HashAlgorithmCount -> SaltLength -> HashAlgorithms -> Salt，
            # 不是 count -> algs -> saltlen（按后者读会把 32 字节盐长当成算法号）
            n, salt = u16(d, 0), u16(d, 2)
            hs = [HASH_ALG.get(u16(d, 4 + 2 * i), hex(u16(d, 4 + 2 * i))) for i in range(n)]
            info = "hashes=%s saltlen=%d" % (hs, salt)
        elif ctype == 2 and len(d) >= 2:               # ENCRYPTION
            n = u16(d, 0)
            info = "ciphers=%s" % [CIPHER.get(u16(d, 2 + 2 * i), hex(u16(d, 2 + 2 * i))) for i in range(n)]
        elif ctype == 3 and len(d) >= 2:               # COMPRESSION
            n = u16(d, 0)
            info = "algos=%s" % [COMP_ALG.get(u16(d, 2 + 2 * i), hex(u16(d, 2 + 2 * i))) for i in range(n)]
        elif ctype == 5 and len(d) >= 2:               # NETNAME：客户端要访问的主机名
            info = "netname=%r" % d.decode("utf-16-le", "replace").rstrip("\x00")
        out.append("      ctx 0x%04x %-17s %s" % (ctype, CTX.get(ctype, "?"), info))
        e += 8 + dlen
        if (8 + dlen) % 8:
            e += 8 - (8 + dlen) % 8
    return out


def show_frame(cmd, status, flags, mid, body, fr):
    extra = ""
    if cmd == 0 and (flags & 1) and len(body) >= 64:
        # 响应：注意 Guid 在 [8:24]，caps 在 24（与请求的布局不同）
        extra = " [RESP] dialect=0x%04x secmode=0x%04x caps=0x%08x guid=%s" % (
            u16(body, 4), u16(body, 2), u32(body, 24), body[8:24].hex())
    elif cmd == 0:
        n = u16(body, 2) if len(body) >= 4 else 0
        dl = [u16(body, 36 + 2 * i) for i in range(n) if 38 + 2 * i <= len(body)]
        # 请求方向：SecMode 在 4、Capabilities 在 8（响应里 caps 在 24，别照抄）
        extra = " [REQ] secmode=0x%04x caps=0x%08x dialects=%s" % (
            u16(body, 4) if len(body) >= 6 else 0,
            u32(body, 8) if len(body) >= 12 else 0,
            [hex(x) for x in dl])
    elif cmd == 5:
        if flags & 1:
            if status == 0:
                d = dec_create_resp(body)
                extra = " RESP action=%s eof=%d fid=%s" % (d["CreateAction"], d["EndOfFile"], d["FileId"])
        else:
            name, ctxs = dec_create_req(body)
            extra = " REQ name=%r ctx=%s" % (name, list(ctxs))
    elif cmd in (15, 16) and len(body) >= 8:
        if flags & 1:
            extra = " RESP class=0x%02x outlen=%d" % (body[2], u32(body, 4))
        else:
            extra = " REQ class=0x%02x" % body[3]
    elif cmd == 11 and len(body) >= 8:
        ctl = u32(body, 4)
        extra = " ctl=0x%08x" % ctl
        if status == 0 and len(body) >= 40:
            outoff, outlen = u32(body, 32), u32(body, 36)
            blob = fr[64 + outoff:64 + outoff + outlen]
            if ctl == 0x00140204 and len(blob) >= 24:
                # VALIDATE_NEGOTIATE_INFO 输出恰好 24 字节
                extra += " VALIDATE caps=0x%08x guid=%s secmode=0x%04x dialect=0x%04x len=%d" % (
                    u32(blob, 0), blob[4:20].hex(), u16(blob, 20), u16(blob, 22), len(blob))
            else:
                extra += " out=%d blob=%s" % (outlen, blob[:24].hex())
    elif cmd == 13 and flags & 1 and len(body) >= 8:
        extra = " RESP entries=%d" % u32(body, 4)
    return "%s%s" % (CMD.get(cmd, cmd), extra)


def main():
    argv = sys.argv[1:]
    mode = "all"
    for m in ("create", "nego"):
        if m in argv:
            mode = m
            argv = [a for a in argv if a != m]
    if not argv:
        raise SystemExit(__doc__)
    vmaj, vmin, link, pkts = read_pcap(argv[0])
    print("pcap %d.%d linktype=%d packets=%d" % (vmaj, vmin, link, len(pkts)))

    seen = 0
    for key, buf in streams(pkts, link):
        fs = list(frames(buf))
        probe = [f for f in fs if f[:4] == b"\xffSMB"]
        if not any(f[:4] == b"\xfeSMB" for f in fs) and not (mode == "nego" and probe):
            continue
        seen += 1
        print("\n==== %s:%d -> %s:%d  (%d frames, SMB1 探测 %d 条) ====" % (
            key[0], key[1], key[2], key[3], len(fs), len(probe)))

        if mode == "nego":
            for fr in fs:
                if fr[:4] == b"\xffSMB":
                    cmd1 = fr[4] if len(fr) > 4 else -1
                    print("  SMB1  %-20s len=%d" % (SMB1_CMD.get(cmd1, "cmd=0x%02x" % cmd1), len(fr)))
                    continue
                p = smb2(fr)
                if not p:
                    continue
                cmd, status, flags, mid, body = p
                if cmd != 0 or flags & 1:
                    continue
                print("  NEGOTIATE REQ mid=%-4d %s" % (mid, show_frame(cmd, status, flags, mid, body, fr)))
                for line in dec_nego_ctxs(body):
                    print(line)
            continue

        for fr in fs:
            p = smb2(fr)
            if not p:
                print("  [非 SMB2] len=%d %s" % (len(fr), fr[:16].hex()))
                continue
            cmd, status, flags, mid, body = p
            if mode == "create" and cmd != 5:
                continue
            print("  mid=%-6d %-70s status=0x%08x flags=0x%08x len=%d" % (
                mid, show_frame(cmd, status, flags, mid, body, fr), status, flags, len(body)))
    print("\nSMB streams: %d" % seen)


if __name__ == "__main__":
    main()
