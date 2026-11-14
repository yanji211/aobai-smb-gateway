# SMB Go 服务端实战总结（fsgw 项目）

> 适用读者：需要对「熬拜共享家（fsgw）」的 Linux 纯 Go SMB 服务端做维护、排错、二次开发的人。
> 配套文档：`docs/01-技术设计说明.md`、`docs/04-决策点与风险登记.md`、`README.md`（"Linux 部署（纯 Go SMB 服务端）"一节）。
> 本文聚焦 **internal/smbgo** 这颗子系统，以及让它能通吃 Windows 11 24H2、电视、samba 工具、`net view` 的全部改动。

---

## 1. 背景与目标

fsgw（熬拜共享家）是本地常驻文件共享网关，SMB 是三大协议面（SMB / WebDAV / DLNA）里最"底层"的一个——电视、手机、Windows 资源管理器都靠它直读共享根。

- **Windows 版**：托管系统 SMB 共享（`net share` + 防火墙规则），需要管理员。
- **Linux 版（本文主角）**：进程内 **纯 Go SMB2/3 服务端**，不装 samba、不写 `/etc/samba`、不建系统账户。
  底层库：`github.com/sonroyaalmerol/go-smb-server v0.2.0`。

本阶段把所有"客户端连不上"的问题逐一清零，目标是：**同一份 Go 服务端**，能让 Windows 11 24H2 资源管理器、Win10、电视/手机（匿名来宾）、samba `smbclient -L`、`net view`、RPC 工具（rpcclient）全部正常访问 `\\<IP>\share` 与 `\\<IP>`（服务器根）。

---

## 2. 架构总览

```
客户端（Win11 / 电视 / smbclient）
        │  TCP 445
        ▼
[fsgw 自己持有的监听 :445]            ← net.Listen("tcp",":445")，绑 445 需 root
        │  方言表里有 SMB 2 → 把 SMB1 协商包改写成 SMB2
        │  只列 NT LM 0.12  → 整条连接交给内置 SMB1 通道（smb1srv.go）
        ▼
[库内层监听 127.0.0.1:随机空闲端口]
        ├─ 磁盘共享  share  →  normalizeBackend → vfs.NewLocalBackend(共享根)
        └─ 管道共享  IPC$   →  PipeBackend，挂 srvsvc 处理器（列出共享的 RPC）
```

**关键文件（`internal/smbgo/`）**

| 文件 | 职责 |
| --- | --- |
| `server.go` | 启动流程、对外/对内双层监听、路径规范化（`\a\b`→`a/b`）、只读后端、`stableHandle`（修正库的元数据抖动） |
| `proxy.go` | 协议边界的字节级修正（SMB1 协商兼容、DFS、QUERY_INFO、credit、目录信息类、卷信息、容量……），见第 3.3 节 |
| `ntlmauth.go` | 自研 NTLMSSP 服务端：CHALLENGE 报文重建 + 账号表/来宾策略 + 裸 NTLM/SPNEGO 形状回敬 |
| `srvsvc.go` | IPC$ 管道上的"列出共享" RPC（opnum 15 / 36），原生构造 NDR 响应 |
| `spnego.go` / `ntlmv2.go` | SPNEGO 包装、NTLMv2 验算与 SessionKey 派生 |
| `sessions.go` | 在线会话 + 登录尝试的内存表（`Sessions()` / `Attempts()` 导出给控制台） |
| `applemeta.go` | macOS 影子文件（`.DS_Store` / `._xxx` / `.Trashes` …）的识别与目录枚举过滤，见第 13 章 |
| `smb1srv.go` | 进程内置的最小 SMB1 服务端（只服务纯 SMB1 客户端，如老小米电视），Linux/Windows 共用一份代码，见第 14 章 |

**两个非显然的设计点（都在 `server.go`）**

1. **为什么自己持有一个 `:445` 监听，再转发给内层**——库只愿意听回环，且对 SMB1 协商不回。外层补做 SMB1→SMB2 改写，才让老 Windows 客户端能握手。
2. **`stableHandle` 修正库的两处元数据错误**：
   - `ChangeTime` 被库写成 `time.Now()`，导致 Windows 认为目录随时在变、反复重查根目录而列不出内容 → 改成与 `LastWrite` 一致；
   - 目录的 `Size` 被当成 `AllocationSize/EndOfFile`，Linux 上=4096，而 SMB 约定目录是 0 → 目录强制 `Size=0`。

---

## 3. 三类核心问题与修复（时间线）

### 3.1 Windows 11 24H2 强制签名 —— 最硬的一块骨头

**现象**：Win11 24H2 收到 CHALLENGE 后**不发 AUTHENTICATE**，2ms 内连发 9 次 `SESSION_SETUP`，最后 `net use` 报**错误 67「找不到网络名」**；或弹出 `0x80004005` / "策略阻止未经验证的来宾访问"。

**根因**（微软原文 + 抓包核对）：
- 24H2 起 SMB 签名**默认强制**，而来宾会话没有会话密钥、签不了名——所以"免密"在 24H2 上**不可能成功**（不是配置问题）。
- 只认"真账号 + 真口令"的会话才派生得出签名密钥。
- 底层库自带的 `ntlmssp.NewServer` 生成的 CHALLENGE 报文畸形（TargetInfo 只有 1 段、Version 全零、多塞 SEAL 位），Windows 的 `msv1_0` 直接 RST。
- 库的 NTLM flags **缺了** `EXT_SESS_SEC` / `SIGN` / `ALWAYS_SIGN`：24H2 客户端先看 NTLM 层有没有 ESS 才决定是否继续，缺位就拒。

**修复**（`ntlmauth.go`）：
- `serverSupportedFlags = 0xE2888215`，补齐 `EXT_SESS_SEC | SIGN | ALWAYS_SIGN`（只回客户端请求过的位 + 强制的 UNICODE/NTLM/ESS/TARGET_INFO）。
- 自建 CHALLENGE_MESSAGE：`TargetInfo` 依次给 NbDomain / NbComputer / DnsDomain / DnsComputer / MsvAvFlags=2 / MsvAvTimestamp；`Version=10.0.19041`；`MsvAvFlags` 必须写 2（写 1 会被 24H2 当畸形报文拒）。
- **账号表机制**（`Options.Accounts`，`server.go`）：
  - 表内用户名 → 走真 NTLMv2 验算（存的是 `NTOWFv1 = MD4(UTF16LE(口令))`，`ntlmv2.go` 里据此算 `ResponseKeyNT` 与 `ntProof`）；通过则带上 `SessionKey` → 响应被签名 → 24H2 放行。
  - 表外**具体**用户名 → **明确拒绝**（`STATUS_LOGON_FAILURE`），逼出资源管理器正常的"输入网络凭据"框；若悄悄降级成来宾，反而被 24H2 否决成看不懂的 `0x80004005`。
  - **匿名类**名字（空 / `guest` / `anonymous` / `nobody` / `public` / `ftp`）→ 仍按来宾放行，电视/手机不被这次改动砸掉。
- **裸 NTLM vs SPNEGO 形状回敬**：首字节 `0x60`=SPNEGO，否则裸 NTLMSSP；必须**按请求形状回敬**（`replyToken`/`doneToken`）。这修复了"同一条 TCP 连接上第二个会话必失败（错误 67）"——Windows 复用连接重建会话时发裸包，收到 SPNEGO 就解析失败。

### 3.2 列共享（srvsvc）—— 最近一次修复

**现象**：`\\192.0.2.11`（服务器根，不带共享名）报 **"远程过程调用 (RPC) 协议出错"**；资源管理器打开根、`net view`、`rpcclient netshareenum` 全挂。但 `\\192.0.2.11\share` 直连正常。

**根因**（对照真实 Windows 抓包定）：
- 库不实现 `NetrShareEnumAll`（**opnum 36**），一律 NACK；而 Windows 系工具用的恰恰是 36，只有 `smbclient` 用 15。
- 库的 `NetrShareEnum`（opnum 15）响应 NDR 是错的：Level 后多一个 DWORD、容器里多两个 0、结尾**缺 ResumeHandle 指针与解引用**、**缺收尾 WERROR** → 客户端解不出 → `WERR_RPC_S_CANNOT_SUPPORT` / NDR 解析失败 `0x00020008`。

**修复**（`srvsvc.go`）：在 `server.New` 之前手动 `registerSrvsvc` 在 `PipeBackend` 上挂 `srvsvc`，返回 `IPC$` 磁盘共享；库看到已存在 IPC$ 就不会再塞坏实现。处理器原生处理 opnum 15 与 36（二者签名与响应结构相同，直接复用），按真实 Windows **356 字节**响应逐字节构造 NDR：

```
Level(4)  union标记(4,=Level)  ptr→容器(4)  EntriesRead(4)  ptr→Buffer(4)  数组MaxCount(4)
每项 share_info_1{ ptr名字, type, ptr备注 }(12×n)
每个字符串{ MaxCount, Offset, ActualCount, UTF-16+\0, 4字节对齐 }
TotalEntries(4)  ptr→ResumeHandle(4)  *ResumeHandle=0(4)  WERR_OK(4)
```

支持 Level 0 / 1 / 2 / 502（Level 1 是 `smbclient`/`net rpc`/`net view` 主路径，已全通；2/502 是 rpcclient 调试路径，也已补齐布局）。

**结果**：`net view \\192.0.2.11` 正常列出 `share`（Disk）+ `IPC$`（Remote IPC）；`smbclient -L` 同样两行全。

### 3.3 协议边界（proxy.go）逐条修正

这些都是"状态码正常、客户端报错"的暗坑，只能对照 samba 成功抓包逐包改：

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `net use` 报错 121（超时） | 客户端首包是 SMB1 协商，纯 SMB2 服务端不回 | 合成等价 SMB2 协商转给内层 |
| 报错 53（找不到网络路径） | 协商响应没带 SPNEGO | 补 `NegTokenInit` |
| 会话起来后还要求签名、报错 53 | 库无"来宾"概念，`SessionFlags` 恒 0 | 置 `SMB2_SESSION_FLAG_IS_GUEST` |
| 10 秒后 RST | `IPC$` 被按磁盘共享回，DFS 探测走不下去 | 改 `ShareType=PIPE` + `MaximalAccess=0x001F00A9` |
| 同上 | 库对 `FSCTL_DFS_GET_REFERRALS` 回 `INVALID_HANDLE` | 改回 samba 的 `STATUS_NOT_FOUND` |
| 列目录报错 58 | 最简 `QUERY_INFO` 是 104 字节，库要求 105 | 补 1 字节填充 |
| 卡死 20 秒 | 客户端每个请求要 33 个 credit，库只批 1 | 补足 credit |
| 同上 | 客户端要 `FileBothDirectoryInformation(0x03)`，库按 0x01 布局回 | 按目标信息类重排目录项 |
| 只列出 1 条 | 库对同一句柄只枚举一次 | 请求侧 `RESTART_SCANS` + 放大缓冲，响应侧按句柄游标切页 |
| 剩余空间显示 0 / 恒为 1TB | 库没实现 `0x07`，`0x03` 的 `BytesPerSector` 偏移错 | 用 `statfs` 回真实容量 |
| 卷标/卷容量导致 `dir` 报 58 | 两类卷信息结构畸形（偏移错/被缓冲截断） | 代理层按规范整体重建 |
| **列共享失败（见 3.2）** | **库的 srvsvc 实现坏（36→NACK、15 NDR 错位）** | **`srvsvc.go` 原生实现 opnum 15/36** |

> 自查方法：先让同一台 Windows 客户端连一遍 samba，抓"成功"字节流，再逐包对照——上面每一条都是这么定下来的。

### 3.4 可写共享：库的写路径欠了四处

只读时这些问题都被"共享只读"挡在门外，一开 `writable: true` 就全暴露出来。四处都是**库的
缺陷**，修在 fsgw 的包装层里（`server.go` 的 `createFixBackend` / `stableHandle` /
`normalizeBackend`，`proxy.go` 的 `ackAllocationSetInfo`）。

| 现象 | 根因 | 处理 |
| --- | --- | --- |
| 新建文件恒为 0 字节；资源管理器报"目标文件夹访问被拒绝 / 你需要权限来执行此操作"（改用覆盖写又正常） | `getFlags` 对 `FILE_CREATE` 返回 `O_CREATE\|O_EXCL`，**没有 `O_RDWR`**，句柄只读 → 紧随其后的 `WRITE` 就是 `EBADF` → `osErrToStatus` 一律映射成 `ACCESS_DENIED` | `createFixBackend.Open`：自己按 `O_CREATE\|O_RDWR(\|O_TRUNC)` 建/截断（`FILE_CREATE` 保留 `O_EXCL`），再把 Disposition 改成 `OPEN_IF` 交给库 |
| 大文件复制"进度走完却报意外的网络错误"；`Set-Content`/`FileStream` 一个字节都写不进去 | 复制路径建好文件后先发 `SET_INFO` 的 `FileAllocationInformation`(19) 预占空间；库的 `handleSetInfo` 只认 Disposition / Basic / EOF / Rename 四类，其余 `NOT_SUPPORTED`，客户端当致命错误 | 代理层识别 `InfoType=1 && FileInfoClass=19` 直接回 `STATUS_SUCCESS`，不转给内层（预占提示不影响落盘） |
| 删除静默失效、截断/改时间戳无效、重命名不动 | 库靠**类型断言**找能力：删除断言 `Backend().(vfs.Remover)`、SetInfo/改名断言**句柄**的 `vfs.SetInfoer` / `vfs.Renamer`；包装层不实现就等于"不支持" | `normalizeBackend` 补 `Remove`、`stableHandle` 补 `SetInfo`/`Rename`，逐个转发；`readOnlyHandle` 保持不实现，只读语义不变 |
| 重命名后目录里出现"名字含反斜杠"的畸形条目，随后列目录报 `ERROR_BAD_NET_RESP`（58） | `localHandle.Rename` 用 `filepath.Base(filepath.FromSlash(newPath))`，Linux 上 `FromSlash` 是空操作，`\dir\b.txt` 被当成一个文件名 | `stableHandle.Rename` 先 `normalizePath`（`\`→`/`）再交给库；跨目录改名仍只取 basename，属库的限制 |

验收：Windows 侧新建/覆盖/200MB 复制（MD5 一致）/读回（MD5 一致）/重命名/删除/列举全通，
来宾用 `smbclient //<IP>/share -N -c 'put ...'` 也能写。注意 Linux 侧写权限是**整机粒度**，
`guest_writable` 不单独生效——开了 `writable` 等于同网段所有客户端都能写。

### 3.5 多文件/大文件复制几十秒后必断：读超时把帧边界读错位

**现象**：资源管理器复制一批文件，传了几十秒（或一两百 MB）后弹"出现了意外的网络错误"。
客户端表现为连接被服务端关掉：抓包里 `Z:` 的连接都是**服务端先发 FIN，再连发 RST**，
每条连接活 30～60 秒就换一条新的（端口号递增），周而复始。

**定位过程**（这次值得记，因为日志里默认什么都没有）：

1. 客户端侧抓包 → 只有 `QUERY_INFO` 的 `INVALID_PARAM`（`FileNormalizedNameInformation` /
   `FileEaInformation`，见 3.3），没有致命错误；连接是被**服务端**掐掉的。
2. 服务端 `journalctl` 里 ERROR/WARN 一条都没有，因为库把断连原因写在 **DEBUG** 级别。
   把 `log.level` 调成 `debug` 才看到真正的报错：

   ```
   {"level":"DEBUG","msg":"read error","err":"transport: unexpected frame type byte 0xfe"}
   ```

   `0xfe` 正是 SMB2 报文头的第一个字节（`\xfeSMB` 的 `F`）——内层服务把**报文中间**当成
   了新帧的帧头。
3. 在 `lo` 上抓代理↔内层（127.0.0.1 上的随机端口，启动日志里有）的全帧，逐帧校验 NetBIOS 长度字段，
   线上字节流**完全对齐**——说明不是代理写坏了，而是内层自己读串了。

**根因**在库的 `smb/server/server.go` + `smb/transport/frame.go` 的组合：

```go
// serveConn：为了及时回写异步响应，给连接设了 200ms 读截止时间，超时就 continue 重来
_ = cn.fc.Underlying().SetReadDeadline(time.Now().Add(200 * time.Millisecond))
msg, err := cn.fc.ReadMessage()
if err != nil {
    var ne net.Error
    if errors.As(err, &ne) && ne.Timeout() { continue }   // ← 这里假设"超时=还没开始读"
    return
}
```

而 `ReadMessage` 用的是 `io.ReadFull(hdr)` + `io.ReadFull(body)`：**只要中途超时，已经收到的
字节就被丢掉，读位置却停在了帧中间**。下一轮从帧体中部重新找 4 字节帧头，于是把 `0xfe`
当成类型字节，报错并断开连接。

为什么偏偏在多文件复制时触发：客户端一次发 1 MB 的 `WRITE`，写入期间磁盘/索引在忙，
TCP 收得慢，1 MB 帧体常常读不满 200 ms 就会超时一次——一超时就是一条连接报废。

**修复**：把库 vendor 到 `third_party/go-smb-server`（`go.mod` 加 `replace`），只改
`smb/transport/frame.go`——让帧读取**可续读**：

- `FramedConn` 增加 `hdrRead` / `bodyLen` / `bodyRead` 三个进度字段；
- 报文头改成 `Read` 循环累加，读一半超时就带着进度返回，下一轮接着读；
- 帧体同理，超时不算失败，保留 `bodyRead` 继续；只有非超时错误才终止；
- 超时错误仍然包成 `net.Error` 返回，`serveConn` 的 `continue` 逻辑不变。

**验收**（Windows → `Z:`）：

| 场景 | 修复前 | 修复后 |
| --- | --- | --- |
| 40 个文件 × 15 MB（600 MB） | 每 30～60 秒断一次，报意外网络错误 | 一次跑完 123.7 s，40 个文件 MD5 全一致 |
| 10 个子目录 × 20 个 512 KB（100 MB，200 文件） | 同上 | 一次跑完 38 s，200 文件 + 10 目录全一致 |
| 服务端 `unexpected frame type` 计数 | 每分钟数次 | **0** |
| 会话认证次数（12:15 之后的 5 分钟） | 每条连接都重连 | 2 次（正常建连 + 一次重连） |

顺带记一个非故障的观测：这台机器服务端走 Wi-Fi（`wlp2s0`，5 GHz，300 Mbit/s），
实测写入吞吐约 2.5～5 MB/s，而磁盘直写有 101 MB/s。吞吐瓶颈在 SMB 服务端的单连接
串行写路径，不在磁盘也不在链路余量——要提速得另做（多线程/写合并），与断连问题无关。

---

## 4. 认证策略：账号表 vs 来宾

| 场景 | 行为 | 客户端表现 |
| --- | --- | --- |
| 未配账号表 | 纯来宾：任何身份都放行 | 电视/手机免密直进 |
| 已配账号表 + 用户名在表中 + 口令对 | NTLMv2 通过，带签名 SessionKey | Win11 24H2 正常进 |
| 已配账号表 + 用户名在表中 + 口令错 | `STATUS_LOGON_FAILURE` | 重新弹凭据框 |
| 已配账号表 + 表外具体用户名 | 明确拒绝（逼出凭据框） | 弹"输入网络凭据" |
| 匿名类（空/guest/anonymous…） | 仍来宾放行 | 电视/手机照旧 |

**配置三种等价入口**
- `config.yaml` 兼容写法：`smb.account_name: fsgw` + `smb.nt_hash: <MD4十六进制>`（或 `smb.password: 明文`）。
- 账号表文件：`/etc/fsgw/smb_clients.yaml`（权限 0600，只存 NTHash，可手工编辑后重启生效）。
- 控制台「SMB 客户端」卡片：增删账号、实时在线连接、最近登录尝试（点一下把被拒客户名填进输入框）。

**常用命令**
```bash
fsgw smb nt-hash <口令>     # 生成 NT 哈希（MD4(UTF16LE(口令))）
fsgw smb check              # 报当前登记了几个账号、账号表文件位置
```

---

## 5. 部署（Linux 纯 Go）

**交叉编译（开发机在 Windows 也能出 Linux 二进制）**
```bash
cd D:\fsgw
GOOS=linux GOARCH=amd64 ./tools/go.sh build -o deploy/linux/fsgw ./cmd/fsgw
```
> `tools/go.sh` 已封装：`GOTOOLCHAIN=go1.26.10`、`GOPROXY=goproxy.cn`、本地 `GOPATH/GOCACHE`，无需本机全局装 Go。

**一键安装（部署机 root）**
```bash
cd deploy/linux && sudo sh install.sh
# 同目录需：fsgw（二进制）、config.yaml、fsgw.service
```
`install.sh` 流程：检查 445 是否被 samba 占用 → 装二进制到 `/usr/local/bin/fsgw` → 写 `/etc/fsgw/config.yaml`（旧配置自动备份 `.bak`）→ 装 systemd 单元并 `restart`。

**开关**
```bash
sudo fsgw on -state ALL -confirm   # 开 SMB + DLNA + WebDAV
sudo fsgw off                      # 全关：445/8200/8443 立即停止监听
sudo fsgw smb check                # 逐项诊断
sudo fsgw ui                       # 打印带 token 的控制台地址
```

**远端 `/etc/fsgw/config.yaml` 关键项**（当前部署）
```yaml
shares:
  - root: /srv/share      # 共享根，guest 被映射成 nobody，需 o+rx（755）
    name: share               # \\<IP>\share
    writable: false           # 只读：电视只能播放
smb:
  enabled: true
  auth: guest                 # 纯 Go 服务端只支持 guest（NTLM 握手 + 口令留空即通过）
  account_name: fsgw
  nt_hash: "00000000000000000000000000000000"   # 占位示例：NT 哈希必须是 32 位十六进制
```

**控制台远程访问**（只绑回环，用端口转发进）
```bash
ssh -L 8444:127.0.0.1:8444 example-user@192.0.2.11
# token：journalctl -u fsgw | grep -o 'http://127.0.0.1:8444/#[0-9a-f]*' | tail -1
```

---

## 6. 验证状态

| 项 | 结果 |
| --- | --- |
| `smbclient -L //192.0.2.11` | ✅ 列出 `share`(Disk) + `IPC$`(IPC) |
| `\\192.0.2.11\share` 直连 | ✅ 可读，回环 ~670 MB/s，内容哈希一致 |
| `net view \\192.0.2.11` | ✅ 正常（srvsvc 修复后） |
| Win11 24H2 资源管理器 / `net use` | ✅ 账号口令登录通过并签名 |
| Level 1 / 2 / 502 枚举 | ✅ NDR 全通 |
| `go vet ./internal/smbgo/...` | ✅ 通过（见第 8 节构建复核） |
| Windows / Linux 双平台 `build` | ✅ 通过 |
| 自测 / 验收 | ✅ 45 项 selftest + 46 项 `tools/acceptance.sh` 全绿 |

---

## 7. 已知边界与排错

- **WebDAV 明文 HTTP（8443）**：本移植无 TLS，口令 Basic 明文，仅适合局域网。
- **单页目录上限**：约 1.5 万条目录项以内能完整列出，超出只列前一段（库不支持跳过已发条目）。
- **smbclient 诊断噪音**：读大文件偶打 `parallel_read returned NT_INVALID_NETWORK_RESPONSE` 后回退串行——实际传输正确（哈希一致），可忽略。
- **Win11 客户端重定向器偶发卡死**（历史同类）：表现为服务端一切正常但 Win11 整体访问失败。恢复手段：`net use * /delete /y` 后 `net stop LanmanWorkstation` + `net start LanmanWorkstation`（**只动客户端、不动服务端**即恢复）。排错时先在 Linux 侧 `smbclient -L` 确认服务端存活，再判断是回归还是客户端卡死。
- **调试残留**：排错时在远端 `/tmp` 落的 `ipc*.pcap`、`ref.pcap`、`fsgw-new`、`pipe.py` 等，问题解决后记得清理。

---

## 8. 相关资料索引（均在 `D:\fsgw` 内）

| 资料 | 路径 | 说明 |
| --- | --- | --- |
| 本文 | `docs/05-SMB-Go服务端实战总结.md` | SMB 子系统总账 |
| 核心源码 | `internal/smbgo/server.go` `proxy.go` `ntlmauth.go` `srvsvc.go` `spnego.go` `ntlmv2.go` `sessions.go` | 见第 2 节 |
| 部署（Linux） | `deploy/linux/install.sh` `deploy/linux/config.yaml` `deploy/linux/fsgw.service` | 一键装 + 配置 + systemd |
| 构建封装 | `tools/go.sh` | 跨平台 Go 构建环境 |
| 验收 | `tools/acceptance.sh`（46 项外部黑盒） | 对着真实实例打 |
| 通用配置 | `config.yaml`（Windows 版） | `smb.auth` / `account_name` / `nt_hash` |
| 总说明 | `README.md`（"Linux 部署（纯 Go SMB 服务端）"一节） | 协议边界修正表 + Win11 章节 |

**构建复核命令**（本文第 6 节"通过"结论由以下命令复核）
```bash
./tools/go.sh vet ./internal/smbgo/...
./tools/go.sh build -o fsgw.exe        ./cmd/fsgw     # Windows
GOOS=linux ./tools/go.sh build -o fsgw ./cmd/fsgw     # Linux
```

## 9. Windows 版移植记录（2026-11）

### 9.1 为什么要移植

Windows 版原来是"托管系统共享"（`net share` + `ForceGuest`）。在 Win11 24H2/25H2 上这条路走不通：

| 问题 | 机制 | 结果 |
| --- | --- | --- |
| 免密必然失败 | 24H2 客户端默认强制 SMB 签名；来宾会话没有会话密钥，签不了名 | "组织的安全策略阻止未经身份验证的来宾访问" |
| 免密只能整机开 | 免密靠 `ForceGuest=1`，那是全局开关 | 一开，本机所有网络登录都映射成 Guest |

自研服务端两头都解决：认证在进程内、签名密钥由 NT 哈希派生、免密会话打 `IS_GUEST` 标记
让客户端自己关签名。于是决定把 Linux 那套原样搬上 Windows，而不是继续在系统共享上打补丁。

### 9.2 改动清单

| 文件 | 改动 | 为什么 |
| --- | --- | --- |
| `internal/smbgo/proxy.go` | build tag `linux` → `linux \|\| windows`；抽出 `diskUnits` | 协议翻译层是纯字节操作，与平台无关，Windows 必须复用，否则 SMB1 协商/SPNEGO/SET_INFO 那些坑全部复发 |
| `internal/smbgo/diskfs_windows.go` | 新增，`GetDiskFreeSpaceExW` + `GetDiskFreeSpaceW` | 报卷容量（`FileFsFullSizeInformation`）要有真实的 AllocationUnits，不能用假数 |
| `internal/smbgo/diskfs_unix.go` | 由 `proxy.go` 原有的 statfs 版本移出 | 同上，按平台分文件 |
| `internal/smbhost/hosted_go.go` | 新增，Linux 的实现整体搬进来，改名 `goEnsureShare` 等 | Windows 与 Linux 共用一份，避免两套逻辑漂移 |
| `internal/smbhost/hosted_linux.go` | 变成薄转发 | 接口不变 |
| `internal/smbhost/hosted_windows.go` | 变成引擎分发器：`auto` / `go` / `native` | 保留 native 作兜底与显式回退 |
| `internal/smbhost/hosted_windows_native.go` | 原 Windows 实现改名 `native*` | 不与 go 引擎抢符号 |
| `internal/smbhost/port445_windows.go` | 新增，`svc/mgr` 接管 `LanmanServer` | Windows 的 445 是系统服务绑死的，不接管就 bind 不上 |
| `internal/smbhost/guest_windows.go` | 免密按引擎分流；`Backup` 加 `engine` 字段 | go 引擎不动任何系统策略；同时兼容老版本留下的 native 备份 |
| `internal/config/config.go` | 新增 `smb.engine` 与其校验 | 让选择显式、可回退 |
| `internal/app/app.go` | 启动时 `SetEngine` + `Recover`；免密路径分流 | 崩溃残留要收拾，免密不能误改整机策略 |
| `cmd/fsgw/smbcheck_windows.go` | `smb check` 按引擎分两套检查项 | go 引擎下 Guest/ForceGuest/LSA 全是无关项，照旧检查会误导 |
| `tools/smbserve` | 新增联调小工具 | 不需要管理员权限就能把服务端起在任意端口做协议调试 |

### 9.3 445 接管（`port445_windows.go`）

```
检查 445 是否空闲（试 bind）
  └─ 空闲 → 直接用
  └─ 被占 → 连服务管理器
       1) 第一次接管：记录 LanmanServer 的 StartType 与是否在运行 → <data_dir>\lanserver_backup.json
       2) StartType 改 手动（避免重启后又被抢走）
       3) 停服务，轮询等 445 释放（最多 20 秒）
       4) 仍被占 → 立刻还原并报错（绝不停在半接管状态）
退出/切换/崩溃后重启：按备份还原 StartType，原来在跑就重新拉起
```

用 `golang.org/x/sys/windows/svc/mgr` 而不是 `sc.exe`：一是不依赖外部命令的本地化输出，
二是能直接读到 `svc.Status` 做轮询，比解析文本可靠。

### 9.4 验证状态

- `GOOS=windows go build ./cmd/... ./internal/...` 通过；`GOOS=linux` 同样通过（同一份 `hosted_go.go`）。
- 库自带端到端测试在 Windows 上全绿（`go test github.com/sonroyaalmerol/go-smb-server/smb/...`），
  覆盖了 Windows 下的 vfs 建/写/读/改名/删除/列目录——这是移植里最容易踩的平台差异。
- 445 接管的真机验收需要管理员权限（`fsgw.exe on` 或 `以管理员身份启动.cmd`），
  非提权会话无法复现，验收步骤见 README「Windows 版：自研服务端接管 445」。
- 联调提示：Windows 的 SMB 重定向器**不支持** `\\host@port\share` 这种带端口写法
  （实测连接根本不会发到目标端口），所以非 445 端口的服务只能靠 Linux 侧 `smbclient -p` 或提权起 445 来验。

### 9.5 未做与风险

- 接管期间本机系统共享（`C$`/`IPC$`/自定义共享）不可用，这是 445 独占的必然结果，已写进 README。
- `engine: auto` 的回退判断只看"服务端能否起来"，不检查回退后客户端是否真的能连；
  回退时会 WARN 一句"Win11 免密将不可用"。
- 控制台/托盘里还没有"当前引擎"的展示位，需要看日志或 `fsgw smb check`。

## 10. 本机验收（Windows，无管理员权限）

### 10.1 为什么不能直接用资源管理器

Windows 的 SMB 重定向器只认 445，**不支持** `\\host@port\share`（实测连接根本不会发到目标端口）。
没提权就抢不到 445（被 `LanmanServer` 占着），于是"自研服务端到底对不对"在本机无法用系统客户端验证。

绕法：`tools/smbping` 用第三方纯 Go SMB2 客户端（`github.com/hirochachacha/go-smb2`，按微软文档逐条实现）
当外部考官，服务端用 `tools/smbserve` 起在任意端口，两边都是独立实现——服务端的协议偏差会被如实打出来。
该工具自成一个 Go module（`tools/smbping/go.mod`），不进主模块依赖。入口脚本 `tools/smbping.sh`。

验收覆盖：列目录+查属性、建→写→读→改名→删、大文件流式读写（SHA256 全量比对）、
N 个文件 / M 个子目录的批量复制与删除、多条会话并发读写。

### 10.2 它打出来的三个真缺陷

第一次跑就红了 2 项，顺手又挖出 1 项。都不是"环境问题"，全是代码问题。

| 现象 | 根因 | 修法 |
| --- | --- | --- |
| 改名报"拒绝访问"，文件纹丝不动 | Go 的 `syscall.Open` 只在**打开已存在文件**时才申请 `FILE_SHARE_DELETE`；`CREATE_NEW`/`CREATE_ALWAYS` 打开时没有。客户端"开着句柄改名"（SMB 里完全合法）就被 Windows 判成共享冲突，库再糊成 `STATUS_ACCESS_DENIED` | 仓库内 `smb/vfs/file_windows.go`：自己调 `CreateFile`，共享位固定给 `READ\|WRITE\|DELETE` |
| 每一个"新建文件夹"都报"文件已存在"，但目录其实建好了 | `LocalBackend.Open` 建完目录后仍拿 `getFlags(FILE_CREATE)` 的 `O_CREATE\|O_EXCL` 去打开它——刚建的目录当然已存在，直接 `EEXIST` | 同上文件所在包：`CreateDir` 分支把标志改成纯 `O_RDONLY`；真重复创建才报冲突 |
| 列目录/建目录报"拒绝访问" | 同上 `CreateFile` 少了 `FILE_FLAG_BACKUP_SEMANTICS`，该位是"能否打开目录"的开关 | 打开时固定带上（对普通文件无副作用） |
| 同机起第二个实例时，请求被**悄悄转给另一个进程** | 内层监听端口写死 `127.0.0.1:14450`：第二个实例 bind 失败，但"就绪探测"能连上第一个实例的端口，于是只读共享实际读写到别人的共享根 | `internal/smbgo/server.go`：每次启动现取空闲回环端口，并同时要求"内层没报错 + 端口能连"才算就绪，端口竞争时换端口重试 |

最后一条最危险：它不是"连不上"，而是**连上了、连错人了**。只读共享变成可写、
A 目录看到 B 目录的内容，日志里只有一条被 `INFO 已就绪` 掩盖的 `ERROR SMB 服务异常退出`。

### 10.3 修复后的本机结果（2026-11-05）

```
SMB 客户端验收 → 127.0.0.1:4450  共享 share  账号 admin
  [ OK ] 列目录+查询属性        0 项
  [ OK ] 新建+写入+回读         6421 字节，摘要一致
  [ OK ] 改名+删除             改名生效，删除后不可见
  [ OK ] 大文件写入+回读        128 MiB，写 129.4 MB/s，读 171.1 MB/s，摘要一致
  [ OK ] 多文件写入+回读        300 个文件 / 12 个子目录，写 2.257s，读+校验 412ms
  [ OK ] 多文件删除            300 个文件全部删除，用时 503ms
  [ OK ] 并发会话              6 条会话并行读写，全部一致
结论：全部通过。
```

另外两个变体单独验过：

- **免密通道**（`-user guest -pass ""`，服务端不带账号表）：日志出现
  `会话成功响应已标记为来宾会话（SessionFlags=IS_GUEST）`，写入/改名/删除/并发全通过。
- **只读共享**（`-readonly`）：列目录正常，`新建文件` 明确被拒（`permission denied`），
  不会出现"只读还能写"的假象。

回归：库自带 `go test .../smb/...` 在 Windows 全绿；`GOOS=linux` 的 build / vet 同样通过
（`file_unix.go` 里同名函数直接转 `os.OpenFile`，两平台共用同一处调用点）。

### 10.4 这个工具能不能用于局域网真机

能，但只对**非 445 端口**有用（例如联调机 `-addr 192.0.2.10:4450`）。
正式环境走 445 时，直接用 Windows 客户端 `net use`（见 README 一键修复 EXE）更贴近真实场景。

---

## 11. Linux / macOS 客户端接入（2026-11-10）

背景：110 上的 SMB 共享 Windows 10/11 一切正常，**Linux（`mount -t cifs`）和 macOS 连不上**。
要求是"接入时按客户端类型单独处理、不能砸掉 Windows"。结论：问题不在认证，而在
协议细节——三个地方各有各的坑，而且互相掩盖（修完一个才露出下一个）。

### 11.1 接入端识别（`internal/smbgo/client.go`）

代理层在客户端首包上做指纹，识别结果写进在线会话表（控制台「接入端」列）并决定
开哪些兼容补丁（`compat{fsProbe, validateNego}`）。

| 判据（按强度排序） | 判为 | 依据 |
| --- | --- | --- |
| 只声明 1 个方言，且首包就是 SMB2 协商 | `linux-cifs` | `mount.cifs vers=` 只翻成一条 dialect；Linux 内核对首发 SMB2，从不发 SMB1 探测 |
| 发过 SMB1 探测、之后**又补发**独立的 SMB2 协商，且带 MULTI_CHANNEL | `macos` | Windows 拿到探测包的协商响应后直接进 SESSION_SETUP，**从不补发**；mac 会补，实测 caps=0x7f |
| 首包是 SMB1 探测包 | `windows`（暂定） | Win10/11 仍先发一条只列方言的 SMB1 探测包；但 mac 也发，这一条只能算暂定，等后续帧修正 |
| 带 MULTI_CHANNEL / PERSISTENT_HANDLES 能力位 | `windows` | 必须在加密位之前判，否则会把 Win 误判成 Samba |
| 声明 3.1.1 且没有 ENCRYPTION 位 | `macos` | 老版本 macOS 的画像；Big Sur（11.7）实测**带** 0x40，所以这条不能单独用 |
| 带 ENCRYPTION 能力位 | `linux-samba` | smbclient 用户态默认要求加密 |

> 识别是**两阶段**的：首包先给一个暂定结论，收到真正的 SMB2 NEGOTIATE 后由
> `refineClient` 修正（结论变化会打一条「接入端识别已修正」日志，并同步到在线
> 会话表）。mac 与 Windows 的首包完全一样，只靠单帧指纹分不开，必须看行为序列——
> 详见第 12 章。

识别不准时可用配置兜底（IP 精确或前缀匹配，优先于指纹，且不会被二次识别覆盖）：

```yaml
smb:
  client_hints:
    - ip: 192.0.2.150
      kind: macos
```

### 11.2 真问题一：复合请求（这条才是 `mount error(9)` 的元凶）

内核打开共享根目录时发的是一条**复合报文**：

```
CREATE("") + QUERY_INFO(FileAllInformation) + CLOSE      （一条 TCP 帧，后两条带 RELATED 标志）
```

后两条的 FileId 填的是保留值 `0xFFFF…FF`，含义是"沿用前面那条 CREATE 打开的句柄"。
内层库没有复合语义，把每条当独立请求解析，拿保留 FileId 查句柄必然
`STATUS_INVALID_HANDLE` → 内核 `cifs_read_super: get root inode failed` → 挂载失败。
Windows 把这三步拆成三条独立请求发，所以只有 Linux / macOS 中招。

处理（`proxy.go` 的 `exchangeCompound`）：拆成独立请求逐条换手，把保留 FileId 换成
上一条 CREATE 响应里返回的真句柄，再把响应合回一条复合响应。要点：

- 拆分后的 QUERY_INFO 请求体正好 40 字节，内层解析要求 ≥41（`StructureSize=41` 的尾字节），
  要补一个填充字节（与常规路径的 `padQueryInfo` 同理）；
- **FileId 替换必须发生在"登记请求参数"之前**：目录枚举的游标键是 FileId+通配符，
  拿 `0xFF..FF` 去算会跟真句柄分成两个桶，同一个目录会被整份返回两次（客户端看到每条目重复）；
- 响应改写只能做一次。`pumpToClient` 与 `exchangeCompound` 共用 `patchResponse`，
  两边都调就会把目录分页游标推两次、条目被整段跳过。

### 11.3 真问题二：`FILE_ALL_INFORMATION` 太短

内层只写 Basic(40) + Standard(24) + 20 字节错位的"空字段"，共 **84 字节**；内核按
`sizeof(FILE_ALL_INFO)=101` 校验：

```
CIFS: VFS: buffer length 84 smaller than minimum size 101
CIFS: VFS: bogus file nlink value 0        ← 校验失败后 fattr 全零的连带症状
→ mount error(20): Not a directory
```

`fixFileAllInfo` 按 MS-FSCC 2.4.2 重建：Basic/Standard 前 64 字节原样搬（内层这段是对的），
Internal/Ea/Access/Position/Mode/Alignment 补零，`NumberOfLinks` 兜底为 1，尾部补到 104 字节。

### 11.4 真问题三：`FSCTL_VALIDATE_NEGOTIATE_INFO` 的输出长度被客户端钉死

内核与 smbclient 在这个 ioctl 上要求**恰好 24 字节**输出，多一点少一点都不行：

- 内核：`Invalid protocol negotiate response size: 26` → `protocol revalidation - security settings mismatch` → `cifs_mount failed w/return code = -5`
- smbclient：请求里 `MaxOutputResponse=24`，超出的输出直接判畸形（`NT_STATUS_INVALID_NETWORK_RESPONSE`）

另有两条容易踩的偏移细节：

- 协商响应里的 **ServerGuid 在 body[8:24]**（不是 28..44，那是 MaxTransact/MaxRead/MaxWrite/SystemTime 拼出来的垃圾）。取错会让 smbclient 把 TREE_CONNECT 判成 `ACCESS_DENIED`；内核不校验 GUID，所以这个 bug 只在 smbclient 上显形。
- Samba 客户端在**请求**里用的是扩展布局（Capabilities/Guid/SecurityMode/**DialectCount+Dialects[]**），但**响应**仍要 24 字节、方言放在偏移 22 —— 不要因为请求带了个 count 就把响应也改长。

### 11.5 另外两处只有 Linux/macOS 会问的

`FILE_FS_DEVICE_INFORMATION`(0x04) 与 `FILE_FS_SECTOR_SIZE_INFORMATION`(0x0b)：Windows 从不问，
内层一律回 `STATUS_INVALID_PARAMETER`，内核据此判"取不到设备信息"直接 abort。
`fixVolumeInfo` 按 `compat.fsProbe`（非 Windows 才开）补上。

### 11.6 真问题四：删目录（rmdir）失败（2026-11-10 下午补）

前面三条修完后 Linux 能挂、能读、能写、能删**文件**，但 `rmdir` 一律失败（返回 1，目录还在），
而且每个目录都正好卡 **10 秒**——这个"整数 10 秒"是超时值，直接指向我们自己的换手逻辑。

报文形状（内核删空目录）：

```
CREATE("d1", CreateOptions=FILE_DIRECTORY_FILE, DELETE 权限) + SET_INFO(FileDispositionInformation)
```

`SET_INFO` 的响应体只有 **2 字节**（SMB2 SET_INFO 响应固定 2 字节），整帧 4+64+2 = **70 字节**。
而 `claimWaiter` 开头有一道长度守卫：

```go
if len(frame) < nbHeaderLen+smb2HeaderLen+8 {   // 4+64+8 = 76
    return nil, false
}
```

70 < 76 → 这条响应被判成"不是我在等的响应"，走常规路径直接转发给客户端；
等着换手的 `exchangeCompound` 永远收不到，只能干等 `time.After(10*time.Second)` 超时，
于是 `SET_INFO` 之后的 `CLOSE` 也没发出去，内核拿不到完整响应 → `rmdir` 失败。

之前没暴露是因为复合请求里第二条通常是 `QUERY_INFO`（响应 92 字节）或 `CLOSE`（响应 60 字节），
都过得了 76 这道线；只有"删目录"这种 2 字节响应踩上。

修法：守卫只要够一个 SMB2 头（`nbHeaderLen+smb2HeaderLen`），判断字段都在头里，不需要 +8。
回归测试 `TestClaimWaiterAcceptsShortResponse` 用 70 字节的 SET_INFO 响应锁死这条。

**教训**：凡是"最小长度"前置判断，都要问一句"这条命令最短的合法响应有多长"。
响应体长度为 2 字节的（SET_INFO / IOCTL / TREE_DISCONNECT / LOGOFF）都会被这类守卫误伤。

### 11.7 诊断手法（按有效性排序）

1. **`FSGW_SMB_TRACE=1`**（`patchResponse` / `pumpTo*` 里的 `traceFrame`）：逐帧打印
   命令、MessageId、状态码、长度。常态日志只记被改写的帧，看不出"客户端在哪一步放弃"。
2. **内核侧开关**：`echo 1 > /proc/fs/cifs/traceSMB` 能拿到内核眼里的完整帧内容；
   `cifsFYI` 在 6.12 上设了不出东西，直接用 `traceSMB`。
3. **环回抓包 + 自写解析器**：`tcpdump -i lo -U -s 0 -w /tmp/x.pcap port 4455`，
   再 `python tools/smbdec.py /tmp/x.pcap`（加 `create` 只看 CREATE 的路径/FileId/上下文）
   逐字段核对。解析器还替我们踩了两个坑：上下文名实际是 **ASCII**（`QFid`/`MxAc`，规范写的是 Unicode）；
   `NameOffset`/`DataOffset` 内核按**相对上下文结构**算，不是相对 SMB2 头。
4. **`tools/smbserve`**：`go run ./tools/smbserve -root /tmp/x -addr :4455 -user admin -pass changeme`
   起一个指向临时目录的独立实例（走的是与生产完全相同的 `smbgo.Start`，所以代理层补丁也在），
   不碰 445 生产共享，可以反复重启、反复抓包。

### 11.8 验证状态（2026-11-10，110 生产实例）

| 客户端 | 结果 |
| --- | --- |
| Linux 内核 `mount -t cifs -o guest,vers=3.0` | ✅ 挂载、列目录、`df` 显示真实容量（1.8T / 已用 839G） |
| Linux 内核 `mount -t cifs -o username=admin,password=***` | ✅ 挂载、列目录、写（含新建文件/新建目录）、读回、删除 |
| Linux 常用操作矩阵（`cp -r` / `mv` / `rm -rf` / `truncate` / `touch` / 嵌套建删） | ✅ 全部 RC=0；`ln -s` 不支持（CIFS 标准行为，需 `mfsymlinks`） |
| `rmdir` 删空目录 | ✅ 修复 11.6 后通过（此前必失败且卡 10 秒） |
| `smbclient`（匿名 / 账号） | ✅ 列目录 + 块数容量 |
| Windows 10/11（`net use` / `dir` / 子目录） | ✅ 未回归；卷序列号 `5A17-C3E4` |
| macOS 11.7.10（`mount_smbfs`，账号 / 来宾） | ✅ 见第 12 章（真机实测，挂载 + 全部文件操作 + `df` 真实容量） |
| 控制台「接入端」列 | ✅ 同时显示 `Windows`、`macOS`、`Linux（内核 CIFS）`，mac 首包的暂定结论会被自动修正 |

### 11.9 踩过的坑（回归时先看这里）

- 生成型改动一律**别多给字节**：24 字节的 ioctl 输出、101 字节的 FILE_ALL_INFO 都是硬性下限/上限。
- 解析型改动一律**别多要字节**：判"是不是响应"只看 SMB2 头就够，多要 8 字节就会把 70 字节的
  SET_INFO 响应漏掉（见 11.6，症状是固定 10 秒卡顿 + rmdir 失败）。
- `patchResponse` 是唯一的响应改写点，**只能调一次**。
- 复合报文拆分时，凡是"按请求内容算出来的键"（FileId、游标键）都要在**替换保留值之后**再算。
- 测试共享目录被 `sudo rm -rf` 重建后会变成 root 属主，SMB 进程写不进去会回
  `STATUS_ACCESS_DENIED`——别误判成权限回归，`chown` 回来即可。

## 12. macOS 客户端接入（2026-11-10 真机实测）

真机：macOS 11.7.10（Big Sur，x86_64），Apple SMBFS 3.6.2，用 `mount_smbfs` 挂载。
第 11 章当时只能靠指纹推演，这次补上了实测，结论有两处被推翻。

### 12.1 现象：一句完全没有信息量的报错

```
$ mount -t smbfs '//admin:changeme@192.0.2.11/share' ~/prod
mount_smbfs: mount error: /Users/example-user/prod: No such file or directory
$ echo $?
64
```

挂载点明明是刚 `mkdir` 出来的空目录。换个路径（`/tmp`、`/Volumes`、家目录）、
换成 `sudo`、换端口，报错一字不差——**这个 "No such file or directory" 与本地
文件系统毫无关系**，它是 Apple 把"树连接失败"折成的一个 errno。

内核日志里才有真话：

```
nbssn_recvhdr: id 17 flags 0x62 Server closed their side of the connection.
nbssn_recv: nbssn_recvhdr error 32
```

### 12.2 第一步：把"本地问题"和"服务端问题"分开

`smbutil`（用户态 SMBClient）与 `mount_smbfs`（内核 `smbfs.kext`）走的是**两套
独立实现**。用 `smbutil view` 一试：

```
$ smbutil view -N //guest@192.0.2.11
Share          Type    Comments
share          Disk
IPC$           Pipe    Remote IPC
2 shares listed
```

用户态完全正常（网络、SPNEGO、NTLM、TREE_CONNECT 全通），说明断点在内核那条
链路上。再开 `FSGW_SMB_TRACE=1` 看服务端，一次就定位：

```
TREE_CONNECT →  path=\\192.0.2.11\SHARE
← TREE_CONNECT  status=0xc00000cc        ← STATUS_BAD_NETWORK_NAME
```

### 12.3 真问题一：mac 把共享名转成大写（`STATUS_BAD_NETWORK_NAME`）

**mac 发的是 `\\192.0.2.11\SHARE`，而共享名是 `share`。** 内层库按字面
比对，`SHARE ≠ share`，直接回 `0xC00000CC`。

Windows 与 Linux 都把用户输入原样发（一般就是小写），只有 Apple 的 SMBFS 会把
共享名统一规范化成大写再发——所以这个坑只对 mac 生效，而且表现成"认证都过了、
就是打不开共享"。

验证很直接，在 Linux 上用大写共享名挂同一个实例：

```
mount -t cifs //127.0.0.1/share ...   → RC=0
mount -t cifs //127.0.0.1/SHARE ...   → RC=32 (mount error)
```

**修法**（`proxy.go: fixTreePath`）：在 TREE_CONNECT 请求进内层之前，把 UNC 里
共享名那一段的字符改回真实大小写。

```go
// 取最后一个反斜杠之后的部分，与真实共享名 EqualFold 就比较
// 原地改写这段 UTF-16LE 字节，长度不变
tail[2*k] = st.share[k]
```

只改大小写、**长度不变**，所以 `NextCommand`、各结构体偏移、签名全都不用重算。
这条对 Windows/Linux 是空操作（它们本来就发对），所以不构成回归风险。

### 12.4 真问题二：mac 首包与 Windows 一模一样

第 11 章 11.1 里写过"macOS 从不发 SMB1 探测包"，**实测是错的**。抓包看 mac 的
第一帧：

```
SMB1 NEGOTIATE   dialects: "NT LM 0.12" / "SMB 2.002" / "SMB 2.???"
                 NativeOS: （没有）
```

与 Windows 10/11 的探测包**一字不差**，两边都不带 NativeOS 自报串。所以原来
"首包是 SMB1 探测包 ⇒ Windows" 这条判据，把 mac 稳稳判成了 Windows——日志里
就是 `client=windows label=Windows evidence="首包为 SMB1 探测包（Windows 特征）"`。

更麻烦的是能力位也对不上：mac 的 SMB2 NEGOTIATE 实测

| 客户端 | 方言 | caps | 首包 |
| --- | --- | --- | --- |
| macOS 11.7 | 2.0.2 / 2.1 / 3.0 / 3.0.2 / 3.1.1 | `0x7f` | SMB1 探测 → **补发** SMB2 协商 |
| Windows 10/11 | 同上五项 | `0xff`（重连）/ `0x4D` | SMB1 探测 → **直接** SESSION_SETUP |
| Linux 内核 CIFS | 仅 `3.0` 一项 | `0x77` | 直接 SMB2 协商，无探测 |

`0x7f` 含 `MULTI_CHANNEL(0x08)` 和 `ENCRYPTION(0x40)`——第 11 章"mac 从不声明
加密"、"靠多通道位判 Windows"两条在这里同时失效。

**真正能分开的是行为序列，不是单帧字段：**

> Windows 发完 SMB1 探测、拿到我们合成的 SMB2 协商响应后，**直接发 SESSION_SETUP**，
> 从不补发一条独立的 SMB2 NEGOTIATE 请求。mac 会补。

于是识别改成两阶段（`proxy.go: refineClient` + `client.go: sniffSMB2After`）：

1. 首包给暂定结论（mac 会暂定为 windows）；
2. 收到真正的 SMB2 NEGOTIATE 时，若 `sawSMB1Probe == true` 且 `caps & 0x08 != 0`
   —— 排除 Windows（它不会走到这一步），判为 macos，同时把兼容画像
   `comp` 一起换掉，并打一条「接入端识别已修正」日志。

日志实证：

```
SMB 接入端已识别  client=windows evidence="首包为 SMB1 探测包（Windows 特征）"
接入端识别已修正  from=windows to=macos dialects=2.0.2,2.1,3.0,3.0.2,3.1.1 caps=0x0000007f
              evidence="SMB1 探测后又补发 SMB2 协商，且带 MULTI_CHANNEL：排除 Windows，判为 macOS"
```

这个时机足够早：TREE_CONNECT 在认证之后才发生，兼容画像在这里改还来得及。
`client_hints` 人工指定的结论不会被二次识别覆盖。

### 12.5 验证（110 生产实例，445 端口）

| 项目 | 结果 |
| --- | --- |
| `mount_smbfs '//admin:***@192.0.2.11/share'` | ✅ RC=0 |
| `mount_smbfs -N '//guest@192.0.2.11/share'` | ✅ RC=0（来宾） |
| 写 / 读 / 建嵌套目录 / 写嵌套文件 / 复制 / 重命名 / `stat` | ✅ 全部 RC=0 |
| 删文件 / `rm -rf` 目录树 | ✅ RC=0 |
| `df -h` | ✅ 真实容量：1.8Ti / 已用 838Gi / 46% |
| 控制台「接入端」列 | ✅ 显示 `macOS`，与 `Windows`、`Linux（内核 CIFS）` 并存 |

部署后连续 25 分钟日志：`panic` 0、`level=ERROR` 0、换手超时 0。

### 12.6 怎么复现这套判断

`tools/smbdec.py` 新加了 `nego` 模式，直接把上面那张表打出来：

```
$ python tools/smbdec.py mac.pcap nego
==== 192.0.2.101:62530 -> 192.0.2.11:4455  (27 frames, SMB1 探测 1 条) ====
  SMB1  NEGOTIATE(探测)        len=69
  NEGOTIATE REQ mid=1  [REQ] secmode=0x0001 caps=0x0000007f dialects=['0x202','0x210','0x300','0x302','0x311']
      ctx 0x0001 PREAUTH_INTEGRITY hashes=['SHA-512'] saltlen=32
      ctx 0x0002 ENCRYPTION        ciphers=['AES-128-CCM']
      ctx 0x0003 COMPRESSION       algos=['NONE']
      ctx 0x0005 NETNAME           netname='192.0.2.11'
```

同一份抓包里跑 Windows 的包，会看到 `SMB1 探测 1 条` 但**没有任何 `NEGOTIATE REQ`**
——这就是"从不补发协商"的可视化证据。抓包命令：

```bash
sudo tcpdump -i any -s 0 -U -w /tmp/x.pcap 'port 445'
# 抓完记得 chmod 644，tcpdump 写出来的文件归 tcpdump 用户
```

### 12.7 mac 特有的操作坑（不是服务端的问题）

- **挂载点别用 `/tmp`**：Big Sur 上 `/tmp` 是 `/private/tmp` 的符号链接，
  挂载能成功（`mount` 里有记录），但 ssh 会话访问它会 `Operation not permitted`
  ——这是 macOS 的隐私保护拦了 sshd 访问网络卷，不是共享没挂上。挂 `~/xxx` 正常。
- **卸载要用 `diskutil unmount force`**：`umount` 常报 `Resource busy`（挂在里面
  的 shell 工作目录还没退出），`diskutil unmount force` 一句话解决。
- **`mount -t smbfs` 不认 `-N`**：`-N`（免口令）是 `mount_smbfs` 的选项，
  必须写 `/sbin/mount_smbfs -N '//guest@host/share' /mnt`；`mount -o guest` 也不认
  （报 `-o guest: option not supported`）。
- **Finder 的"连接服务器"走的是同一套内核实现**，本文的修法对它同样生效；但
  Finder 还会额外拉 IPC$ 做共享枚举，那条路径走 `srvsvc`，与挂载本身无关。

### 12.8 已知局限

mac 少数连接（挂载前的探测）**直接发单方言 SMB2 协商**，不带 SMB1 探测包，形态
与 Linux 内核 CIFS 完全一致。这类连接会被显示成 `Linux（内核 CIFS）`。
协议层没有可区分的信息，属显示层面的不精确；对应会话的兼容画像两者相同
（都开 `fsProbe`），不影响功能。要绝对准确就用 `client_hints` 指定。

---

## 13. macOS 影子文件（`.DS_Store` / `._xxx`）的处理（2026-11-10）

### 13.1 现象与定性

mac 访问过的目录会多出 `.DS_Store`（Finder 的窗口布局）、`._foo.txt`（AppleDouble：
资源分叉 + xattr）、`.Trashes/`、`.Spotlight-V100/`、`.fseventsd/`、`.apdisk` 等。
这些**不是网关写的**，是 macOS 对"没有 HFS+ 属性空间的卷"的标准降级方案。

痛点只落在别的接入端：Windows 资源管理器里满屏 `._xxx`，`dir` 数量凭空翻倍，
备份与索引跟着变脏。mac 自己在 Finder 里本来就不显示点开头的文件。

于是处理目标不是"删干净"，而是：**别让 Windows / Linux 看见，同时别破坏 mac 的使用体验**。

### 13.2 落在哪一层：`fixQueryDirectory`

目录枚举在代理层已经被整体接管（`fixQueryDirectory`：把内层"每次从头全量枚举"的
结果按客户端要的信息类重排、再按句柄游标切页），过滤插在这里只改一处，三个平台全受益。

关键约束：**过滤必须发生在 `cursorBegin` 之前**。游标记的是"已经发给客户端的条目数"，
只有对同一份过滤后的列表计数，切页才不会错位、`STATUS_NO_MORE_FILES` 才不会早到或迟到一条。

```
parseDirEntries → filterAppleMeta → cursorBegin → 切页 → advanceCursor(len(page))
```

`filterAppleMeta` 原地压缩底层数组（`entries[:0]`），大目录一次几千条也不会多复制一份名字。

### 13.3 为什么默认"只对非 mac 隐藏"

一开始的实现是"所有接入端都藏"，实测后改掉：**mac 找不到 `.DS_Store` 不会认为"本来就没有"，
而是每次进目录都新建一个再写一遍**。后果是浏览一次写一次（小文件写入放大），
而 Finder 的窗口布局反而存不住。

最终三态：

| 值 | 行为 | 用在哪 |
| --- | --- | --- |
| `hide`（留空等同） | 只对非 macOS 隐藏；mac 照旧 | 默认 |
| `all` | 全藏，含 mac | mac 侧已关 `DSDontWriteNetworkStores` 时可选 |
| `off` | 不过滤 | 排障：确认过滤有没有误伤 |

判定用的是已有的两阶段识别结果 `st.client.Kind`（第 12 章），`NEGOTIATE` 阶段就已定稿，
早于任何 `TREE_CONNECT` / `QUERY_DIRECTORY`，不存在"过滤时还不知道是谁"的窗口期。

### 13.4 存量清理：`fsgw clean-meta`

列目录过滤不删文件，磁盘上照旧躺着。清存量是独立命令，只认白名单、只删共享根之内、
不跟随符号链接，**默认只列清单，`-force` 才动手**：

```bash
sudo fsgw clean-meta -config /etc/fsgw/config.yaml -v        # 看清单 + 逐条路径
sudo fsgw clean-meta -config /etc/fsgw/config.yaml -force    # 真删
```

命中白名单的目录（`.Trashes` 之类）先算子树体积再整棵 `RemoveAll`，返回 `fs.SkipDir`，
不会把里面的"已删文件副本"当成普通条目再走一遍。

### 13.5 验证（110 生产实例）

| 用例 | 结果 |
| --- | --- |
| 磁盘 669 条（500 正常 + 167 `._` + `.DS_Store`） | Windows `Get-ChildItem -Force`：**500 条，元数据 0 条** |
| 同一目录，`smbclient -N ls` | 500 条，去重后仍 500（分页无重复无遗漏） |
| 根目录（`/srv/share`，原 239 个影子文件） | 过滤后 Windows 看不到；`clean-meta -force` 删 239 个 / 500 KB，复查 0 |
| mac 挂载（`mount_smbfs //admin@...`） | RC=0；根目录仍能列出 `.DS_Store`，`_mt_test` 里 500 正常 + 166 `._` 全部可见 |
| mac 读写 | 写/读/建目录/`rm -rf` 全 RC=0；`df` 1.8Ti / 838Gi / 46% |
| 生产日志 | panic 0、ERROR 0 |

> 过滤是"看得见与否"，不是隐藏属性：mac 按名字直接 `OPEN` 这些文件，不依赖目录枚举，
> 所以 mac 侧的图标、标签、窗口布局完全不受影响。

### 13.6 这个问题的边界

`DSDontWriteNetworkStores`（Apple 官方开关）只关 `.DS_Store`，关不掉 AppleDouble。
`._xxx` 是否产生取决于服务端是否支持 NTFS 扩展属性 / named stream 写入——内层库没有这条路径，
mac 就退化成 `._` 文件。要做到"一个都不产生"得补 SMB2 `FileFullEaInformation`(0x0F) 与
xattr 映射，成本与收益不成比例，当前策略（看不见 + 定期清）已经闭环。

### 13.7 踩坑

- **过滤别放在游标之后**：游标与页边界立刻错位，表现为"某些文件永远看不到"或分页提前结束。
- **`.Trashes` 里是完整路径的普通文件名**（`.Trashes/501/xxx.pdf`），判断要按"任一段命中"，
  只看叶子会把废纸篓里的文件当成普通文件放出去。`IsAppleMetaName` 两种形态都认。
- **别把 `._` 前缀写成"以 `.` 开头"**：`.gitignore`、`.env` 是正常文件，误伤会把用户数据藏掉。

---

## 14. 只支持 SMB1 的老设备：按客户端类型分流（2026-11-10）

### 14.1 现象：能发现，点不进去

小米电视连 `\\192.0.2.11\share` 一直转圈，服务端日志里只有一条

```
SMB 接入端已识别 remote=192.0.2.20:41170 client=windows dialects="" caps="0x00000000"
  evidence="首包为 SMB1 探测包（Windows 特征）"
```

之后再无任何记录——认证没开始，TREE_CONNECT 也没有。

### 14.2 抓包定性：它只认 SMB1

`tcpdump -i any host <电视IP> and port 445` 之后 `tools/smbdec.py`，整条连接只有两帧：

| 方向 | 字节 | 内容 |
| --- | --- | --- |
| 电视 → 445 | `0000002f ff 53 4d 42 72 …` | SMB1 `SMB_COM_NEGOTIATE`，方言表**只有** `NT LM 0.12` |
| 445 → 电视 | `0000009e fe 53 4d 42 …` | SMB2 `NEGOTIATE` 响应，dialect=0x0302，status=0 |

电视收到 SMB2 响应后再不发一个字节。

**关键区别**：Windows 也发 SMB1 探测包，但它的方言表是
`NT LM 0.12 / SMB 2.002 / SMB 2.???`——所以"收到 SMB2 响应就继续走 SMB2"成立。
只列 `NT LM 0.12` 的客户端是**纯 SMB1**，拿到 SMB2 协商结果无法解析，只能放弃。

原实现把所有 SMB1 首包无条件改写成 SMB2 协商（这是为 Windows 加的，见第 1 章），
遇到纯 SMB1 客户端就表现为"日志说识别成功、业务上一步都走不动"。

### 14.3 判据：方言表里有没有 SMB 2

```go
dial := smb1Dialects(rawFirst)   // 解 SMB_COM_NEGOTIATE 的 ByteCount 区
if smb1Only(dial) { … }          // 一个 "SMB 2" 前缀都没有 = 纯 SMB1
```

解析失败（非 NEGOTIATE、截断、WordCount≠0）一律返回 nil，`smb1Only(nil) == false`，
保持原来的"当 Windows 改写"行为——**宁可漏判，不可误伤 Windows**。

### 14.4 第一版：按客户端类型分流到回环 samba

先在回环上起一份只讲 SMB1 的 samba（`deploy/linux/smb1.conf`）：`smb ports = 4450`、
`interfaces = 127.0.0.1`、`server min/max protocol = NT1`、guest 放行、`read only = yes`，
运行目录（pid/lock/state/cache/private）全部独立，不碰 `/var/lib/samba`。

网关侧 `proxy.go: relayToSMB1` 把已经读出来的首帧先写给后端，之后两个方向裸 `io.Copy`，
不解析、不改写，也不设空闲超时（电视播片时几十分钟没有控制命令，设了会把正在播的流掐断）。
配置项 `smb.smb1_backend: 127.0.0.1:4450`。

这一版在 110 上跑通了，但**只解决了 Linux**：Windows 没有 samba，
老小米对着 Windows 版（98.88）依然看不到任何东西。

### 14.5 第二版（现行）：进程内置 SMB1 通道，两平台同一份代码

结论先行：**自己写一条最小 SMB1 服务端**（`internal/smbgo/smb1srv.go`，约 1400 行），
`smb1_backend` 留空即启用。Linux / Windows 共用同一份代码，不需要装 samba、
也不需要打开 Windows 的 SMB1 功能。

分流点没变，还是在 `proxy.go` 认出纯 SMB1 客户端之后：

```go
if smb1Only(dial) {
    if s.smb1 != "" {  relayToSMB1(c, first, s.smb1) }   // 配了外部后端就转交
    serveSMB1(c, first, s.root, s.share, !s.readOnly, log) // 否则进程内自己服务
}
```

实现范围（够电视/老投影用，不求完整）：NEGOTIATE / SESSION_SETUP_ANDX /
TREE_CONNECT_ANDX / TREE_DISCONNECT / LOGOFF / ECHO / NT_CREATE_ANDX / READ_ANDX /
WRITE_ANDX / CLOSE / CHECK_DIRECTORY / QUERY_INFORMATION / QUERY_INFORMATION_DISK /
TRANSACTION / TRANSACTION2（FIND_FIRST2、FIND_NEXT2、QUERY_PATH_INFO、QUERY_FILE_INFO、
QUERY_FS_INFO）。安全模型与之前的 samba 兜底一致：匿名可读，边界靠共享开关。
文件写入一律 `ACCESS_DENIED`——老设备（电视/投影/播放器）只有看片场景，
写入走 SMB2/3 那条路。

列共享两条路都通：`\PIPE\LANMAN` 上的 MS-RAP `NetShareEnum`，以及 IPC$ 上
CREATE `srvsvc` 管道后在里面跑 DCE/RPC（直接复用 SMB2 侧已有的 `handleSrvsvcRPC`，
它是协议无关的）。

### 14.6 踩过的坑（每一条都用真实 smbclient 复现过）

| 现象 | 根因 | 修法 |
| --- | --- | --- |
| `Server requested PLAINTEXT password` | NEGOTIATE 的 SecurityMode 回了 `0x01` | 改 `0x03`（USER_SECURITY\|ENCRYPT_PASSWORDS），与 samba 实测值一致 |
| `session setup failed: NT_STATUS_INVALID_NETWORK_RESPONSE` | SESSION_SETUP_ANDX 用 wc=4 + 空 SecurityBlob（扩展安全形状）却没声明该能力 | 改 wc=3 + 三段原生字符串（`Windows 6.1` / `FSGW` / `WORKGROUP`） |
| `unable to parse name from info level 260` | FIND 条目按文档写 0x0104 = 64 字节前缀 | 按 samba 实测：0x0104 → 94（带 24 字节短名区）、0x0105 → 76、0x0106 → 102 |
| 小米电视进去后目录显示成 **5 个同名 `share`**（日期还都是当天） | 电视发的 `InformationLevel = 0x0101`，被按 QUERY 那套理解成「老式 8.3 固定 26 字节」；实际 FIND_FIRST2 的 0x0101 是 `SMB_FIND_FILE_DIRECTORY_INFO`，**64 字节前缀**。结构对不上，客户端按 64 字节步进就滑到了别处，把共享名当成了条目名 | FIND 与 QUERY 是**两套**信息级别编号，不能共用一个常量；0x0101 单独按 64 字节编码 |
| `NT_STATUS_INVALID_NETWORK_RESPONSE listing` | TRANS2 响应没写参数区，`DataOffset` 也没 4 字节对齐 | 统一走 `replyTrans`：参数区落 56、数据区落 68 |
| `cd \sub\` 报 `OBJECT_NAME_NOT_FOUND` | NT_CREATE 字节区开头多 1 个对齐 pad，UTF-16 名字整体错位成 `尀猀甀戀` | `nameAfterAlign` 先剥 pad 再解码 |
| 下载下来的文件是 0 字节 | `FILE_ALL_INFO`(0x0107) 把 EndOfFile 写到 40（AllocationSize 的位置） | 改成 68 字节结构，EOF@48；客户端才肯发 READ |
| `ls sub` 列出的是根目录 | FIND_FIRST2 的搜索路径在 Trans2 **参数区尾部**（`params[12:]`），原先读数据区永远是空串 | 改读参数区，数据区仅作回退 |
| `rpc_pipe_bind for pipe srvsvc failed ... CONNECTION_DISCONNECTED` | ① 管道名带结尾 NUL（`"srvsvc\x00"`）匹配不上处理器；② TRANSACTION 的 Name 从 28 字节处找，把第一个 SetupWord 当成了名字（得到 `"&"`）；③ WRITE_ANDX 的 DataLength/DataOffset 少算 2 字节（18/20 → 应为 20/22） | `pipeKey` 统一规范化；SetupWords 在 14 个字之后、Name 在其后且在 ByteCount 之后的字节区里；修正 WRITE 偏移 |
| 列共享回 `NT_STATUS_NOT_SUPPORTED` | 管道事务靠 `SetupWords = {TRANS_NMPIPE(0x0026), FID}` 识别，原先按 Name 里含不含 `SRVSVC` 分流 | 先看 setup word，再看 Name |
| RAP 应答越界 | 20 字节缓冲里写到偏移 26 | 按 MS-RAP ShareInfo1 重写：`EntryCount(2)` + 每项 20 字节 `{NetName[13], Type@13, pad@15, RemarkOffset@16=-1}` |

### 14.7 验证

单测（`internal/smbgo/smb1srv_test.go`）：Trans2 响应偏移、各信息级别的条目前缀长度、
FILE_ALL_INFO 的 EOF 偏移、`nameAfterAlign`、`pipeKey`、TRANSACTION 的 SetupWords 分流、
RAP 名字解析。每一条都对应上表里的一个坑。

端到端用 **samba 自己的 smbclient 当真实 SMB1 客户端**（`-m NT1` 且关掉 SPNEGO/NTLMv2）：

| 用例 | Linux 110（内置通道，445） | Windows 88（内置通道，1445） |
| --- | --- | --- |
| `smbclient -L` 列共享 | `share` / `IPC$` 正常 | 同左 |
| 列根目录（含中文名） | 正常，`.DS_Store` 被隐藏 | 同左 |
| 进中文子目录 `数字人输出` | 正常 | 正常 |
| 下载中英文名文件 | 内容一致 | 内容一致 |
| 只读共享建目录 | `ACCESS_DENIED` | 同左 |

真机验证（小米电视 4A，`MiTV4_ANSM0`，系统媒体浏览器 `com.xiaomi.mitv.mediaexplorer`，
只发 `NT LM 0.12`）。用 ADB 遥控操作 + 屏幕截图逐屏核对：

| 用例 | 结果 |
| --- | --- |
| 设备列表出现 `192.0.2.11` | 正常 |
| 进主机看到共享 `share` | 正常 |
| 进 `share` 列根目录 | 19 个业务目录，中文名与修改日期均正确 |
| 滚动到底部 | `融资`/`数字人输出`/`颜诗翼`/`template` 等全部可见，无重复、无错位 |
| 进 `融资` 子目录 | 文件名、大小、日期正确（`评价.ogg` 6.3MB、`青少年脊柱健康管理平台.pdf` 0.4MB 等） |
| 进 `2020-05-22-23-img` | 2 个镜像文件，大小正确（`sdb4.ntfs-ptcl-img.gz.au` 3.9GB） |

> 修 0x0101 之前，同一个位置显示的是 **5 个一模一样的 `share`**。
> 抓包看得很清楚：电视连发 5 次 `FIND_FIRST2`（`InformationLevel=0x0101`），
> 第一条响应 653 字节被它按 64 字节步进解析，走位之后把共享名当成了条目名，
> 于是每解析出一条就是 `share`；后面的请求因为客户端状态机已乱而全部被丢弃。
> 改成正确的 64 字节 `DIRECTORY_INFO` 后，请求与响应恢复一一对应。

> `smbclient -L` 最后那行 `Unable to connect with SMB1 -- no workgroup available` 是
> smbclient 自己回落 445 端口去找"主浏览器"的结果（测试时服务在 1445），与内置通道无关。

### 14.8 边界

- 内置通道是**最小实现**：不做签名、DFS、EA、压缩、Unix 扩展，也不支持 SMB1 的
  NT_TRANSACT。清单见 `smb1srv.go` 顶部注释。
- 内置通道**只读**：文件写入一律 `ACCESS_DENIED`（WRITE_ANDX 只对命名管道放行）。
  老设备的看片场景够用；要写入请用 SMB2/3（Windows/mac/手机都走那条路）。
- Windows 上仍需要让出自研服务端绑 445（会临时停 `LanmanServer`），这是自研引擎的
  既有行为，与 SMB1 无关。若显式配置 `smb.engine: native`，则走系统 SMB，
  老设备是否可用取决于系统是否装了 SMB1 服务端——**想稳就留 `auto`**。
- 想改用外部 samba（比如要它那套多用户/日志），把 `smb.smb1_backend` 填成
  `127.0.0.1:4450` 并照 `deploy/linux/smb1.conf` 起服务即可，代码路径不变。
