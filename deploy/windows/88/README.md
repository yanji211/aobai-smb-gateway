# 88 部署实况（Windows 11 · 熬拜共享家 fsgw）

本目录记录 **192.0.2.10** 这台 Windows 机器上实际运行的部署，用于出问题时对照 / 重装复原。
代码与 110 同源（本仓库 `cmd/`、`internal/`），此处只放 **Windows/88 独有的运行事实与脚本**。

## 1. 主机

| 项 | 值 |
|---|---|
| 计算机名 | WIN-FSGW（示例） |
| 系统 | Microsoft Windows 11 专业版，10.0.26200 |
| 地址 | **192.0.2.10/24（WLAN）**；另有 192.0.2.12（以太网） |
| CPU / 内存 | i5-12490F（12 逻辑核）/ 31.8 GB |
| 共享根 | `D:\share` → SMB 共享名 `share` |
| 索引规模 | 文件 471662 · 目录 85602 · 版本 180 · 路径历史 557300 |

> 局域网内其他机器（含小米电视）用 `\\192.0.2.10\share` 访问的是 **WLAN 那张网卡**。

## 2. 二进制

| 项 | 值 |
|---|---|
| 路径 | `D:\fsgw\fsgw.exe` |
| 大小 | 19713536 字节 |
| md5 | `<your-windows-build-md5>` |
| 版本 | `fsgw 0.1.0` |
| 构建 | 本仓库 `./cmd/fsgw` 交叉编译：`GOOS=windows GOARCH=amd64 go build -o fsgw.exe ./cmd/fsgw`（2026-11-14 15:44，含内置 SMB1 服务端修复） |
| 备份 | 旧版留在 `D:\fsgw\fsgw.exe.bak.20261114` |

> 二进制不入库（19MB / 每次构建都变）。核验现场版本用 `md5sum fsgw.exe` 对比上表。

## 3. 服务与端口

托管方式：**Windows 计划任务**（不是服务、不是终端里的进程）。

| 项 | 值 |
|---|---|
| 任务名 | `fsgw-share` |
| 动作 | `D:\fsgw\fsgw.exe run -notray` |
| 工作目录 | `D:\fsgw` |
| 触发器 | AtStartup |
| 主体 | `SYSTEM` / ServiceAccount / RunLevel Highest |
| 失败处理 | 自动重启 3 次，间隔 1 分钟；不随电池/空闲停止；执行时限无限制 |
| 实测 | 进程 PID 1880，SessionId **0**，445 归它 |

| 端口 | 用途 | LAN 状态下的实测 |
|---|---|---|
| 445 | SMB（进程内 SMB2/3 + 内置 SMB1 通道） | 就绪 `\\本机\share` |
| 8200 | DLNA | 就绪 `192.0.2.10:8200` |
| 8443 | WebDAV（外网面） | **停止**（`bind 127.0.0.1:8443`，属 WAN 面，LAN 态不监听） |
| 8444 | 控制台（token 鉴权 + Host/Origin 校验） | 就绪 `127.0.0.1:8444` |
| 8445 | sync（fsgw-sync 推目录） | 就绪 `0.0.0.0:8445` |

## 4. 路径

- `D:\fsgw\`：`fsgw.exe`、`config.yaml`（即仓库根同名文件）、`smb_clients.yaml`、`*.cmd` / `*.ps1` 运维脚本
- `D:\fsgw\data\`：`fsgw.db`（SQLite 索引）、`sync.db`、`control.token`、`state.json`、`dlna_udn.txt`、`logs\`
- 日志：`D:\fsgw\data\logs\fsgw.log`（JSON，`level: info`）+ `audit.log`
- 共享根：`D:\share`

> 启动时会先做「索引对齐」（本机 47 万文件，约 1–3 分钟），完成前**不监听 445**。
> 排查「445 连不上」先看这条，别急着判定服务异常。

## 5. 445 归属：本机改动（重要）

Windows 上 445 默认被内核驱动 `srvnet` 占着，且系统 SMB 默认 `EnableSMB1Protocol=False`，
小米电视（纯 SMB1）既连不上也抢不过。本机采取的做法：

```powershell
Set-Service -Name LanmanServer -StartupType Disabled
Stop-Service -Name LanmanServer -Force
# 然后重启一次（srvnet 只在开机加载，停服务不会释放 445）
```

结果：`LanmanServer` = **Stopped / Disabled**，开机起 445 即为空，fsgw 直接接管。

- 副作用：本机 Windows 自带共享全部失效；`Get-SmbServerConfiguration` 也不再可用（服务未运行时报 Win32 111，属正常）；
- 一键改造脚本：仓库根 `disable-windows-smb.cmd`；
- 回滚脚本：`restore-smb.cmd`（本目录）—— 停 fsgw → `sc config LanmanServer start= auto` → 启动服务。
  注意回滚后系统 SMB 只讲 SMB2/3，老电视**仍**看不到这台机器。

## 6. config.yaml 关键项（Windows 实际值）

| 配置项 | 值 | 说明 |
|---|---|---|
| `data_dir` | `D:\fsgw\data` | 索引/令牌/日志 |
| `shares[0].root` / `name` | `D:\share` / `share` | 共享根与共享名 |
| `shares[0].writable` | `true` | 可写 |
| `smb.engine` | `auto` | 自研服务端优先，失败回退系统共享 |
| `smb.auth` | `guest` | 免密（同时保留 `admin` 账号的 `nt_hash` 供 Win11 24H2+ 客户端签名登录） |
| `smb.account_name` / `nt_hash` | `admin` / `<占位哈希>` | 只存 NT 哈希，明文不入库 |
| `smb.guest_writable` | `true` | 免密也允许写 |
| `smb.smb1_backend` | `""` | **留空 = 用进程内置 SMB1 通道**（电视走的就是这条） |
| `dlna.friendly_name` | `88share` | 与 110 的「家庭共享」区分 |
| `webdav.bind` | `127.0.0.1:8443` | 外网面 |
| `ui.bind` | `127.0.0.1:8444` | 控制台只绑回环 |
| `switch.startup_state` | **`LAN`** | 2026-11-14 从 `OFF` 改过来；`OFF` 时只开 8444，445/8200/8445 全不开 |
| `log.level` | `info` | 排障时才临时改 `debug`（重启会重建索引，1–3 分钟） |

## 7. 踩坑清单（都是实际撞过的）

1. **电视「进去看不到东西」不是服务端问题。**
   fsgw 每次重启都会让电视内核 cifs 那条会话失效，但电视（vold）**继续复用旧挂载点**
   `/mnt/smb/192.0.2.10@@share`，readdir 拿到 0 条 → 媒体浏览器显示「未发现可支持的视频、音乐、图片文件」。
   logcat 证据：`SMB_DAE do_mount rc=0` 之后 `TVME-DiskDevice: scan dir=... count=0`。
   **重启电视即恢复**（电视不会自己感知服务端重启）。同一时刻用 110 上的 NT1 客户端列目录、取文件、比 md5 全对。
2. **终端里起的进程活不下来。** `run -notray` 跟会话共生死；`run -detach` 实测 3 秒就被回收。
   必须用计划任务（SYSTEM，session 0）。
3. **`switch.startup_state: OFF`** 会让「服务看着起了、电视连不上」——只有 8444 在听。
   改配置后可直接 `fsgw.exe on -state LAN`，但别忘了把配置文件也改掉（重启以文件为准）。
4. **`fsgw on -state LAN` 后 `status` 可能显示「状态 OFF (期望 LAN)」**，再执行一次 `on` 即可；
   以「监听 SMB 就绪」为准，不要以为没起来。
5. **8444 可能落在 Hyper-V 保留端口段**，导致控制台 bind 失败；遇到就换端口或清保留段（历史记录见 `data\port445_blocked.json`，该文件已一并删除）。
6. **停 `LanmanServer` 不释放 445**，必须重启；重启前先确认 `StartType=Disabled`，否则开机又被 srvnet 抢回。
7. 日志里有非 UTF-8 片段，`grep` 会当二进制处理，要用 `grep -a`。

## 8. 复原步骤（重装一台同样的 88）

```powershell
# 1. 构建（仓库根）
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -o fsgw.exe ./cmd/fsgw

# 2. 放到位：D:\fsgw\{fsgw.exe, config.yaml, smb_clients.yaml}

# 3. 让出 445（需管理员）：停用系统 SMB 服务并重启一次
Set-Service -Name LanmanServer -StartupType Disabled
Stop-Service -Name LanmanServer -Force
Restart-Computer -Force

# 4. 注册开机自启任务（本目录脚本，管理员 PowerShell）
.\register-task.ps1

# 5. 核对：445 归 fsgw，共享就绪
D:\fsgw\fsgw.exe status
```

口令不在版本库内：`webdav.password_hash` / `smb.nt_hash` 只有哈希，改口令用 `fsgw passwd` 或控制台。

## 9. 验证记录（2026-11-14）

- **110 侧 NT1 客户端**（`smbclient -m NT1`）：列共享 OK、列目录 OK、`get` 两个文件 md5 与本机完全一致
  （`1024.html` = `<file-md5>`、`<file>.png` = `<file-md5>`）。
- **电视侧**（小米电视 4，ADB 直连实测）：网络共享页列出 `192.0.2.10` → 进 `share` → 文件列表正常
  （PDF / jpg / mp4，中文名正常）→ 图片全屏显示正常 → mp4 进播放器并播到结尾
  （logcat `position 1533/1567`），即读整段数据的路径也通。
- 电视播放器早期症状：`getDuration=0`、黑屏、`TRANS2` 返回 `0xC00000BB`。根因是内置 SMB1 服务端的两处偏移错误
  （`NT_CREATE_ANDX` 响应 FID 应在偏移 5、`QUERY_PATH_INFO` 文件名在 Parameter 区且头 6 字节），
  已修在 `internal/smbgo/smb1srv.go`，本次二进制即修复版。
