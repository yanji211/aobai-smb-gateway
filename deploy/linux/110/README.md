# 110 部署实况（Debian 13 · 熬拜共享家 fsgw）

本目录记录 **192.0.2.11** 这台机器上实际运行的 Linux 部署，用于出问题时对照 / 重装复原。
代码与 Windows 版同源（本仓库 `cmd/`、`internal/`），此处只放 **110 独有的运行配置与指纹**；
`fsgw.service`、`fsgw-smb1.service`、`smb1.conf` 与上级 `deploy/linux/` 模板逐字节一致，故不重复存放。

## 1. 主机

| 项 | 值 |
|---|---|
| 主机名 | linux-fsgw（示例） |
| 系统 | Debian GNU/Linux 13 (trixie)，kernel 6.12.115+deb13.1-amd64 |
| 地址 | 192.0.2.11/24（wlp2s0） |
| 共享根 | `/srv/share`（1.8T，已用 745G）→ SMB 共享名 `share` |

## 2. 二进制

| 项 | 值 |
|---|---|
| 路径 | `/usr/local/bin/fsgw` |
| 大小 | 18744095 字节 |
| md5 | `<your-linux-build-md5>` |
| 版本 | `fsgw 0.1.0` |
| 构建 | 本仓库 `./cmd/fsgw` 交叉编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o fsgw ./cmd/fsgw`（2026-11-14 构建，含内置 SMB1 服务端修复） |

> 二进制不入库（18MB / 每次构建都变）。核验现场版本用 `md5sum /usr/local/bin/fsgw` 对比上表。
>
> 二进制不入库，上表 md5 只是示例占位。不同 Go 版本/构建参数会得到不同指纹，
> 用上面那条命令从本仓库源码即可重建同版本服务，用 `md5sum` 核对本机产物。

## 3. 服务与端口

- `fsgw.service`：**active / enabled**
  `ExecStart=/usr/local/bin/fsgw run -config /etc/fsgw/config.yaml -notray`，`WorkingDirectory=/var/lib/fsgw`，`KillSignal=SIGTERM`，`TimeoutStopSec=20`
- `fsgw-smb1.service`：**inactive / disabled** —— 纯 SMB1 客户端改走进程内置通道 `internal/smbgo/smb1srv.go`，已不再需要回环上的 samba 后端

| 端口 | 用途 |
|---|---|
| 445 | SMB（进程内纯 Go SMB2/3 + 内置 SMB1 通道） |
| 8200 | DLNA |
| 8443 | WebDAV |
| 8444 | 控制台（token 鉴权 + Host/Origin 校验） |
| 8445 | sync（fsgw-sync 推目录） |

## 4. 路径

- `/etc/fsgw/`：`config.yaml`（0600 root）、`smb1.conf`、`smb_clients.yaml`（0600）
- `/var/lib/fsgw/`：`fsgw.db`（SQLite 索引，约 1.9G）、`fsgw.db-wal`、`sync.db`、`control.token`、`state.json`、`dlna_udn.txt`、`smb1/`
- 日志：`/var/lib/fsgw/logs/fsgw.log`（JSON，`level: info`）+ `audit.log`；**不进 journald**

> 启动时会先做「索引对齐」，完成前**不监听 445**，通常 1–3 分钟。排查「445 连不上」先看这条，不要急着判定服务异常。

## 5. 本目录文件

| 文件 | 说明 |
|---|---|
| `smb_clients.yaml` | 控制台维护的客户端 NT 哈希白名单（`note` 里的明文口令已剔除） |

110 的运行配置已**上提**为上级的 `deploy/linux/config.yaml`（内容即 110 运行值，仅删掉注释里的明文口令），
避免同一份配置在两处各存一份、日后分叉。保守模板在 `deploy/linux/config.template.yaml`。

未收录：二进制、`fsgw.db` / `sync.db` 运行时数据库、`control.token`。

## 6. 与保守模板的差异（`config.template.yaml` → `config.yaml`）

| 配置项 | 模板 | 110 实际 |
|---|---|---|
| `shares[0].writable` | false（只读） | **true**（可写） |
| `smb.account_name` | fsgw | **admin**（并配置 `nt_hash`） |
| `smb.guest_writable` | false | **true** |
| `smb.smb1_backend` | `""` | `""`（模板注释仍是旧语义「留空=不支持 SMB1」，当前代码语义是「留空=用内置 SMB1 通道」） |
| `smb.apple_meta` | `hide`（显式写出） | 未写（默认即 hide，行为一致） |
| `dlna.friendly_name` | 熬拜共享家 | 家庭共享 |
| `webdav.users` / `ui.allow_remote` / `sync.enabled` | 模板为保守默认 | 均已实际启用 |

## 7. 复原步骤（重装一台同样的 110）

```bash
# 1. 放二进制（按本仓库源码交叉编译；110 当前版本 md5 见第 2 节）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o fsgw ./cmd/fsgw

# 2. 装服务骨架 + 二进制 + 配置（install.sh 会装同目录的 fsgw 与 config.yaml）
cp fsgw deploy/linux/fsgw
sudo bash deploy/linux/install.sh

# 3. 客户白名单单独放（install.sh 不管这个文件）
sudo cp deploy/linux/110/smb_clients.yaml /etc/fsgw/smb_clients.yaml
sudo chmod 600 /etc/fsgw/smb_clients.yaml

# 4. 起服务，等索引对齐完成后再验证 445
sudo systemctl enable --now fsgw
sudo tail -f /var/lib/fsgw/logs/fsgw.log
```

口令不在版本库内：`webdav.password_hash` / `smb.nt_hash` 只有哈希，改口令用 `fsgw passwd` 或控制台。
