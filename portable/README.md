# Windows 绿色版（portable）

解压即用的 Windows 构建，无需安装、无需编译、无需系统 samba。
从 [Releases](https://github.com/yanji211/aobai-smb-gateway/releases/latest)
下载 `aobai-smb-gateway-portable-win-x64.zip`。

## 包内容

```
aobai-smb-gateway\
├── fsgw.exe                     ← 双击运行（自动 UAC 提权 + 后台常驻 + 打开控制台）
├── config.yaml                  ← 相对路径配置：data_dir: data / root: share
├── start.cmd / stop.cmd         ← 启动 / 优雅停止
├── disable-system-smb.cmd       ← 可选：腾出 445（改系统服务，需重启）
├── restore-system-smb.cmd       ← 可选：恢复 Windows 自带共享
├── README.md                    ← 完整使用说明
└── share\                       ← 默认共享根，把文件放这里
    └── README.txt               ← 占位说明
```

`config.yaml` 里的路径全部相对配置文件所在目录解析，所以整个文件夹复制到
U 盘或另一台电脑都不用改配置。运行时数据（`data\`：SQLite 索引、日志、token）
首次启动自动创建，删掉整个文件夹即可卸载。

## 默认账号

`admin` / `123456`，SMB、控制台（`127.0.0.1:8444`）、WebDAV（`127.0.0.1:8443`）共用一套。
`smb.auth: guest` 让电视 / 老播放器这类纯 SMB1 设备免密直连，同时该账号仍可显式登录
（Win11 24H2 强制签名时需要）；改成 `account` 即强制账号登录。

> ⚠️ 这是**刻意写在公开包里的默认弱口令**，只为开箱即用。
> 在不可信网络使用前必须修改：`fsgw.exe smb nt-hash 新口令` 填回 `smb.nt_hash`，
> `fsgw.exe passwd -password 新口令` 填回 `webdav.password_hash`，然后 stop/start。

## 445 端口

自研服务端要接管 TCP 445，而 Windows 自带 `LanmanServer`（内核 `srvnet`，PID 4）开机就占着。
**只 stop 服务不够**，必须设为 Disabled 并重启电脑。包里的 `disable-system-smb.cmd`
做这件事、`restore-system-smb.cmd` 负责恢复。详见包内 README.md。

## 从源码重建

```bat
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0
set GOTOOLCHAIN=go1.26.10
go build -trimpath -ldflags "-s -w" -o fsgw.exe ./cmd/fsgw
```

把上面的 exe 与一份相对路径配置（参考包内 `config.yaml`）放进同一目录，
再建一个 `share\` 文件夹即可。Windows 版本信息 / 图标资源在
`cmd/fsgw/resource_windows_amd64.syso`，已随源码入库。

> 注意：仓库根目录的 `config.yaml` 是**脱敏占位版**（口令哈希全 0），不能直接拿来跑；
> 绿色包里的 `config.yaml` 才带可登录的默认账号。

© 2026 成都曼巴科技有限公司 · 保留所有权利
