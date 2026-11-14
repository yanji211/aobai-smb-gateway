# deploy 目录说明

熬拜共享家（fsgw）一套 Go 源码、两个平台产物，部署相关的东西按平台分开放：

```
deploy/
├── linux/                    Linux 部署骨架（以 110 实际值为准）
│   ├── install.sh            安装脚本：建目录、装二进制、放 systemd 单元、放配置
│   ├── fsgw.service          systemd 单元（ExecStart=/usr/local/bin/fsgw run -config /etc/fsgw/config.yaml -notray）
│   ├── fsgw-smb1.service     旧方案：回环 samba 后端（现已 disabled，SMB1 走进程内置通道）
│   ├── smb1.conf             旧方案配套 samba 配置（只讲 NT1、只读、guest）
│   ├── config.yaml           **110 实际运行配置**（可写、admin 账号、nt_hash、内置 SMB1 通道）
│   ├── config.template.yaml  保守模板（只读、guest_writable false，适合新机器起步）
│   └── 110/                  192.0.2.11 实况说明（见其 README）
│       ├── smb_clients.yaml  客户端 NT 哈希白名单
│       └── README.md         主机/二进制指纹/端口/路径/与模板差异/复原步骤
└── windows/                  Windows 部署骨架（以 88 实际值为准）
    ├── README.md             Windows 部署要点（445 归属、计划任务常驻、总开关）
    └── 88/                   192.0.2.10 实况说明（见其 README）
        ├── README.md         主机/二进制指纹/端口/路径/计划任务/踩坑/复原
        ├── register-task.ps1 注册开机自启计划任务 fsgw-share（SYSTEM）
        └── restore-smb.cmd   回滚：停 fsgw，恢复系统 SMB 服务
```

> `linux/fsgw`（linux/amd64 二进制）与 Windows 的 `fsgw.exe` 都不入库。现场用本仓库源码构建：
> `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o fsgw ./cmd/fsgw`
> `GOOS=windows GOARCH=amd64 go build -o fsgw.exe ./cmd/fsgw`
> 当前版本指纹：110 `<build-md5>`（见 `linux/110/README.md`）、88 `<build-md5>`（见 `windows/88/README.md`）。

## Windows 版

- 源码：与本仓库同一份（`cmd/`、`internal/`），交叉编译目标不同而已
- 配置：仓库根目录 `config.yaml`（`data_dir: D:\fsgw\data`，共享根 `D:\share`）
- 常驻：计划任务 `fsgw-share`（`SYSTEM` / AtStartup / session 0），**不要在终端里起进程**
- 445 归属：Windows 默认被 `srvnet` 占用，需 `LanmanServer` 设 Disabled 并重启一次，fsgw 才能接管；
  一键脚本 `disable-windows-smb.cmd`（仓库根），回滚 `deploy/windows/88/restore-smb.cmd`
- 实况与踩坑：见 [`windows/88/README.md`](windows/88/README.md)


## Linux 版（以 110 为准）

- 编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o fsgw ./cmd/fsgw`
- 安装：`sudo bash deploy/linux/install.sh`，二进制放 `/usr/local/bin/fsgw`
- 配置：`/etc/fsgw/config.yaml`（0600），数据 `/var/lib/fsgw`
- 实况与复原：见 [`linux/110/README.md`](linux/110/README.md)

## 两边都要注意的两条

1. **SMB1 走进程内置通道**（`internal/smbgo/smb1srv.go`），不需要系统装 samba；
   `smb1_backend` 留空 = 用内置通道，填地址才转交外部 samba。
2. **启动先做索引对齐，完成前不开放 445**（Linux 侧约 1–3 分钟），日志在
   `/var/lib/fsgw/logs/fsgw.log`（JSON，不进 journald）。
