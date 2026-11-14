# Windows 部署骨架

熬拜共享家（fsgw）在 Windows 上的部署方式，与 `deploy/linux/` 对称：**源码同一份**，
只是产物、服务托管方式、以及 445 端口的归属处理不同。

```
deploy/windows/
├── README.md                 本文件：Windows 部署要点
└── 88/                       192.0.2.10 实况（见其 README）
    ├── README.md             主机/二进制指纹/端口/路径/计划任务/踩坑/复原
    ├── register-task.ps1     注册开机自启计划任务（SYSTEM，替代手工启动）
    └── restore-smb.cmd       回滚：停 fsgw、把 LanmanServer 恢复 Automatic
```

## 1. 产物与配置

| 项 | Windows |
|---|---|
| 二进制 | `fsgw.exe`（windows/amd64，**不入库**，每次构建都变） |
| 构建 | 在仓库根：`GOOS=windows GOARCH=amd64 go build -o fsgw.exe ./cmd/fsgw` |
| 配置 | **仓库根 `config.yaml`**（即 Windows 实际运行值，见 88/README 关键项） |
| 数据目录 | `data_dir`（本机 `D:\fsgw\data`）：`fsgw.db`、`control.token`、`logs\` |
| 启动 | `fsgw.exe run -notray`；交互式双击等价于 `fsgw run -detach -open` |

配置与 Linux 共用同一套字段，只在路径、`dlna.friendly_name` 等处不同。

## 2. 关键差异：445 归谁

Linux 上 445 空着，fsgw 直接绑。**Windows 上 445 默认被系统 SMB 服务占着**：

- 持有者是内核驱动 `srvnet`（进程显示为 PID 4 System），停 `LanmanServer` 服务**不会**立刻释放；
- 系统 SMB 默认 `EnableSMB1Protocol=False`，小米电视这类纯 SMB1 客户端连不上；
- 因此方案是：`LanmanServer` 设为 **Disabled** → **重启一次**（srvnet 只在开机时加载）→ 445 从开机起就是空的 → fsgw 接管。

代价与注意：

- 本机的 Windows 自带共享（`\\192.0.2.10\c$`、`net share` 出来的东西）随之失效；
- 想恢复系统共享：跑 `deploy/windows/88/restore-smb.cmd`（或桌面同名脚本），恢复后 445 就要还给系统 SMB，
  fsgw 必须停 —— 两者**不能同时占 445**；
- 一键改造脚本在仓库根：`disable-windows-smb.cmd`（停服务 → 等 445 释放 → 清掉 `data\port445_blocked.json` → 起 fsgw；
  若 445 仍被咬住会提示重启）。

## 3. 常驻：不要用「终端里起进程」

在会话里 `fsgw.exe run -notray` 或 `-detach`，**会话一结束进程就被回收**（实测 `-detach` 也撑不过 3 秒）。
Windows 上要让 445 长期在线，用计划任务托管：

- 任务名 `fsgw-share`，动作 `D:\fsgw\fsgw.exe run -notray`，工作目录 `D:\fsgw`
- 触发器 AtStartup，主体 `SYSTEM` + `Highest`，失败自动重启 3 次 / 间隔 1 分钟
- 进程落在 session 0，不随任何登录会话/终端结束

注册脚本：`deploy/windows/88/register-task.ps1`（需管理员 PowerShell）。

## 4. 总开关别忘

`switch.startup_state` 不是 `OFF` 才会开局域网面（445 / 8200 / 8445）。
`OFF` 时只有控制台 8444 在听，表现为「服务起了但电视连不上」。
改完可直接 `fsgw.exe on -state LAN` 生效，不必重启（但重启后仍以配置文件为准，所以**配置文件要一起改**）。
