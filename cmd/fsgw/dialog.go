package main

// conflictChoice 是"检测到已有实例在跑"时用户的选择。
//
// 之所以要有 choiceSkip：命令行脚本、开机计划任务、Linux 服务端这些场景
// 没有可见桌面，弹一个 MessageBox 会把进程永久挂住且谁也看不见。它们必须
// 沿用原来的"打印一行再返回"，不能进对话框。
type conflictChoice int

const (
	choiceSkip     conflictChoice = iota // 非交互场景：保持原行为
	choiceKeepOld                        // 保留已有服务，放弃本次启动
	choiceTakeOver                       // 结束已有服务，改用当前这份程序/配置启动
)
