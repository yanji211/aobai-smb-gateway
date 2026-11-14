# 注册 fsgw 开机自启计划任务（fsgw-share）
# 用管理员 PowerShell 执行：  .\register-task.ps1
# 自定义路径：                .\register-task.ps1 -Root "D:\fsgw"
#
# 为什么用计划任务而不是直接起进程：
#   在终端/会话里 start fsgw.exe，会话结束进程就被回收（run -detach 实测也撑不过 3 秒）。
#   SYSTEM 主体的计划任务落在 session 0，开机即起，不随任何登录会话结束。

param(
    [string]$Root  = "D:\fsgw",
    [string]$Name  = "fsgw-share",
    [string]$Args  = "run -notray"
)

$ErrorActionPreference = "Stop"

# 管理员校验
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[x] 需要管理员权限，请用管理员 PowerShell 重跑本脚本。" -ForegroundColor Red
    exit 1
}

$exe = Join-Path $Root "fsgw.exe"
if (-not (Test-Path $exe)) {
    Write-Host "[x] 找不到 $exe" -ForegroundColor Red
    exit 1
}

Write-Host "[..] 注册计划任务 $Name -> $exe $Args"

$action    = New-ScheduledTaskAction -Execute $exe -Argument $Args -WorkingDirectory $Root
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -ExecutionTimeLimit ([TimeSpan]::Zero) `
                -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName $Name
Start-Sleep -Seconds 4

Get-ScheduledTask -TaskName $Name | Select-Object TaskName, State | Format-Table -AutoSize | Out-String
Get-Process fsgw -ErrorAction SilentlyContinue |
    Select-Object Id, SessionId, StartTime | Format-Table -AutoSize | Out-String

Write-Host "[ok] 已注册并启动。445 起来需要先完成索引对齐（数十万文件约 1-3 分钟）。"
Write-Host "     查看：  $exe status"
Write-Host "     撤销：  Unregister-ScheduledTask -TaskName $Name -Confirm:`$false"
