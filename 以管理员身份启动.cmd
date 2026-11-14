@echo off
chcp 65001 >nul
cd /d "%~dp0"

rem 这个脚本现在只用于兼容旧的快捷方式：
rem fsgw.exe 自己会弹 UAC 提权、转到后台、起来后打开控制台，不需要这里再绕一层。
"%~dp0fsgw.exe" %*
