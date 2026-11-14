@echo off
chcp 437 >nul
setlocal
title fsgw: restore Windows built-in SMB

rem Rollback: stop fsgw, set LanmanServer back to Automatic and start it.
rem Note: built-in SMB serves SMB2/3 only, so the old Mi TV (SMB1) still
rem       cannot browse this machine.
rem Port 445 has a single owner: fsgw must be stopped after rollback.

net session >nul 2>&1
if errorlevel 1 (
    echo [..] Requesting administrator rights, please click YES on the UAC prompt.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    timeout /t 3 >nul
    exit /b
)

echo ============================================================
echo  [1/3] Stop fsgw
echo ============================================================
powershell -NoProfile -Command "Get-Process -Name fsgw -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; '  fsgw stopped (if it was running)'"
timeout /t 2 >nul

echo.
echo ============================================================
echo  [2/3] Restore LanmanServer to Automatic and start it
echo ============================================================
sc.exe config LanmanServer start= auto
sc.exe start LanmanServer
echo.
sc.exe qc LanmanServer | findstr /i "START_TYPE"
sc.exe query LanmanServer | findstr /i "STATE"

echo.
echo ============================================================
echo  [3/3] Who holds 445 now
echo ============================================================
powershell -NoProfile -Command "$c=Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue; if(-not $c){'  445 not listening yet, give it a few seconds'}; foreach($x in $c){ $p=Get-Process -Id $x.OwningProcess -ErrorAction SilentlyContinue; '  445 held by ' + $p.ProcessName + ' (PID ' + $x.OwningProcess + ')' }"

echo.
echo  Windows built-in SMB restored. Note: it serves SMB2/3 only,
echo  so the old Mi TV (SMB1) still cannot browse this machine.
echo.
echo  If fsgw is registered as a scheduled task, stop it from
echo  re-taking 445 on next boot:
echo     schtasks /end    /tn fsgw-share
echo     schtasks /change /tn fsgw-share /disable
echo ============================================================
pause
exit /b
