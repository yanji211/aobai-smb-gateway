@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title Disable Windows SMB server and start fsgw

net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo [..] Requesting administrator privileges, please click YES on UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================================
echo  Step 1/5  Disable Windows built-in SMB server
echo ============================================================
powershell -NoProfile -Command "Set-Service -Name LanmanServer -StartupType Disabled -ErrorAction SilentlyContinue; Write-Output ('      LanmanServer StartType = ' + (Get-Service LanmanServer).StartType)"
powershell -NoProfile -Command "Stop-Service -Name LanmanServer -Force -ErrorAction SilentlyContinue; Write-Output ('      LanmanServer Status    = ' + (Get-Service LanmanServer).Status)"
echo.

echo ============================================================
echo  Step 2/5  Wait for port 445 to be released (max 25s)
echo ============================================================
powershell -NoProfile -Command "$ok=$false; for($i=0;$i -lt 25;$i++){ if(-not (Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue)){ $ok=$true; break }; Start-Sleep -Seconds 1 }; if($ok){ Write-Output '      445 is FREE' } else { Write-Output '      445 STILL BUSY'; $c=Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue; foreach($x in $c){ $p=Get-Process -Id $x.OwningProcess -ErrorAction SilentlyContinue; if($p){ Write-Output ('      holder: PID ' + $p.Id + ' ' + $p.ProcessName) } }; exit 1 }"
set PORT_FREE=%errorlevel%
echo.

echo ============================================================
echo  Step 3/5  Clear stale "port 445 blocked" record
echo ============================================================
if exist "data\port445_blocked.json" (
    del /q "data\port445_blocked.json"
    echo      removed data\port445_blocked.json
) else (
    echo      nothing to clean
)
echo.

if not "%PORT_FREE%"=="0" goto :need_reboot

echo ============================================================
echo  Step 4/5  Start fsgw (it will serve 445 with built-in SMB1)
echo ============================================================
start "" "%~dp0fsgw.exe"
Start-Sleep -Seconds 6
powershell -NoProfile -Command "$c=Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue; if($c){ foreach($x in $c){ $p=Get-Process -Id $x.OwningProcess -ErrorAction SilentlyContinue; if($p){ Write-Output ('      445 now held by PID ' + $p.Id + ' ' + $p.ProcessName) } }; Write-Output '      -> if it says fsgw, you are good' } else { Write-Output '      445 still not listening, check fsgw window / data\fsgw.log' }"
echo.

echo ============================================================
echo  Step 5/5  Done
echo ============================================================
echo  Old Mi TV should now use:   \\192.0.2.10\share
echo.
pause
exit /b

:need_reboot
echo ============================================================
echo  Port 445 could not be released by stopping the service.
echo  The SMB kernel driver only unloads at boot.
echo.
echo  Please REBOOT this machine once. After reboot
echo  LanmanServer stays Disabled, so 445 will be free and
echo  fsgw can take it. Then just double-click fsgw.exe.
echo ============================================================
echo.
pause
exit /b
