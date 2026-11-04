@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -File "%~dp0Start-Sentinel.ps1" %*
set "sentinel_exit=%errorlevel%"
if not "%sentinel_exit%"=="0" pause
exit /b %sentinel_exit%
