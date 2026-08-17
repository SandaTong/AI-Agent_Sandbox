@echo off
chcp 65001 >nul
rem =============================================================================
rem run_m6_appid.bat - M6 WFP network control [Form C: AppID exact match]
rem
rem broker uses WFP to block ALL outbound of hello_target.exe by exe path
rem (AppId). Only this one process is affected; others are untouched.
rem
rem Requires ADMIN (WFP filter needs write access). Double-click auto-elevates.
rem
rem Expected (target jailbreak-7 all BLOCKED):
rem   [7a] 8.8.8.8   : BLOCKED
rem   [7b] 1.1.1.1   : BLOCKED
rem   [7c] 127.0.0.1 : BLOCKED  (even loopback - WFP advantage over Firewall)
rem =============================================================================

rem ---- auto elevate: relaunch as admin via PowerShell if not admin ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [i] Not admin, requesting elevation...
    powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k','cd /d \"%~dp0\" & \"%~f0\"' -Verb RunAs"
    exit /b
)

setlocal
cd /d %~dp0

set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === M6 AppID exact block: block all outbound of hello_target.exe (incl loopback) ===
rem --once: target exits after jailbreak tests (won't hang the script).
%BUILD_DIR%\%CFG%\m6_appid_demo.exe "%TARGET%" --once
echo.
echo === m6_appid_demo exit code = %ERRORLEVEL% ===
pause
