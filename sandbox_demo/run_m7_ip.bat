@echo off
chcp 65001 >nul
rem =============================================================================
rem run_m7_ip.bat - M7 [Form C: DNS->IP linked with M6 WFP]
rem
rem broker resolves allowlisted domains to IPs (shows DNS->IP->WFP link), then
rem uses M6 WFP. WFP IP exact-match does not hit on this box (see M6.md sec 4),
rem so it falls back to AppID form to block all target outbound; resolved IPs
rem are printed as the linkage policy.
rem
rem Requires ADMIN (WFP filter needs write access). Double-click auto-elevates.
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

echo === M7 DNS-IP: resolve example.com to IP + AppID fallback block ===
rem --once: target exits after jailbreak tests (won't hang the script).
%BUILD_DIR%\%CFG%\m7_ip_demo.exe --allow example.com "%TARGET%" --once
echo.
echo === m7_ip_demo exit code = %ERRORLEVEL% ===
echo [i] Form C does NOT hook DNS: jailbreak-8 two lines are SUCCESS (no resolve block).
echo [i] jailbreak-7 three lines are BLOCKED by AppID fallback; broker log shows example.com IP.
pause
