@echo off
chcp 65001 >nul
rem =============================================================================
rem run_m7.bat - M7 [Form A: DNS domain allowlist Hook]
rem
rem broker injects dns_hook.dll into target, hooks ws2_32!GetAddrInfoW, and
rem allows/blocks by domain allowlist. Non-allowlisted domains fail to resolve
rem (GetAddrInfoW returns WSAHOST_NOT_FOUND / 11001).
rem
rem Observe the hook via:
rem   * Sysinternals DebugView : [dns] allow/block ...
rem   * %TEMP%\dns_hook_log.txt : on disk
rem
rem Expected (target jailbreak-8):
rem   [8a] resolve example.com  (allowlisted)     : SUCCESS
rem   [8b] resolve www.bing.com (not allowlisted) : BLOCKED (err=11001)
rem =============================================================================
setlocal
cd /d %~dp0

set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === M7 DNS allowlist: only example.com allowed, others blocked ===
rem --once: target exits after jailbreak tests (won't hang the script).
%BUILD_DIR%\%CFG%\m7_demo.exe --allow example.com "%TARGET%" --once
echo.
echo === m7_demo exit code = %ERRORLEVEL% ===
pause
