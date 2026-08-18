@echo off
chcp 65001 >nul
rem =============================================================================
rem run_m8.bat - M8 [Form A: file broker policy engine]
rem
rem Broker exposes a named-pipe file broker with an enhanced policy engine:
rem   * multi-rule allowlist: C:\sandbox_share (read-only) + C:\sandbox_write (writable)
rem   * read/write/create operations over IPC
rem   * TOCTOU defense: open handle first, verify real path via GetFinalPathNameByHandle
rem   * minimal-access handle duplication back to target
rem
rem Expected (target --ipc):
rem   [ipc] open C:\sandbox_share\hello.txt       -> OK (read)
rem   [ipc] open ...\drivers\etc\hosts            -> BLOCKED (out of allowlist)
rem   [ipc] write C:\sandbox_write\agent_out.txt  -> OK (broker on behalf)
rem   [ipc] write C:\sandbox_share\should_fail.txt-> BLOCKED (read-only rule)
rem =============================================================================
setlocal
cd /d %~dp0

set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

rem ---- prepare policy dirs / seed file ----
if not exist C:\sandbox_share mkdir C:\sandbox_share
if not exist C:\sandbox_write mkdir C:\sandbox_write
if not exist C:\sandbox_share\hello.txt echo hello-from-broker> C:\sandbox_share\hello.txt

echo === M8 file broker: read-only C:\sandbox_share + writable C:\sandbox_write ===
%BUILD_DIR%\%CFG%\m8_demo.exe "%TARGET%" --ipc --once
echo.
echo === m8_demo exit code = %ERRORLEVEL% ===
echo (check C:\sandbox_write\agent_out.txt was written by broker)
pause
