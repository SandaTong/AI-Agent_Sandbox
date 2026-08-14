@echo off
rem =============================================================================
rem run_m6.bat - M6 WFP 网络管控【形态 A：IP 黑名单】
rem
rem broker 用 WFP 给 target 装：对黑名单 IP（默认 8.8.8.8）加 BLOCK，其余放行，
rem 规则限定到只对 target 进程生效（不动全机网络）。
rem
rem ⚠️ 必须以【管理员】运行——改 WFP filter 要写权限，否则 FwpmEngineOpen 失败。
rem
rem 期望现象（target 的 jailbreak-7 三行）：
rem   [7a] 8.8.8.8   (黑名单内) : BLOCKED  <- 从 M0~M5 一直 SUCCESS，M6 按 IP 拦下
rem   [7b] 1.1.1.1   (黑名单外) : SUCCESS  <- 不在黑名单，放行
rem   [7c] 127.0.0.1 (loopback) : SUCCESS  <- 不在黑名单，放行（要拦 loopback 见 AppID 形态）
rem =============================================================================
setlocal

rem 自检管理员权限
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] 需要管理员权限。请右键"以管理员身份运行"本脚本。
    pause
    exit /b 1
)

set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === M6 IP 黑名单：拦 target 连 8.8.8.8，其余放行 ===
%BUILD_DIR%\%CFG%\m6_demo.exe --block 8.8.8.8 "%TARGET%"
echo.
echo === m6_demo exit code = %ERRORLEVEL% ===
pause
