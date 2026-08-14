@echo off
rem =============================================================================
rem run_m6_appid.bat - M6 WFP 网络管控【形态 C：AppID 精确匹配】
rem
rem broker 用 WFP 按 exe 路径(AppId) 精确拦 hello_target.exe 的全部 outbound，
rem 只影响这一个进程，同机其他进程网络不受影响。
rem
rem ⚠️ 必须以【管理员】运行。
rem
rem 期望现象（target 的 jailbreak-7 三行全 BLOCKED）：
rem   [7a] 8.8.8.8   (白名单外) : BLOCKED
rem   [7b] 1.1.1.1   (白名单内) : BLOCKED  <- AppID 形态无白名单，全拦
rem   [7c] 127.0.0.1 (loopback) : BLOCKED  <- 连回环也拦，WFP 相对 Firewall 的关键优势
rem =============================================================================
setlocal

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] 需要管理员权限。请右键"以管理员身份运行"本脚本。
    pause
    exit /b 1
)

set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === M6 AppID 精确拦截：拦 hello_target.exe 全部 outbound（含 loopback）===
%BUILD_DIR%\%CFG%\m6_appid_demo.exe "%TARGET%"
echo.
echo === m6_appid_demo exit code = %ERRORLEVEL% ===
pause
