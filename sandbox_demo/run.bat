@echo off
rem =============================================================================
rem run.bat - 用 M0 sandbox 拉起 hello_target 做冒烟
rem 用法:
rem   run.bat                              -> 沙箱运行 hello_target.exe
rem   run.bat "C:\path\to\your.exe"        -> 沙箱运行指定程序
rem
rem 说明:
rem   * 默认不再用 notepad.exe。Win11 的 notepad 是 UWP wrapper：一被启动
rem     它就把窗口交给系统 UWP host 然后自己退出，看起来像"秒退"。这属于
rem     Windows 现代应用的正常行为，不是沙箱 bug。
rem   * hello_target 是我们自己写的极简 target：打印自身 IL + 心跳循环，
rem     方便观察沙箱前后区别。
rem =============================================================================

setlocal
set BUILD_DIR=build_m0
set CFG=Debug

if "%~1"=="" (
    set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe
) else (
    set TARGET=%~1
)

echo === Launching sandboxed target: %TARGET%===
%BUILD_DIR%\%CFG%\m0_demo.exe "%TARGET%"
echo.
echo === m0_demo exit code = %ERRORLEVEL% ===
pause
