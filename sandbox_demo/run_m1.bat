@echo off
rem =============================================================================
rem run_m1.bat - 用 M1 沙箱（Low IL + Mitigation + Alt Desktop）拉起 hello_target
rem
rem 与 run.bat（M0 版本）对比预期:
rem   * hello_target 打印的 integrity_level 从 High/Medium 变成 Low
rem   * Process Explorer 里可以看到 target 的 Mandatory Label = Low
rem   * Threads 标签里 target 属于 sandbox_winsta_xxx\sandbox_desk
rem   * target 试图起子进程 -> 会失败（ACCESS_DENIED）
rem =============================================================================

setlocal
set BUILD_DIR=build_m0
set CFG=Debug

if "%~1"=="" (
    set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe
) else (
    set TARGET=%~1
)

echo === Launching M1 sandboxed target: %TARGET% ===
%BUILD_DIR%\%CFG%\m1_demo.exe "%TARGET%"
echo.
echo === m1_demo exit code = %ERRORLEVEL% ===
pause
