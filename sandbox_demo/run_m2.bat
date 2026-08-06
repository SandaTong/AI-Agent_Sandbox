@echo off
rem =============================================================================
rem run_m2.bat - 用 M2 沙箱（AppContainer，不带网络）拉起 hello_target
rem
rem 期望现象：
rem   * broker 打印 AppContainer package SID = S-1-15-2-...
rem   * target 打印 integrity_level = Low
rem   * jailbreak-1..5 全部 BLOCKED（M1 层护栏还在）
rem   * jailbreak-6 (global mutex) : BLOCKED (AppContainer 命名空间)
rem   * jailbreak-7 (TCP connect)  : BLOCKED (WSAErr=10013, 无 internetClient cap)
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug

if "%~1"=="" (
    set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe
) else (
    set TARGET=%~1
)

echo === Launching M2 sandbox: %TARGET% ===
%BUILD_DIR%\%CFG%\m2_demo.exe "%TARGET%"
echo.
echo === m2_demo exit code = %ERRORLEVEL% ===
pause
