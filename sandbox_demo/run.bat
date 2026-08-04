@echo off
rem =============================================================================
rem run.bat - 用 M0 sandbox 拉起 notepad 做冒烟
rem 用法: run.bat  或  run.bat "C:\path\to\your.exe"
rem =============================================================================

setlocal
set BUILD_DIR=build_m0
set CFG=Debug

if "%~1"=="" (
    set TARGET=C:\Windows\System32\notepad.exe
) else (
    set TARGET=%~1
)

%BUILD_DIR%\%CFG%\m0_demo.exe "%TARGET%"
