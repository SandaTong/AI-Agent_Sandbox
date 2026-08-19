@echo off
chcp 65001 >nul
rem =============================================================================
rem run_mf.bat - M9 run the user-mode control program (admin required)
rem
rem Connects to the Minifilter comm port, pushes a sensitive-path blocklist,
rem then prints audit records (which pid opened which path, allow/BLOCKED).
rem
rem Default blocklist keyword: \sandbox_secret\  (case-insensitive substring).
rem After it runs, open any file under C:\sandbox_secret\ from another process
rem (e.g. notepad) -> should be denied, and every open is audited here.
rem =============================================================================
setlocal
cd /d %~dp0

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [i] Not admin, requesting elevation...
    powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k','cd /d \"%~dp0\" & \"%~f0\"' -Verb RunAs"
    exit /b
)

set BUILD_DIR=build_m0
set CFG=Debug
set CTL=%BUILD_DIR%\%CFG%\mf_ctl.exe

if not exist "%CTL%" (
    echo [x] %CTL% not found. Build mf_ctl first: cmake --build %BUILD_DIR% --config %CFG% --target mf_ctl
    pause
    exit /b 1
)

rem prepare a demo protected dir so you have something to test open on
if not exist C:\sandbox_secret mkdir C:\sandbox_secret
echo top-secret> C:\sandbox_secret\a.txt 2>nul

echo === M9 Minifilter control: blocklist keyword = \sandbox_secret\ ===
echo (open C:\sandbox_secret\a.txt from notepad in another window to see BLOCKED)
"%CTL%" "\sandbox_secret\"
pause
