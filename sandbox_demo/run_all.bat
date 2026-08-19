@echo off
chcp 65001 >nul
rem =============================================================================
rem run_all.bat - M10 one-click regression: run all non-destructive demos
rem                (M0~M8) in sequence, tally PASS/FAIL by exit code.
rem
rem Skips M9 (kernel Minifilter) because it needs WDK build + VM + testsigning.
rem Requires ADMIN (M6/M7 use WFP/firewall); auto-elevates via PowerShell.
rem
rem PASS = demo exe exited 0. Each demo drives hello_target with --once
rem (jailbreak tests run then target exits, so nothing hangs).
rem =============================================================================

rem ---- auto elevate ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [i] Not admin, requesting elevation...
    powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k','cd /d \"%~dp0\" & \"%~f0\"' -Verb RunAs"
    exit /b
)

setlocal EnableDelayedExpansion
cd /d %~dp0

set BUILD_DIR=build_m0
set CFG=Debug
set BIN=%BUILD_DIR%\%CFG%
set TARGET=%BIN%\hello_target.exe

if not exist "%BIN%\m0_demo.exe" (
    echo [x] build not found. Run build.bat first.
    pause
    exit /b 1
)

rem prepare dirs some demos expect
if not exist C:\sandbox_share mkdir C:\sandbox_share
if not exist C:\sandbox_write mkdir C:\sandbox_write
if not exist C:\sandbox_protected mkdir C:\sandbox_protected
if not exist C:\sandbox_share\hello.txt echo hello-from-broker> C:\sandbox_share\hello.txt

set PASS=0
set FAIL=0

echo ==============================================================
echo   AI-Agent Sandbox - regression run (M0~M8)
echo ==============================================================

call :RUN "M0 Job+Token"            "%BIN%\m0_demo.exe" "%TARGET%" --once
call :RUN "M1 IL+Mitigation"        "%BIN%\m1_demo.exe" "%TARGET%" --once
call :RUN "M2 AppContainer"         "%BIN%\m2_demo.exe" "%TARGET%" --once
call :RUN "M3 Broker IPC"           "%BIN%\m3_demo.exe" "%TARGET%" --ipc --once
call :RUN "M4 Inject+Hook"          "%BIN%\m4_demo.exe" "%TARGET%" --once
call :RUN "M5 Anti-Inject"          "%BIN%\m5_demo.exe" "%TARGET%" --selfcheck --once
call :RUN "M6 WFP IP"               "%BIN%\m6_demo.exe" "%TARGET%" --once
call :RUN "M6 WFP AppID"            "%BIN%\m6_appid_demo.exe" "%TARGET%" --once
call :RUN "M7 DNS allowlist"        "%BIN%\m7_demo.exe" --allow example.com "%TARGET%" --once
call :RUN "M7 DNS->IP WFP"          "%BIN%\m7_ip_demo.exe" "%TARGET%" --once
call :RUN "M8 File Broker"          "%BIN%\m8_demo.exe" "%TARGET%" --ipc --once
call :RUN "M8 DENY-ACE"             "%BIN%\m8_denyacl_demo.exe" "%TARGET%" --once

echo.
echo ==============================================================
echo   SUMMARY   PASS=%PASS%  FAIL=%FAIL%
echo ==============================================================
echo (per-line PASS/FAIL shown above)
echo.
echo (M9 kernel Minifilter is skipped here; run it in a VM: see src\minifilter\README.md)
pause
exit /b 0

rem ---------------------------------------------------------------
rem :RUN <label> <exe> [args...]
rem ---------------------------------------------------------------
:RUN
set LABEL=%~1
shift
set CMD=%1
shift
set ARGS=
:collect
if "%~1"=="" goto runit
set ARGS=!ARGS! %1
shift
goto collect
:runit
echo.
echo ----- [!LABEL!] -----
%CMD% !ARGS!
set EC=!ERRORLEVEL!
if !EC! EQU 0 (
    set /a PASS+=1
    echo   -^> [PASS] !LABEL! ^(exit 0^)
) else (
    set /a FAIL+=1
    echo   -^> [FAIL] !LABEL! ^(exit !EC!^)
)
goto :eof
