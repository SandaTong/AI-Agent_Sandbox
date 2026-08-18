@echo off
chcp 65001 >nul
rem =============================================================================
rem run_m8_denyacl.bat - M8 [Form B: DENY-ACE strips target's write permission]
rem
rem Before launching target, broker appends a DENY-WRITE ACE (with inherit flags)
rem for the current user's SID onto C:\sandbox_protected via SetNamedSecurityInfo.
rem Target then directly CreateFileW(GENERIC_WRITE) inside that dir and is denied
rem by the kernel DACL check (DENY beats ALLOW). The ACE is rolled back on exit.
rem
rem Expected (target jailbreak-9):
rem   [jailbreak-9] direct write protected dir : BLOCKED (gle=5 ACCESS_DENIED)
rem (without this demo, jailbreak-9 would be SUCCESS)
rem =============================================================================
setlocal
cd /d %~dp0

set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

rem ---- prepare protected dir ----
if not exist C:\sandbox_protected mkdir C:\sandbox_protected

echo === M8 DENY-ACE: target write to C:\sandbox_protected should be blocked ===
%BUILD_DIR%\%CFG%\m8_denyacl_demo.exe "%TARGET%" --once
echo.
echo === m8_denyacl_demo exit code = %ERRORLEVEL% ===
pause
