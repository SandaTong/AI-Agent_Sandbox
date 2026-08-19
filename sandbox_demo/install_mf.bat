@echo off
chcp 65001 >nul
rem =============================================================================
rem install_mf.bat - M9 install & load the Minifilter driver (admin required)
rem
rem Prereq (one-time, then REBOOT):
rem   bcdedit /set testsigning on
rem   (run in a VM; kernel bug = BSOD)
rem
rem This script: copies .sys to system32\drivers, sc create as filesystem driver,
rem then fltmc load. Assumes sandbox_minifilter.sys is already built by WDK and
rem sits next to this script (or edit SYS path below).
rem =============================================================================
setlocal
cd /d %~dp0

rem ---- self-elevate to admin via PowerShell (see memory bat rules) ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [i] Not admin, requesting elevation...
    powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k','cd /d \"%~dp0\" & \"%~f0\"' -Verb RunAs"
    exit /b
)

set SVC=sandboxmf
set SYS=%~dp0src\minifilter\x64\Debug\sandbox_minifilter.sys
set DST=%SystemRoot%\System32\drivers\sandbox_minifilter.sys

if not exist "%SYS%" (
    echo [x] %SYS% not found. Build it with WDK first ^(sandbox_minifilter.vcxproj^).
    echo     If your .sys is elsewhere, edit SYS= above to point to it.
    pause
    exit /b 1
)

echo [i] copy sys to drivers dir
copy /y "%SYS%" "%DST%" >nul

echo [i] sc create %SVC% ^(filesystem minifilter^)
sc create %SVC% type= filesys binPath= "%DST%" start= demand group= "FSFilter Activity Monitor" >nul 2>&1
rem altitude is read from the service registry set by INF; for sc-only path we add it:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SVC%\Instances" /v DefaultInstance /t REG_SZ /d "sandboxmf Instance" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SVC%\Instances\sandboxmf Instance" /v Altitude /t REG_SZ /d "370000" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SVC%\Instances\sandboxmf Instance" /v Flags /t REG_DWORD /d 0 /f >nul

echo [i] fltmc load %SVC%
fltmc load %SVC%
if %ERRORLEVEL% NEQ 0 (
    echo [x] fltmc load failed. Check: testsigning on + rebooted? sys signed for test?
) else (
    echo [OK] driver loaded. Verify with: fltmc filters
)
pause
