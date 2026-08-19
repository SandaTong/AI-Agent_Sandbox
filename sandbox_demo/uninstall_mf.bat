@echo off
chcp 65001 >nul
rem =============================================================================
rem uninstall_mf.bat - M9 unload & remove the Minifilter driver (admin required)
rem =============================================================================
setlocal
cd /d %~dp0

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [i] Not admin, requesting elevation...
    powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k','cd /d \"%~dp0\" & \"%~f0\"' -Verb RunAs"
    exit /b
)

set SVC=sandboxmf

echo [i] fltmc unload %SVC%
fltmc unload %SVC%

echo [i] sc delete %SVC%
sc delete %SVC% >nul 2>&1

echo [i] remove sys
del /q "%SystemRoot%\System32\drivers\sandbox_minifilter.sys" 2>nul

echo [OK] uninstalled. Verify with: fltmc filters
pause
