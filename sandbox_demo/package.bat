@echo off
chcp 65001 >nul
rem =============================================================================
rem package.bat - M11 collect build outputs + scripts + docs into a release zip
rem
rem Output: release\sandbox_demo_release_YYYYMMDD.zip
rem Contains: build_m0\Debug\*.exe + *.dll, all run_*.bat / install/uninstall,
rem           README.md, docs\notes\*.md, src\minifilter\*.sys (if built).
rem No source .cc/.h (this is a runnable release, not source). Uses PowerShell
rem Compress-Archive (built-in, no 7-zip needed).
rem =============================================================================
setlocal
cd /d %~dp0

set BIN=build_m0\Debug
if not exist "%BIN%\m0_demo.exe" (
    echo [x] build not found. Run build.bat first.
    pause
    exit /b 1
)

rem ---- timestamp YYYYMMDD ----
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd"') do set STAMP=%%i
set STAGE=release\stage
set ZIP=release\sandbox_demo_release_%STAMP%.zip

echo [i] cleaning stage
if exist release rmdir /s /q release
mkdir "%STAGE%\bin" "%STAGE%\scripts" "%STAGE%\docs"

echo [i] copy binaries (exe/dll)
copy /y "%BIN%\*.exe" "%STAGE%\bin\" >nul
copy /y "%BIN%\*.dll" "%STAGE%\bin\" >nul
if exist "src\minifilter\x64\Debug\sandbox_minifilter.sys" (
    copy /y "src\minifilter\x64\Debug\sandbox_minifilter.sys" "%STAGE%\bin\" >nul
    copy /y "src\minifilter\sandbox_minifilter.inf" "%STAGE%\bin\" >nul
)

echo [i] copy scripts
copy /y "run*.bat" "%STAGE%\scripts\" >nul
copy /y "install_mf.bat" "%STAGE%\scripts\" >nul 2>nul
copy /y "uninstall_mf.bat" "%STAGE%\scripts\" >nul 2>nul

echo [i] copy docs
copy /y "README.md" "%STAGE%\" >nul
copy /y "docs\notes\*.md" "%STAGE%\docs\" >nul

echo [i] compress -> %ZIP%
powershell -NoProfile -Command "Compress-Archive -Path '%STAGE%\*' -DestinationPath '%ZIP%' -Force"

if exist "%ZIP%" (
    echo [OK] release created: %ZIP%
    rmdir /s /q "%STAGE%"
) else (
    echo [x] compress failed
)
pause
