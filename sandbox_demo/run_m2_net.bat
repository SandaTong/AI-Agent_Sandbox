@echo off
chcp 65001 >nul
rem =============================================================================
rem run_m2_net.bat - M2 sandbox + internetClient capability
rem
rem Demonstrates broker API: CreateWellKnownSid(WinCapabilityInternetClientSid)
rem + adding the cap SID into SECURITY_CAPABILITIES::Capabilities[].
rem
rem NOTE: this script does NOT change jailbreak-7. See docs/notes/M2.md sec 9:
rem   AppContainer network policy has two layers:
rem     L1 (loopback) - WFP kernel AppContainerLoopback filter, no rule needed
rem     L2 (public)   - Windows Firewall user-mode engine, needs a block rule
rem   jailbreak-7 hits loopback, so internetClient cap has no visible effect
rem   here (cap is only the matching key for L2 rules). To see the cap effect,
rem   add an outbound block rule (M6 WFP work) and make jailbreak-7 hit public.
rem =============================================================================
setlocal
cd /d %~dp0

set BUILD_DIR=build_m0
set CFG=Debug

if "%~1"=="" (
    set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe
) else (
    set TARGET=%~1
)

echo === Launching M2 sandbox (with internetClient cap): %TARGET% ===
%BUILD_DIR%\%CFG%\m2_demo.exe --net "%TARGET%" --once
echo.
echo === m2_demo exit code = %ERRORLEVEL% ===
pause
