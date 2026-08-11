@echo off
rem =============================================================================
rem run_m5.bat - M5 反注入 + 运行时自检【主场景：防御全开，不主动攻击】
rem
rem broker 开满反注入 mitigation（prohibit_dynamic_code / strict_signed_dll /
rem disable_extension_points），target 带 --selfcheck 自检。
rem
rem 期望现象（target 侧 [selfcheck]）：
rem   [selfcheck] DLL加载监控: 干净，未发现异常
rem   [selfcheck] 全量扫描: 干净，未发现异常
rem 说明没有外来注入、关键 API 未被篡改——这是"防御态基线"。
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === M5 主场景：反注入防御全开，target 自检（应干净）===
%BUILD_DIR%\%CFG%\m5_demo.exe "%TARGET%" --selfcheck
echo.
echo === m5_demo exit code = %ERRORLEVEL% ===
pause
