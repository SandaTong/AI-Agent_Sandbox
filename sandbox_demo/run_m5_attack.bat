@echo off
rem =============================================================================
rem run_m5_attack.bat - M5 攻防对照【防御全开 + 主动攻击】⭐ 最有说服力的一组
rem
rem broker 开满反注入 mitigation，然后用 M4 的 injector 主动注入 sandbox_hook.dll。
rem
rem ⭐ 期望现象（broker 侧）：
rem   【攻击】用 injector 尝试注入 ...sandbox_hook.dll ……
rem   【攻击被挡】注入失败: ... —— 反注入 mitigation 生效。这是预期结果。
rem     （通常是远程 LoadLibraryW 被 BLOCK_NON_MICROSOFT_BINARIES 拦，返回 NULL；
rem      或改内存被 PROHIBIT_DYNAMIC_CODE 拦）
rem 期望现象（target 侧 [selfcheck]）：
rem   仍然"干净"——因为注入根本没进来，内核第一道防线就挡住了。
rem
rem 对照 run_m4.bat：同样的 injector，M4 关了防御能得手，M5 开了防御被挡。
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === M5 攻防对照：防御全开 + 主动注入（应被内核挡下）===
%BUILD_DIR%\%CFG%\m5_demo.exe --attack "%TARGET%" --selfcheck
echo.
echo === m5_demo exit code = %ERRORLEVEL% ===
pause
