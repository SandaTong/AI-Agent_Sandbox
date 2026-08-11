@echo off
rem =============================================================================
rem run_m5_defenseoff.bat - M5 对照组【关闭防御 + 主动攻击】= 复现 M4 + 自检兜底
rem
rem broker 关掉反注入 mitigation（等价 M4 场景），然后用 injector 注入。
rem 这次注入会**得手**（和 M4 一样）——但 target 的运行时自检应能**报警**，
rem 证明"内核没挡住时，用户态检测层能兜底发现"。
rem
rem ⭐ 期望现象（broker 侧）：
rem   【攻击得手】注入成功！target 已被植入 hook dll
rem 期望现象（target 侧 [selfcheck]）：
rem   [selfcheck][ALERT][可疑DLL]  白名单外 DLL 被加载: ...sandbox_hook.dll
rem   [selfcheck][ALERT][API被篡改] kernel32!CreateFileW 头字节被改 (E9 jmp rel32) ...
rem   （可能还有[可疑线程]：起点正好是 LoadLibraryW）
rem
rem 这组把"内核挡 vs 用户态查"两层的分工演示得最清楚：
rem   - run_m5_attack.bat（防御开）：内核第一道就挡住，自检干净
rem   - 本脚本（防御关）：注入得手，但自检第二道兜底报警
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug
set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === M5 对照组：关闭防御 + 注入（得手，但自检应报警）===
%BUILD_DIR%\%CFG%\m5_demo.exe --defense-off --attack "%TARGET%" --selfcheck
echo.
echo === m5_demo exit code = %ERRORLEVEL% ===
pause
