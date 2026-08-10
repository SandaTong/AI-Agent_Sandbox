@echo off
rem =============================================================================
rem run_m4_noil.bat - M4 注入 + Hook，target 用 Medium IL（--no-il）
rem
rem 和 run_m4.bat 的唯一区别：加--no-il，让 target 是 Medium IL。
rem 这样 target 对 %TEMP% 有写权限，hook 的文件日志能落盘，方便直接看文件
rem （不用装 DebugView）。
rem
rem 看文件日志：%TEMP%\sandbox_hook_log.txt
rem   里面会有 target 调CreateFileW 的完整路径记录，包括 jailbreak-1 写桌面
rem   文件、CONOUT$、jailbreak-4 加载 DLL 时的路径等。
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug

set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === Launching M4 (Medium IL) broker + inject hook dll: %TARGET% ===
echo === hook 文件日志: %%TEMP%%\sandbox_hook_log.txt ===
%BUILD_DIR%\%CFG%\m4_demo.exe --no-il "%TARGET%"
echo.
echo === m4_demo exit code = %ERRORLEVEL% ===
type "%TEMP%\sandbox_hook_log.txt"
pause
