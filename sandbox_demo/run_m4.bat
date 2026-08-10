@echo off
rem =============================================================================
rem run_m4.bat - M4 DLL 注入 + API Hook 骨架演示
rem
rem 流程：broker 挂起启动 target → 注入 sandbox_hook.dll（远程线程+LoadLibraryW）
rem       → sandbox_hook 在 DllMain 用 MinHook 钩住 CreateFileW → resume target
rem       → target 后续每次 CreateFileW 都先进我们的钩子
rem
rem ⭐ 观察hook 生效的两个通道：
rem
rem   通道 A（推荐，不受 target IL 限制）：Sysinternals DebugView
rem     - 管理员运行 DebugView，勾 Capture > Capture Win32 / Capture Global Win32
rem     - 能实时看到 [hook] CreateFileW 拦截到: <path>
rem     - Low IL / Medium IL 都能看（OutputDebugStringW 不受文件系统权限限制）
rem
rem   通道 B（文件日志，需 target 有写权限）：%TEMP%\sandbox_hook_log.txt
rem     - ⚠️ target 是 Low IL 时（默认），它对普通 %TEMP% 没写权限，文件日志
rem       可能写不出——这本身是 M1 Low IL 的效果（钩子继承 target 权限，不提权）
rem     - 想看文件日志，用 run_m4_noil.bat（--no-il，target 是 Medium IL）
rem
rem 期望现象（broker 侧）：
rem   [+] Injector: 远程线程已起... 入口=LoadLibraryW
rem   [+] Injector: DLL 注入成功 ...
rem   [+] target 已 Resume
rem 期望现象（DebugView /文件日志）：
rem   [hook] sandbox_hook.dll 已注入并 Hook 住 CreateFileW
rem   [hook] CreateFileW 拦截到: C:\Users\<你>\Desktop\sandbox_jailbreak.txt  <- jailbreak-1
rem   [hook] CreateFileW 拦截到: CONOUT$ 等
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug

set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === Launching M4 broker + inject hook dll: %TARGET% ===
echo === 用 DebugView 看 [hook] 日志（Low IL 文件日志可能写不出，属正常）===
%BUILD_DIR%\%CFG%\m4_demo.exe "%TARGET%"
echo.
echo === m4_demo exit code = %ERRORLEVEL% ===
pause
