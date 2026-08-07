@echo off
rem =============================================================================
rem run_m3.bat - M3 Broker/Target IPC 骨架演示
rem
rem 前置准备（首次运行前执行一次）：
rem   mkdir C:\sandbox_share
rem   echo hello-from-broker> C:\sandbox_share\hello.txt
rem
rem 期望现象：
rem   [+] PipeServer: 管道已就绪 \\.\pipe\wemeet_sandbox_m3_ipc
rem   [+] PipeServer: target 已连接
rem   [+] PipeServer: 收到 Ping，回 Pong
rem   [+] PipeServer: 已代劳打开 C:\sandbox_share\hello.txt 并 DuplicateHandle ...
rem   [!] PipeServer: 拒绝打开越权路径: C:\Windows\System32\drivers\etc\hosts
rem   target 侧:
rem     [ipc] Ping -> Pong OK
rem     [ipc] 打开 C:\sandbox_share\hello.txt -> OK (broker 代劳)，ReadFile 成功，读到 N 字节
rem     [ipc] 打开 ...\hosts -> BLOCKED（broker 策略拒绝，越权路径）
rem
rem 说明：
rem   * 默认不带 --ac（先验证纯 IPC 骨架，target 是 Low IL + Mitigation）
rem   * 想叠加 AppContainer + 管道 SD 授权 Package SID，跑 run_m3_ac.bat
rem   * target 跑完 IPC 演示会进入心跳循环，手动关闭 target 窗口即可结束
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug

set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === Launching M3 broker + target(IPC): %TARGET% ===
%BUILD_DIR%\%CFG%\m3_demo.exe "%TARGET%" --ipc
echo.
echo === m3_demo exit code = %ERRORLEVEL% ===
pause
