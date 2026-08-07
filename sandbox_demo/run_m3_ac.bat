@echo off
rem =============================================================================
rem run_m3_ac.bat - M3 IPC + AppContainer（管道 SD 授权 Package SID）
rem
rem 这是 M3 最有价值的一组：target 是 AppContainer / LowBox token，broker 建
rem 管道时把 SD 授权了target 的 Package SID（否则 AppContainer target 连管道
rem 会 ACCESS_DENIED）。这一步把 M2 的 AppContainer 和 M3 的 IPC 缝在一起。
rem
rem 前置准备（首次运行前执行一次）：
rem   mkdir C:\sandbox_share
rem   echo hello-from-broker> C:\sandbox_share\hello.txt
rem
rem 期望现象（相比 run_m3.bat 多一行）：
rem   [+] AppContainer: package SID = S-1-15-2-...
rem   [+] PipeServer: 管道 SD 追加授权 AppContainer SID S-1-15-2-...
rem   [+] PipeServer: target 已连接        <- AppContainer target 成功连上（授权生效）
rem   ...（Ping/OpenFile 结果同 run_m3.bat）
rem
rem 对照实验：如果把 pipe_server.cc 里授权那段去掉再重编，这里的 target 会
rem 打印 [ipc] 连接 broker 失败: gle=5（ACCESS_DENIED）——那就是"未授权 SID"
rem 的直接证据。
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug

set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe

echo === Launching M3 broker + AppContainer target(IPC): %TARGET% ===
%BUILD_DIR%\%CFG%\m3_demo.exe --ac "%TARGET%" --ipc
echo.
echo === m3_demo exit code = %ERRORLEVEL% ===
pause
