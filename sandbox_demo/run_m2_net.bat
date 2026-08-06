@echo off
rem =============================================================================
rem run_m2_net.bat - M2 沙箱+ internetClient capability
rem
rem ⚠️ 用于演示 broker 侧API：CreateWellKnownSid(WinCapabilityInternetClientSid)
rem     + 把 cap SID 加进 SECURITY_CAPABILITIES::Capabilities[]。
rem
rem 【注意】这份脚本**不会让 jailbreak-7 变化**。原因见 docs/notes/M2.md § 九：
rem
rem   AppContainer 的网络策略分两层：
rem     L1 (回环) —— WFP 内核 AppContainerLoopback 过滤器硬拦，不依赖规则
rem     L2 (公网) —— Windows Firewall 用户态策略引擎，依赖 block 规则
rem
rem   我们 jailbreak-7 打的是回环 127.0.0.1:1，走L1 硬拦，永远 BLOCKED，
rem   跟 internetClient cap 无关（cap 只是 L2 规则的匹配依据）。
rem
rem   想真正看到 cap 白名单效果需要：先程序化加一条 outbound block规则
rem   （M4 做 WFP 时的工作），再改 jailbreak-7 打公网。
rem =============================================================================
setlocal
set BUILD_DIR=build_m0
set CFG=Debug

if "%~1"=="" (
    set TARGET=%BUILD_DIR%\%CFG%\hello_target.exe
) else (
    set TARGET=%~1
)

echo === Launching M2 sandbox (with internetClient cap): %TARGET% ===
echo (jailbreak-7 打的是回环，结果不会因为加 cap 而变化，见 M2.md § 九)
%BUILD_DIR%\%CFG%\m2_demo.exe --net "%TARGET%"
echo.
echo === m2_demo exit code = %ERRORLEVEL% ===
pause
