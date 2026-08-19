# AI-Agent Sandbox（Windows 原生进程级沙箱）

> 一个专门用来**关 AI Agent 的 Windows 原生进程沙箱**：把"行为不可预测、却握着你数据和执行权的 agent 进程"关进 **Job（资源）+ Token/IL（权限）+ Mitigation（能力）+ WFP/DNS（网络）+ 文件 Broker/Minifilter（数据）** 多层围栏。
>
> 核心假设：**不赌"模型不作恶"，只在 OS 层把"作恶的爆炸半径"限制死**（defense-in-depth）。
>
> 从 Windows 内核对象机制出发，逐 milestone（M0~M9）搭建，用户态一路做到内核 Minifilter 驱动。既是系统底层学习工程，也是 AI Agent 运行时安全底座的原型。

---

## 五层围栏全景

```
        行为不可预测、握着你数据和执行权的 AI Agent 进程
                              │
   ┌──────────────────────────┼──────────────────────────┐
   ▼          ▼               ▼              ▼            ▼
 资源围栏   权限围栏         能力围栏        网络围栏      数据围栏
 (M0/M1)   (M1/M2)         (M1/M5)        (M2/M6/M7)   (M3/M8/M9)
 Job       Token/IL        Mitigation     Firewall     Broker
 CPU/内存  受限token       禁动态代码       WFP AppID    文件代理
 /进程数   /Low IL         /非签名DLL       DNS 域名     /工作区隔离
 /UI       /AppContainer   /禁子进程        /拦loopback  /Minifilter
   │          │               │              │            │
   └──────────┴───────────────┴──────────────┴────────────┘
                              │
              agent 崩了/作恶，爆炸半径被限死在沙箱内
                    （M4/M5 反注入保证沙箱自身不被劫持）
```

> 完整动机与产品落点见 `docs/notes/why_sandbox_for_agent.md`。

---

## Milestone 一览（M0~M9 全部完成）

| M | 主题 | 一句话 | 关键技术 | demo |
|---|---|---|---|---|
| **M0** | 基础闭环 | Job + 受限 token 起 target | `CreateJobObject` / `CreateRestrictedToken` / KILL_ON_JOB_CLOSE | `run.bat` |
| **M1** | 权限+能力收敛 | 降 IL + 8 项 Mitigation + Alt Desktop | Integrity Level / Process Mitigation Policy / WindowStation | `run_m1.bat` |
| **M2** | 命名空间隔离 | AppContainer / LowBox + 防火墙加餐 | AppContainer / Capability SID / INetFwPolicy2 | `run_m2.bat` `run_m2_net.bat` |
| **M3** | Broker IPC | 命名管道 broker/target + DuplicateHandle | Named Pipe / SDDL 授权 / 帧协议 | `run_m3.bat` `run_m3_ac.bat` |
| **M4** | 注入+Hook | 远程线程注入 + MinHook inline hook | LoadLibrary 注入四件套 / trampoline | `run_m4.bat` `run_m4_noil.bat` |
| **M5** | 反注入 | 内核 mitigation + 用户态运行时自检 | LdrRegisterDllNotification / API 完整性 | `run_m5.bat` `run_m5_attack.bat` `run_m5_defenseoff.bat` |
| **M6** | 网络管控（IP） | WFP 按 AppID/IP 拦 outbound（含 loopback） | WFP ALE_AUTH_CONNECT_V4 / AppID | `run_m6.bat` `run_m6_appid.bat` |
| **M7** | 网络管控（域名） | 注入 hook GetAddrInfoW 做域名白名单 | MinHook / DNS 链路 / DoH | `run_m7.bat` `run_m7_ip.bat` |
| **M8** | 文件 Broker | 策略引擎(防TOCTOU+最小权限) + DENY-ACE | GetFinalPathNameByHandle / NTFS DACL | `run_m8.bat` `run_m8_denyacl.bat` |
| **M9** | 内核 Minifilter | IRP 层审计 + 敏感路径拦截 | FltRegisterFilter / IRP_MJ_CREATE / 通信端口 | `install_mf.bat` `run_mf.bat`（需 VM） |

---

## 目录结构

```
sandbox_demo/
  src/
    common/        通用：ScopedHandle / Logger / WinError（header-only）
    core/          沙箱核心库(sandbox_core)：job/token/mitigation/appcontainer/
                   firewall/pipe/injector/self_defense/wfp/file_acl
    demo/          各 milestone 的 demo 主程序 + hello_target(被沙箱化的靶子)
                   + sandbox_hook.dll / dns_hook.dll(注入垫片)
    minifilter/    M9 内核 Minifilter 驱动(WDK 工程，独立编译)
    third_party/   vendored MinHook(M4/M7 用)
  docs/notes/      每个 milestone 的深度笔记 + 横切基础文档
  build.bat        一键 CMake 配置 + 编译(用户态部分)
  run_*.bat        各 milestone 的运行脚本
  run_all.bat      一键跑通 M0~M8 非破坏性 demo 并汇总 PASS/FAIL
  package.bat      打包 release zip
  CMakeLists.txt
```

---

## 快速开始

```bat
:: 1) 编译用户态部分（需 CMake + VS2022）
build.bat

:: 2) 一键回归：顺序跑 M0~M8 非破坏性 demo，看汇总
run_all.bat

:: 3) 单独跑某个 milestone（示例）
run_m6_appid.bat     :: WFP 按 exe 拦全部 outbound（需管理员，脚本自动提权）
run_m8.bat           :: 文件 broker 策略引擎

:: 4) M9 内核 Minifilter（需 WDK 编译 + 在 VM 里加载，勿在主力机跑！）
::    见 src/minifilter/README.md
```

**运行前提**：
- 用户态 demo：Win10/11 x64 + 编译好的 `build_m0/Debug/`。
- M6/M7-ip：需**管理员**（WFP/防火墙），脚本已内置 PowerShell 自动提权。
- M9：需 **WDK 编译 + VM + testsigning**（内核驱动，崩了蓝屏，务必 VM 快照）。

---

## 对应岗位能力（Windows 系统底层 / Agent Sandbox）

| 能力维度 | 本项目覆盖 |
|---|---|
| 权限与安全边界（Token/IL/Job/AppContainer） | M0/M1/M2 |
| 注入与反注入、Hook | M4/M5（MinHook inline hook + 反注入自检） |
| 网络管控（WFP/进程/IP/端口/域名） | M6（WFP）+ M7（DNS hook） |
| 文件系统与访问控制（NTFS/Minifilter/句柄） | M8（DACL/DENY-ACE/句柄代理）+ M9（Minifilter） |
| 内核对象/IRP/对象命名空间 | 贯穿，见 `docs/notes/kernel_objects_101.md` |
| 崩溃/逆向/调试 | WinDbg/livekd/Process Explorer/WinObj（`docs/notes/tools_cheatsheet.md`） |

---

## 文档索引（`docs/notes/`）

- **`why_sandbox_for_agent.md`** ⭐ 工程动机总纲（讲项目先看这篇）
- **`PROJECT_SUMMARY.md`** ⭐ 项目总结：踩坑合集 + 技术决策 + 面试 Q&A 大全
- `M0.md` ~ `M9.md` — 每个 milestone 的完整笔记（原理 + 踩坑 + 实测 + 话术）
- `kernel_objects_101.md` — 横切基础：Object Manager / HANDLE / SeAccessCheck / PEB / 命名管道
- `minhook_trampoline_deepdive.md` — MinHook inline hook 底层深挖
- `sandbox_vs_codex.md` — 本项目 vs OpenAI Codex Sandbox 对比
- `tools_cheatsheet.md` — 调试工具速查
- `reading_plan.md` — 20 天边写边学计划（对齐两本教材）

---

## 免责声明

本项目为**学习/研究用途**。注入、hook、反注入、内核驱动等技术仅用于理解 Windows 安全机制与构建防御性沙箱，请勿用于未授权用途。M9 内核驱动请务必在虚拟机中测试。
