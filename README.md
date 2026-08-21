# AI-Agent Sandbox （Windows）

> 一个**为 AI Agent 提供安全运行环境**的 Windows 原生进程级沙箱。
> 用现代 C++17 + Win32 底层 API 从零搭建，逐 milestone（**M0~M11 已全部完成**）覆盖**进程管控 / 文件隔离 / 网络管控 / 注入与反注入 / Windows NT 底层机制**五大能力块，用户态一路做到内核 Minifilter 驱动。
>
> 核心假设：**不赌"模型不作恶"，只在 OS 层把"作恶的爆炸半径"限制死**（defense-in-depth）。

---

## 1. 这个工程是什么

一句话：**"给 AI Agent 建一个装了铁笼、装了摄像头、装了红外围栏的沙箱进程"**。

背景：AI Agent（比如可执行任意命令的 Copilot）跑起来时，其行为对用户是**不可预测的**——它可能要读文件、发网络、调命令行、装库、写代码。让这样一个"人格不完全可控"的进程直接跑在用户机器上，**风险等价于让一个陌生人拿着 admin token 登录你的电脑**。

沙箱要做的事：

- **进程管控**：把 Agent 关到Job Object 里，限制 CPU/内存/进程数/UI；用 Low IL Token + AppContainer 剥掉权限；用 Mitigation Policy 让它加载不了非签名 DLL / 起不了子进程 / 分配不了动态代码
- **文件系统隔离**：Agent 只能访问自己的沙盒目录，读系统关键路径要经过 Broker 代理；内核态用 Minifilter 做兜底拦截
- **网络访问控制**：Agent 想联网必须走白名单（进程 + IP + 端口 + 协议 + 域名维度），用户态 WFP 是主战场
- **注入 / 反注入**：Agent 进程自己被反注入保护；Agent 想反过来注入宿主也拦
- **权限收敛与异常隔离**：Access Token / IL / Job / Winstation-Desktop 四层围栏；Agent 崩了不影响 Broker

工程对应的招聘方向：**桌面端Agent Sandbox 研发（Windows 方向）**。

---

## 2. 架构（当前 + 目标态）

### 目标态（20 天后完整版）

```
┌─────────────────────────────────────────────────────────────────┐
│                            Broker.exe                │          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐  │
│  │Policy      │  │File Broker │  │WFP Engine  │  │Anti-Inject│  │
│  │Engine      │  │(user-mode) │  │(netACL)    │  │Detector   │  │
│  └────────────┘  └────────────┘  └────────────┘  └───────────┘  │
│         ▲                                                       │
│         │ Named-Pipe IPC (msg framing)                          │
│         ▼                                                       │
│  ┌───────────────────────────── Target.exe ─────────────────────┐
│  │ Job Object + Low IL + AppContainer + Mitigation + AltDesktop││
│  │       Agent code runs here (LLM tool-use / shell / net)     ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────┬───────────────────────────────┘
                                  │  DeviceIoControl
                                  ▼
                    ┌───────────────────────────┐
                    │ sandbox_flt.sys (kernel)  │
                    │  Minifilter：拦文件 IRP   │
                    └───────────────────────────┘
```

### 当前态（M0~M11 全部完成）

```
┌───────────────────────── broker（各 m*_demo.exe，沙箱外/有权限）─────────────────────────┐
│  策略引擎        文件 Broker         WFP 引擎           反注入检测                          │
│  (M8 白名单)     (M8 代劳+句柄)      (M6 AppID/IP)      (M5 Ldr 通知/线程扫描)              │
│      ▲                ▲  命名管道 IPC（帧协议 + DuplicateHandle，M3）                        │
│      │ 起进程         │  + 注入 dns_hook/sandbox_hook（M4/M7）                              │
│      ▼                ▼                                                                     │
│  ┌──────────────────────────── target.exe（hello_target，沙箱内）────────────────────────┐ │
│  │ Job Object(M0) + Restricted Token/Low IL(M0/M1) + AppContainer(M2)                    │ │
│  │ + 8 项 Mitigation Policy(M1) + Alt WinSta/Desktop(M1)                                 │ │
│  │ 内部跑 9 项越狱测试（jailbreak-1~9），每项对应一层围栏，基线全 SUCCESS→沙箱化后 BLOCKED │ │
│  └──────────────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────┬──────────────────────────────────────────────┘
                                           │  FltMgr 通信端口（策略下发 + 审计上报）
                                           ▼
                         ┌────────────────────────────────────┐
                         │ sandbox_minifilter.sys（内核，M9）   │
                         │  IRP_MJ_CREATE PreCreate：审计 + 拦截 │
                         │  （altitude 370000，STATUS_ACCESS_DENIED）│
                         └────────────────────────────────────┘
```

> 五层围栏：**资源(M0/M1) → 权限(M1/M2) → 能力(M1/M5) → 网络(M2/M6/M7) → 数据(M3/M8/M9)**。
> M4(攻:注入+hook) 与 M5(守:反注入) 互为镜像，保证沙箱自身不被劫持。

---

## 3. Roadmap（20 天 × 11 个 milestone）

| Day | Milestone | 交付物 | JD 命中 | 状态 |
|---|---|---|---|---|
| D1 | **M0** 基础闭环 | Job / Token / CREATE_SUSPENDED 三步舞 | W1 | ✅ 完成 |
| D2-3 | **M1** 进程加固 | Low IL + STARTUPINFOEX + 8 项 Mitigation Policy + Alternate Desktop | W1 | ✅ 完成 |
| D4-5 | **M2** 现代沙箱 | AppContainer / LowBox Token + Capability SID | W1 | ✅ 完成 |
| D6 | **M3** Broker/Target 双进程 + Named-Pipe IPC | 拆成 `broker.exe` + `target.exe` | W1/W5 | ✅ 完成 |
| D7-8 | **M4** 注入与 Hook（正向） | `injector.exe` + MinHook 拦截 `CreateFileW` | W4 | ✅ 完成 |
| D9 | **M5** 反注入与运行时检测 | `LdrRegisterDllNotification` + 模块白名单 + 远程线程检测 | W4 | ✅ 完成 |
| D10-12 | **M6** WFP 网络管控 | 用户态 WFP：进程 + IP + 端口 + 协议 白/黑名单（AppID 形态拦 loopback） | W3 | ✅ 完成 |
| D13 | **M7** 域名维度控制 | 注入 dns_hook.dll 钩 GetAddrInfoW 做域名白名单 + DNS→IP 联动 WFP | W3 | ✅ 完成 |
| D14-15 | **M8** 用户态文件隔离 | 文件 Broker 策略引擎（防 TOCTOU + 最小权限句柄）+ NTFS DENY-ACE | W2 | ✅ 完成 |
| D16-18 | **M9** 内核 Minifilter | `sandbox_minifilter.sys` IRP_MJ_CREATE 审计 + 敏感路径拦截 + 通信端口下发策略 | W2 | ✅ 完成 |
| D19 | **M10** 越狱测试 + 一键回归 | hello_target 9 项越狱测试 + `run_all.bat` 汇总 PASS/FAIL | 全部 | ✅ 完成 |
| D20 | **M11** 交付打包 | 顶层 README + `PROJECT_SUMMARY.md` + `package.bat` release zip | 全部 | ✅ 完成 |

**JD 能力块编号**：
- W1 = 进程管控（Job / Token / IL / AppContainer / PP-PPL / Mitigation）
- W2 = 文件系统隔离（NTFS ACL / Minifilter / 对象命名空间 / 句柄 ACL）
- W3 = 网络访问控制（WFP / LSP / NSP / NDIS / TDI，进程/协议/IP/端口/域名维度）
- W4 = 注入与反注入 / Hook（远程线程、APC、IAT / Inline / MinHook）
- W5 = Windows NT 底层原理（PE / 对象管理 / 异常分发 / ALPC / COM）

---

## 4. 目录结构（M0~M11 完整态）

```
sandbox_demo/
├─ CMakeLists.txt           顶层 CMake：分层子目标 + MSVC 硬化选项
├─ build.bat                一键编译（用户态部分 → build_m0/）
├─ run_*.bat                各 milestone 运行脚本（M6/M7-ip 自动提权）
├─ run_all.bat              一键回归：顺序跑 M0~M8 非破坏性 demo 汇总 PASS/FAIL
├─ package.bat              打包 release zip（exe/dll/sys/脚本/docs）
├─ install_mf.bat / run_mf.bat / uninstall_mf.bat   M9 Minifilter 加载/运行/卸载（VM）
├─ src/
│  ├─ common/               无状态工具（header-only）
│  │  ├─ scoped_handle.h    RAII HANDLE 封装
│  │  ├─ win_error.h        GetLastError → std::error_code
│  │  └─ logger.h           线程安全宽字符 logger
│  ├─ core/                 沙箱核心库 sandbox_core
│  │  ├─ job_manager.{h,cc}       Job Object（W1，M0）
│  │  ├─ token_manager.{h,cc}     Restricted Token + Low IL（W1，M0/M1）
│  │  ├─ mitigation.{h,cc}        STARTUPINFOEX + Mitigation Policy（W1，M1）
│  │  ├─ desktop_iso.{h,cc}       Alternate WinStation+Desktop（W1，M1）
│  │  ├─ appcontainer.{h,cc}      AppContainer/LowBox Token（W1，M2）
│  │  ├─ firewall.{h,cc}          INetFwPolicy2 防火墙规则（W3，M2 加餐）
│  │  ├─ pipe_server/client.{h,cc}  命名管道 IPC + 帧协议（W5，M3/M8）
│  │  ├─ injector.{h,cc}          远程线程 DLL 注入（W4，M4/M7）
│  │  ├─ self_defense.{h,cc}      运行时反注入自检（W4，M5）
│  │  ├─ wfp_*.{h,cc}             WFP 网络过滤（W3，M6）
│  │  ├─ file_acl.{h,cc}          NTFS DACL DENY-ACE（W2，M8）
│  │  └─ process_launcher.{h,cc}  串接所有围栏
│  ├─ demo/
│  │  ├─ hello_target.cc          被沙箱化的通用靶子（9 项越狱测试 + --ipc/--selfcheck/--once）
│  │  ├─ m0_demo.cc ~ m8_denyacl_demo.cc   各 milestone demo 主程序
│  │  ├─ sandbox_hook.cc          M4 注入垫片（hook CreateFileW）
│  │  └─ dns_hook.cc              M7 注入垫片（hook GetAddrInfoW）
│  ├─ minifilter/            M9 内核 Minifilter（WDK 工程，独立编译）
│  │  ├─ sandbox_minifilter.c/.inf/.vcxproj   驱动本体
│  │  ├─ mf_protocol.h            内核↔用户共享协议
│  │  ├─ mf_ctl.cc                用户态控制程序（连端口/下发策略/收审计）
│  │  └─ README.md                编译 + 加载步骤（含踩坑）
│  └─ third_party/           vendored MinHook（M4/M7 用）
└─ docs/notes/               每个 milestone 深度笔记 + 横切基础文档
```

---

## 5. 编译与运行

### 环境要求
- **OS**：Windows 10 1709+ / Windows 11（后续 milestone 用到的 Mitigation Policy 需要）
- **VS**：Visual Studio 2022（含 C++桌面负载）
- **SDK**：Windows 10 SDK 26100 或 22621（`_WIN32_WINNT=0x0A00` 生效）
- **CMake**：3.20+
- **WDK**（可选，M9 内核 Minifilter 用）：与 SDK 主版本一致的 WDK for 24H2

### 编译

```bat
::一键编译（生成到 build_m0/ 目录）
build.bat
```

或手动：
```bat
cmake -S . -B build_m0 -A x64
cmake --build build_m0 --config Debug
```

### 运行

```bat
:: 一键回归：顺序跑 M0~M8 全部非破坏性 demo（--once 跑完即退），汇总 PASS/FAIL
run_all.bat

:: 单独跑某个 milestone（示例）
run.bat                :: M0：用最小沙箱拉起 notepad
run_m1.bat             :: M1：Low IL + Mitigation + Alt Desktop
run_m6_appid.bat       :: M6：WFP 按 exe 拦全部 outbound（需管理员，脚本自动提权）
run_m8.bat             :: M8：文件 broker 策略引擎
run_m8_denyacl.bat     :: M8：DENY-ACE 从外部剥夺写权限

:: M9 内核 Minifilter（需 WDK 编译 + 在 VM 里加载，勿在主力机跑！见 src/minifilter/README.md）
install_mf.bat → run_mf.bat → uninstall_mf.bat

:: 打包可分发的 release zip
package.bat
```

预期输出（M0 示例）：
```
[+] JobManager: job created. process_limit=4 mem_limit_mb=256 cpu_rate=20%
[+] TokenManager: restricted token created (all privileges removed)
[+] ProcessLauncher: pid=xxxxx tid=xxxxx image=C:\Windows\System32\notepad.exe
[+] Target exited with code=0
```

---

## 6. 各Milestone 说明

### ✅ M0 — 基础闭环 Job + Token + CREATE_SUSPENDED

**能干什么**：把一个 exe 关进 Job Object（限 4 进程 / 每进程 256 MB / CPU 硬上限 20% / UI 全锁），用一个"所有 privilege 都 disable"的 restricted token 启动它，并保证限制在目标进程执行第一行指令之前就已经生效。

**关键 API**：`CreateJobObjectW` / `SetInformationJobObject` × 3 info-class / `AssignProcessToJobObject` / `OpenProcessToken` / `CreateRestrictedToken` / `CreateProcessAsUserW` + `CREATE_SUSPENDED` / `ResumeThread`。

**修的3 个硬伤**：
1.去掉 `JOB_OBJECT_LIMIT_BREAKAWAY_OK`（这个 flag 是**允许**target 逃出 job，语义完全反了），改为 `KILL_ON_JOB_CLOSE` + `DIE_ON_UNHANDLED_EXCEPTION`
2. 两次 `SetInformationJobObject(ExtendedLimit)` 覆盖问题合并成一次
3. `CreateProcess` 加 `CREATE_SUSPENDED` → assign to job → resume（原代码是先跑后 assign，有时间窗漏洞）

**面试锚点**：见 [`docs/notes/M0.md`](sandbox_demo/docs/notes/M0.md)。

### ✅ M1 — 进程加固：Low IL + Mitigation Policy + Alternate Desktop

**在 M0 基础上叠加的三层护栏**：

1. **Low Integrity Level** — 用 `SetTokenInformation(TokenIntegrityLevel)` 把 target 的 Mandatory Label 改成 `S-1-16-4096`。降完后 target 想写你桌面上的文件返回 `ACCESS_DENIED`（NTFS mandatory label ACE 一票否决）。
2. **STARTUPINFOEX + 8 项 Mitigation Policy**：
   - DEP + 强 ASLR + Force Relocate
   - `BLOCK_NON_MICROSOFT_BINARIES` —— 只允许微软签名的 DLL 加载（**反注入绝杀**）
   - `PROHIBIT_DYNAMIC_CODE` —— 禁 JIT / shellcode
   - `EXTENSION_POINT_DISABLE` —— 拦 AppInit_DLLs / SetWindowsHookEx 全局钩子
   - `IMAGE_LOAD_NO_REMOTE` / `NO_LOW_LABEL`
   - **独立槽位**：`CHILD_PROCESS_RESTRICTED` —— 禁 target 起子进程
3. **Alternate WindowStation + Desktop** — `CreateWindowStation` + `CreateDesktop` 造一对独立 winsta/desktop（SDDL显式带 DACL + Mandatory Label = Low），target 通过 `STARTUPINFO::lpDesktop` 被塞进去；`EnumWindows` 出来看不到用户桌面的窗口。

**新增关键 API**：`SetTokenInformation` / `ConvertStringSidToSidW` / `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` / `CreateWindowStationW` / `CreateDesktopW` / `ConvertStringSecurityDescriptorToSecurityDescriptorW` / `STARTUPINFOEX::lpAttributeList`。

#### M1 越狱测试实测结果

| # | 越狱动作 | baseline | M0 | **M1** | M1 拦截机制 |
|---|---|---|---|---|---|
| 1 | 写用户桌面文件 | SUCCESS | SUCCESS | **BLOCKED (gle=5)** | Low IL / NTFS mandatory ACE |
| 2 | `CreateProcess("cmd.exe")` | SUCCESS | SUCCESS | **BLOCKED (gle=367)** | `CHILD_PROCESS_POLICY` |
| 3 | `VirtualAlloc(RWX)` | SUCCESS | SUCCESS | **BLOCKED (gle=1655)** | `PROHIBIT_DYNAMIC_CODE` |
| 4 | 加载非签名 DLL | SUCCESS | SUCCESS | **BLOCKED (gle=577)** ⭐ | `BLOCK_NON_MICROSOFT_BINARIES` |
| 5 | 读剪贴板 | SUCCESS | SUCCESS | **BLOCKED (gle=5)** | Job `UILIMIT_READCLIPBOARD` |

**M0 拦 0/5，M1 拦 5/5**。gle=577 (ERROR_INVALID_IMAGE_HASH) 是 mitigation policy 生效的**内核层证据**——内核在 Authenticode 校验路径把 DLL 拒了，不是 API 层伪拦。

#### M1 踩坑精华（4 个 `0xC0000142`）

M1 让 target 稳定起来一路踩了 4 个坑，每一个都是 Windows 沙箱工程师的必修课：

1. **`BLOCK_NON_MICROSOFT_BINARIES` 拦 Debug CRT** —— Debug CRT DLL是微软发布但不带微软根签名，被 mitigation 拒。修：target 静态链接 CRT（`/MTd`）
2. **`SetSecurityInfo` 缺 `WRITE_DAC`** —— `WINSTA_ALL_ACCESS` 不含 `WRITE_DAC`。修：Create 时通过 `SECURITY_ATTRIBUTES` 一次到位
3. **Job UI 限制 vs Alt Desktop冲突** —— `NtUserOpenDesktop` 被 `UILIMIT_DESKTOP` 拦。修：Alt Desktop 场景下清掉 Job UI 限制的 DESKTOP + HANDLES 位
4. **Mandatory Label 阻断 Low IL 进 desktop** —— Windows 访问检查是"DACL AND Mandatory Label"双门。修：SDDL 里加 `S:(ML;;;;;LW)` 把 desktop 完整性门槛降到 Low

详见 [`docs/notes/M1.md`](sandbox_demo/docs/notes/M1.md)第七节（含 4 条金牌面试话术）。

**运行**：`run_m1.bat`，或 `.\build_m0\Debug\m1_demo.exe [--strict N] [--no-il] [--no-desk] <target.exe>`

### ✅ M2 — AppContainer / LowBox Token（Chromium renderer 级隔离）

**在 M1 基础上把 target塞进 AppContainer**——独立 Package SID + 独立命名空间 + Capability 白名单。这是 Windows 用户态沙箱的顶配（UWP / Edge renderer / Windows Sandbox 都是这一套）。

三件套：

1. **AppContainer Profile**（`CreateAppContainerProfile`）—— 系统级注册，产出独一无二的 **Package SID**（`S-1-15-2-...`）
2. **独立对象命名空间** —— target 看到的 `\BaseNamedObjects\` 实际映射到 `\Sessions\<n>\AppContainerNamedObjects\<pkg_sid>\`，看不到 global 对象
3. **Capability 白名单** —— 默认几乎啥都做不了；显式带 `internetClient` 才有网、带 `documentsLibrary` 才能读用户 Documents

**关键 API**：`CreateAppContainerProfile` / `DeriveAppContainerSidFromAppContainerName` / `CreateWellKnownSid(WinCapability*)` / `SECURITY_CAPABILITIES` / `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`。

#### M2 越狱测试实测结果（对比 M1）

| # | 越狱动作 | M1 结果 | **M2 结果** | 更早/更硬的原因 |
|---|---|---|---|---|
| 1 | 写用户桌面文件 | BLOCKED gle=5 | **BLOCKED gle=5** | 相同 |
| 2 | 起子进程 | BLOCKED gle=367 | **BLOCKED gle=367** | 相同 |
| 3 | RWX 内存 | BLOCKED gle=1655 | **BLOCKED gle=1655** | 相同 |
| 4 | 加载非签名 DLL | BLOCKED gle=577 (mitigation 层) | **BLOCKED gle=5 (NTFS 层)** ⭐ | Package SID 对文件无读权限，更早一层拦下 |
| 5 | 读剪贴板 | GetClipboardData 拦 | **连 OpenClipboard 都拦** ⭐ | 主体不属于 winsta 剪贴板 ACL |
| 6 | 打开 broker 造的 global mutex | **SUCCESS**（共享 BaseNamedObjects 能看到 broker 的对象） | **BLOCKED gle=2** ⭐⭐ | **broker 明明造了，target 看不到**——独立命名空间 |
| 7 | TCP loopback 127.0.0.1:1 | SUCCESS（M1 完全不禁网） | **SUCCESS (10061)** ⚠️ | **AppContainer 单靠自身不禁网**——需 broker 主动往 Firewall 写规则，见 M2.md § 九 |

**gle=2 (FILE_NOT_FOUND)** 是 AppContainer 命名空间隔离的招牌——不是"拒绝访问"，而是"目标对象在你的命名空间里根本不存在"。

**jailbreak-7 反直觉的实测结论**：M2 单独存在时**根本没禁网**。`AppContainerLoopback` 内核过滤器只拦入方向；出方向完全走 Windows Firewall 用户态规则表，而 `CreateAppContainerProfile` 只落地 Registry 不会自动写防火墙规则（UWP 通过 `Add-AppxPackage` 部署时框架才自动写）。生产级实现要 broker 程序化调 `INetFwPolicy2` 补齐规则——**这一步是 M2 加餐补丁做的事**（Chromium sandbox 同做法）。

#### M2 关键坑（3 个亲踩记录）

- **AppContainer + 手工 alt desktop 冲突** → M2 默认关掉 alt desktop（AppContainer 自带 UI 命名空间隔离）
- **`BLOCK_NON_MICROSOFT_BINARIES` 干扰 winsock helper** → M2 关掉这项mitigation（AppContainer 已提供更早一层的拦截）
- **AppContainer 不等于自动禁网** ⭐ → capability 只是防火墙规则的匹配标签，规则本身要 broker 主动写；见加餐补丁 `core/firewall.{h,cc}`

详见 [`docs/notes/M2.md`](sandbox_demo/docs/notes/M2.md)（含 5 条金牌面试话术）。

**运行**：`run_m2.bat` / `run_m2_net.bat`；或 `.\build_m0\Debug\m2_demo.exe [--net] [--strict N] [--no-il] [--desk] <target.exe>`。

### ✅ M3 — Broker/Target Named-Pipe IPC 骨架

**沙箱从"单机护栏"进化到"工程化沙箱"的关键一步**。M0~M2 把target 关进笼子，笼子越严target 越什么都干不了——真实 renderer 的敏感操作必须**委托 broker 代劳**。M3 建立这条委托通道。

```
target（沙箱内，无权限）  --IPC 请求-->  broker（沙箱外，有权限）
                                          ├ 策略检查（白名单）← 安全决策点
                                          ├ 代劳 CreateFileW
                                          └ DuplicateHandle 交还句柄
target <--句柄值--  可直接 ReadFile 使用
```

三个技术支柱：

1. **命名管道（消息模式）** — `CreateNamedPipeW(PIPE_TYPE_MESSAGE)` + SDDL 授权，一次 ReadFile 拿一整条消息
2. **DuplicateHandle 跨进程句柄传递** — HANDLE 是进程私有的 handle table 索引，不能直接传数值，必须让内核在 target 的 handle table 里新建表项
3. **边界安全** — 把 target 当恶意输入：magic/version 校验、payload 硬上限 64KB 防 DoS、路径白名单 + 拒 `..` 穿越、不透传 Win32 gle

#### M3 实测（broker + target 交错日志）

```
[+] PipeServer: target 已连接
  [ipc] Ping -> Pong OK                ← 双向通信闭环
[+] PipeServer: 已代劳打开 C:\sandbox_share\hello.txt ... (dup=360)
  [ipc] 打开 hello.txt -> OK (broker 代劳)，ReadFile 读到 30 字节   ← ⭐ 句柄传递成功
[!] PipeServer: 拒绝打开越权路径: ...\etc\hosts
  [ipc] 打开 hosts -> BLOCKED（broker 策略拒绝）                    ← ⭐ 白名单生效
```

`dup=360` + target 读到 30 字节（= hello.txt 大小）= **DuplicateHandle 跨进程句柄传递铁证**。

#### M3 关键坑：命名管道 SDDL 的"双门"（复用 M1 坑 #4）

Low IL target 连管道被 `ACCESS_DENIED (gle=5)`。根因是**双层门**：① 显式写 DACL 后无默认创建者授权，Low IL 普通 token 不匹配任何 ACE；② 管道默认继承创建者 Medium IL 的 mandatory label，Low IL `NoWriteUp` 被拒。修法：DACL 加目标主体授权 + SACL加 `(ML;;NW;;;LW)` 降低完整性门槛。**这正是 M1 桌面隔离时理解的"Windows 访问检查 = DACL AND Mandatory Label 双门"在管道对象上的再现**。

带 `--ac` 时 broker 把管道 SDDL 追加 `(A;;GA;;;<PackageSid>)` 授权 AppContainer target——**M2 AppContainer 与 M3 IPC 的缝合点**。

详见 [`docs/notes/M3.md`](sandbox_demo/docs/notes/M3.md)（4 条金牌面试话术）。

**运行**（先`mkdir C:\sandbox_share` 且放一个 `hello.txt`）：`run_m3.bat`（纯 IPC）/ `run_m3_ac.bat`（IPC + AppContainer）；或 `.\build_m0\Debug\m3_demo.exe [--ac] [--strict N] [--no-il] <target.exe> --ipc`。

### ✅ M4 — DLL 注入 + API Hook（精简版骨架）

**从"沙箱设计者"切到"往target 植入拦截垫片"视角**。broker 主动往 target 注入一个 DLL，DLL 在 target 内部用 MinHook 钩住敏感 API（CreateFileW），把调用重定向到拦截逻辑。**注入在沙箱里不是攻击，是 Chromium sandbox 式的 interception——target 无感知地被拦截转发**。这是 M3 IPC 的自然延伸（M3 target 主动请代劳，M4 被hook 后自动交出调用）。

远程线程注入四件套：

1. `VirtualAllocEx` 在 target 地址空间分配内存
2. `WriteProcessMemory` 写入 DLL 路径字符串
3. `GetProcAddress(kernel32, "LoadLibraryW")` —— kernel32 同 session 基址一致，broker 取的地址在 target 有效
4. `CreateRemoteThread`(入口=LoadLibraryW, 参数=路径地址) —— 借 target 线程加载 DLL

Hook 用 **MinHook**（vendored 到 `src/third_party/minhook`）做 Inline Hook。

#### M4 实测

- **注入成功硬证据**：`(Get-Process hello_target).Modules` 里出现 `sandbox_hook.dll`
- **Hook 生效硬证据**：钩子拦到 jailbreak-1 的真实路径 `[hook] CreateFileW 拦截到: C:\Users\<你>\Desktop\sandbox_jailbreak.txt`

#### M4 关键坑：注入的 hook 垫片"继承 target 权限，不提权"

Low IL target 下，注入成功、hook 装上了，但钩子里写文件日志到Medium IL 目录**写不出**（ACCESS_DENIED）。根因：**钩子改内存/拦函数不受 IL 限制，但钩子里发起的系统调用仍以 target 身份和 IL 走完整访问检查**。想让被 hook 的操作越权，只能转发给权限更高的 broker 代劳——**这反过来印证了沙箱 IPC 的必要性**。日志因此改用 `OutputDebugStringW`（不受文件系统 IL 限制，DebugView 可看）。

另一个坑：**强 mitigation 与运行时注入天然冲突**（`PROHIBIT_DYNAMIC_CODE` 拦 Inline Hook 改内存、`BLOCK_NON_MICROSOFT_BINARIES` 拦加载未签名 hook dll）——精简版为演示注入骨架关掉了这两项。

详见 [`docs/notes/M4.md`](sandbox_demo/docs/notes/M4.md)（5 条金牌面试话术）。

**运行**：`run_m4.bat`（Low IL，用 DebugView 看 hook 日志）/ `run_m4_noil.bat`（Medium IL，文件日志可落盘）；或 `.\build_m0\Debug\m4_demo.exe [--strict N] [--no-il] <target.exe>`。

### ✅ M5 — 反注入 + 运行时检测（防御双层：内核挡 + 用户态查）

**M4 的镜像面**。M4 做"攻"（注入 + hook），M5 做"守"——怎么让别人别想注入我 / 篡改我。核心洞见：**反注入是两层配合，不是一层**。

```
有人想注入 target
   ├─ 第一层 内核护栏（Mitigation Policy）：从进程创建绑在 EPROCESS，无法绕过 → 注入进不来（拦）
   └─ 第二层 用户态自检（target 自己查自己）：内核挡不住/开不满时兜底 → 注入进来也能发现（报）
```

**第一层 反注入 mitigation**（broker 侧，M1 就有的 policy 位，正面用于反注入语义）：

| Mitigation 位 | 防的注入手法 |
|---|---|
| `BLOCK_NON_MICROSOFT_BINARIES` | 远程线程 LoadLibrary 注入未签名 dll（M4 那种，主力拦截） |
| `PROHIBIT_DYNAMIC_CODE` | inline hook 改 API 机器码 / RWX shellcode |
| `DISABLE_EXTENSION_POINTS` | AppInit_DLLs / SetWindowsHookEx 全局钩子注入 |

**第二层 用户态运行时自检**（`core/self_defense.{h,cc}`，跑在 target 内部）：

1. **`LdrRegisterDllNotification`** — 实时抓 DLL 加载事件，白名单外的 DLL 加载即告警（比轮询模块列表无窗口期）
2. **可疑远程线程扫描** — 枚举线程起始地址，起点是 `LoadLibraryW` 或落在裸内存的判为可疑
3. **关键 API inline-hook 自检** — 读 `CreateFileW` 头字节，被改成 `jmp`（E9/FF25/48B8…）即疑似被 hook

#### M5 实测：用 M4 injector 做攻防对照（硬证据）

同一套 M4 远程线程注入器，开/关反注入 mitigation 结果相反：

```
[防御ON+攻击]  sandbox_hook 注入进 target?  False   ← ⭐ BLOCK_NON_MICROSOFT_BINARIES 挡住
[防御OFF+攻击] sandbox_hook 注入进 target?  True    ← 关掉防御，注入得手（复现 M4）
```

`run_m5_defenseoff.bat`（注入得手）时 target 自检三条告警全命中（DebugView 可见）：可疑 DLL + API 被篡改（E9 jmp）+ 可疑线程（起点=LoadLibraryW）——**内核没挡住时用户态兜底发现**。

#### M5 关键点：攻防同源

M4 为了能注入，特意关掉 `PROHIBIT_DYNAMIC_CODE` / `BLOCK_NON_MICROSOFT_BINARIES`——**这恰恰说明它们本质就是"内核级反注入"**。M5 第一层不用新造，把 M4 关掉的正面开回来即是。攻和防是同一套机制的两面。

详见 [`docs/notes/M5.md`](sandbox_demo/docs/notes/M5.md)（5 条金牌面试话术）。

**运行**：`run_m5.bat`（防御全开基线）/ `run_m5_attack.bat`（防御全开 + 注入，应被挡）/ `run_m5_defenseoff.bat`（关防御 + 注入，得手但自检报警）；或 `.\build_m0\Debug\m5_demo.exe [--defense-off] [--attack] [--no-il] <target.exe> --selfcheck`。

### ✅ M6 — WFP 用户态网络管控（按进程 / 按远程 IP 拦 outbound）

用 **WFP（Windows Filtering Platform）** 在 `ALE_AUTH_CONNECT_V4` 层加**纯用户态 filter**，比 M2 的 Windows Firewall 更底层、更精确，并**补上 M2 § 九留的 loopback 债**。DYNAMIC 会话，进程退出由 BFE 自动清理，不留残留。

**两种形态（各一个 demo）**：

| 形态 | demo | 匹配条件 | 实测 |
|---|---|---|---|
| **AppID 精确拦** ⭐ | `m6_appid_demo.cc` | `ALE_APP_ID`（exe 路径） | ✅ target 全部 outbound 三行全 BLOCKED，**连 127.0.0.1 loopback 都拦**（`WSAErr=10013`）—— 还清 M2 loopback 债 |
| IP 黑名单 | `m6_demo.cc` | `IP_REMOTE_ADDRESS` | ⚠️ filter 装配完全正确（netsh 可见 `8.8.8.8/32`）但本机纯用户态该层 IP 条件**不命中** |

**为什么 WFP 能拦 loopback 而 Firewall 不能**：Firewall 是 WFP 的上层应用且对 loopback 默认 bypass；WFP 直接挂 ALE 连接授权层，loopback 也经过该层。

**M6 最硬的坑（IP 精确匹配不命中）**：`IP_REMOTE_ADDRESS` 的 UINT32/ADDR_MASK × 主机序/网络序四种组合全试尽都不命中；用 `M6_BLOCK_ALL` 无条件 BLOCK 做对照三行全拦，**定性证明**——本会话裸 BLOCK 有效、AppID 条件有效、唯独 IP 条件在 `connect()` 授权瞬间求值被环境仲裁短路，属 WFP 分层语义 + 本机环境层面，纯用户态改不动，要稳需内核态 callout。附带两个工程坑：① netsh 显示按主机序反解，"显示对≠运行时匹配对"；② exe 被残留进程占用致 `LNK1168` 静默未更新（跑的还是旧 exe）。

详见 [`docs/notes/M6.md`](sandbox_demo/docs/notes/M6.md)。

**运行**（需管理员权限）：`run_m6_appid.bat`（AppID 形态，三行应全 BLOCKED）/ `run_m6.bat`（IP 黑名单，本机 IP 条件不命中）。

### ✅ M7 — DNS 域名维度管控（网络管控从 IP 升到域名）

M6 的 WFP 只看得到 IP，看不到域名。agent 场景真正想说的是"只准连 `api.openai.com`"——域名管控必须在 **DNS 解析环节**做。M7 复用 M4 的注入 + MinHook 骨架，把 hook 点从 `CreateFileW` 换成 **`ws2_32!GetAddrInfoW`**，做域名白名单。

```
m7_demo → 注入 dns_hook.dll → 在 target 内 hook GetAddrInfoW
  · 白名单内域名 → 放行（正常解析出 IP）
  · 白名单外域名 → 返回 WSAHOST_NOT_FOUND（拿不到 IP，连不上）
```

**为什么 hook 而非 WFP 拦 :53**：域名解析走进程外 dnscache 服务，WFP 在 :53 报文看到的源是 svchost 而非 target，区分不了进程；进程内 hook 才能拿明文域名 + 区分进程 + 挡 DoH。

**两种形态**：

| 形态 | demo | 做法 | 实测 |
|---|---|---|---|
| **A 域名白名单 Hook** ⭐ | `m7_demo` + `dns_hook.dll` | 进程内 hook `GetAddrInfoW` | ✅ `example.com`(白名单内)放行、`www.bing.com`(白名单外)被 `WSAHOST_NOT_FOUND`(11001) 拦 |
| C DNS→IP 联动 WFP | `m7_ip_demo` | broker 解析域名拿 IP + M6 WFP | 演示 hostname+IP 纵深；IP 白名单部分继承 M6"IP 不命中"坑，用 AppID 兜底 |

**白名单传递零改 core**：broker `SetEnvironmentVariableW(M7_DNS_ALLOWLIST)`，子进程继承环境块，注入的 DLL 在 DllMain 读。

详见 [`docs/notes/M7.md`](sandbox_demo/docs/notes/M7.md)。

**运行**：`run_m7.bat`（形态 A，看 target 的 jailbreak-8 两行 + DebugView/`%TEMP%\dns_hook_log.txt`）/ `run_m7_ip.bat`（形态 C，需管理员）。

### ✅ M8 — 用户态文件 Broker（策略引擎 + DENY-ACE 双路线）

**把 M3 那个"单目录只读"的文件 broker 骨架升级成生产级**，并演示与之互补的第二条路线。对应 JD 的"敏感路径隔离 / 文件读写审计 / 权限收敛"。

**形态 A — 文件 Broker 策略引擎增强**（在 M3 骨架上补齐四点）：

1. **多规则白名单读写分离** — `FilePolicyRule{dir_prefix, allow_write}`，只读目录 vs 可写目录；命中规则后再判 access 维度（`kDenied` 越权 vs `kAccessNotAllowed` 命中只读规则但请求写）
2. **读/写/创建多操作** — `OpenFileRequest` 加 `access_mode`/`disposition`，协议 version 提到 2 但**向后兼容 M3 v1**（按 body 长度自适应）
3. **防 TOCTOU** ⭐ — 先开句柄再 `GetFinalPathNameByHandleW` 拿"事后真身"（解 symlink/junction/短名/大小写）校验白名单，**校验对象 = 使用对象**
4. **最小权限句柄回传** — DuplicateHandle 按策略最小 access，不再 `DUPLICATE_SAME_ACCESS`

**形态 B — DENY-ACE 从外部剥夺写权限**（互补路线）：broker 起 target 前用 `SetNamedSecurityInfo` 给敏感目录追加针对 target 用户 SID 的 **DENY-WRITE ACE**（含目录+文件继承），target 自己 `CreateFileW(写)` 被内核 DACL 检查一票否决（gle=5）。靠"restricted token 用户 SID 不变"定位 target，析构自动回滚。

#### M8 实测（形态 A 四点全绿）

| 观察点 | target 侧结果 | 验证的增强点 |
|---|---|---|
| 只读目录**读** | `打开 hello.txt -> OK，读到 30 字节` | 白名单命中放行 |
| 越权路径**读** | `BLOCKED（越权路径）` | GetFinalPathNameByHandle 真身校验 |
| 可写目录**写/创建** | `写 -> OK，写入 38 字节` | 读写分离 + 多操作（v2 协议 access=1/dispo=2） |
| 只读目录**写** | `BLOCKED（命中只读规则）⭐` | 两级判定 kAccessNotAllowed |

形态 B：jailbreak-9 从"目录不存在 gle=3"变成"DENY-ACE 挡下 gle=5"——**gle 3→5 就是形态 B 的核心证据**。

**两条路线哲学**：A = 主动授予（默认全禁 broker 发句柄，Chromium sandbox 套路，细粒度），B = 被动剥夺（改客体 ACL 从外部收权，目录级），纵深防御常一起用。

详见 [`docs/notes/M8.md`](sandbox_demo/docs/notes/M8.md)。

**运行**：`run_m8.bat`（形态 A）/ `run_m8_denyacl.bat`（形态 B）。

### ✅ M9 — 内核 Minifilter 文件过滤驱动（审计 + 拦截，W2 皇冠）

**M8 的用户态防线能被绕过**（target 直接 `NtCreateFile` 跳过 broker、有 `WRITE_DAC` 就能改掉 DENY-ACE、TOCTOU），M9 把文件管控**下沉到内核 IRP 层兜底**——挂 FltMgr、altitude 370000，在 `IRP_MJ_CREATE` 的 Pre 回调里拦**任何进程任何路径**，绕不过。形态 A+B 合一（审计上报 + 敏感路径拦截 + 用户态下发策略）。

**关键实现点**：

1. **只拦用户态请求** — `Data->RequestorMode == KernelMode` 直接放行（内核自身 I/O 不干扰）
2. **规范化路径** — `FltGetFileNameInformation(FILE_NAME_NORMALIZED)`，拿到的是已解析短名/符号链接的最终对象——**内核过滤天然免疫 TOCTOU/symlink 绕过**（M8 要靠 GetFinalPathNameByHandle 补）
3. **拦截 = `FLT_PREOP_COMPLETE` + `STATUS_ACCESS_DENIED`** — 命中黑名单时请求不再下发给 ntfs.sys，从内核层挡死
4. **通信端口 + SD 收紧** — `FltCreateCommunicationPort` 建端口，只允许 Admin/SYSTEM 连；审计走 `FltSendMessage`(内核→用户)，策略下发走 `PortMessage`(用户→内核)
5. **内核铁律** — 不信任对端（PortMessage 严格校验 + `__try/__except`）、防溢出（len 夹紧）、并发用 `KSPIN_LOCK`、回调在 PASSIVE_LEVEL

#### M9 交付状态

- **驱动本体 `sandbox_minifilter.sys` 已在本机 WDK 环境编译通过**（VS2022 + WDK 10.0.26100，C 代码零 error）；用户态控制程序 `mf_ctl` 亦编译通过。
- 编译踩的三个环境/打包坑（非代码问题）：① MSB8040 需 Spectre 库 → 关 `SpectreMitigation`；② InfVerif/inf2cat → 补 INF `[SourceDisksFiles]` 段 + 关打包；③ SignTool 缺 /fd → 关自动签名。
- **加载/拦截实测在 VM 里做**（testsigning + `fltmc load`，内核 bug = 蓝屏，务必 VM 快照）。

#### M9 vs M8 纵深关系

| 维度 | M8 用户态 | M9 内核 Minifilter |
|---|---|---|
| 拦截层 | 用户态 broker / DACL | 内核 IRP_MJ_CREATE |
| 能否绕过 | 可（NtCreateFile / 改 DACL） | 否（所有用户态 create 都过 FltMgr） |
| 防 TOCTOU | 靠 GetFinalPathNameByHandle 补 | 天生：内核拿到的就是最终对象 |
| 崩溃代价 | 进程崩 | 蓝屏（须 VM） |

详见 [`docs/notes/M9.md`](sandbox_demo/docs/notes/M9.md) 与 [`src/minifilter/README.md`](sandbox_demo/src/minifilter/README.md)。

### ✅ M10-11 — 测试 + 交付打包

- **`run_all.bat`** — 一键回归：自动提权 + 建目录 + 顺序跑 M0~M8 全部非破坏性 demo（`--once` 跑完即退）+ 按退出码打 PASS/FAIL + 汇总（跳过需 VM 的 M9）
- **顶层 `README.md`（本文档）+ `sandbox_demo/README.md`** — 项目门面 / 五层围栏全景 / M0~M9 一览 / JD 能力映射
- **`docs/notes/PROJECT_SUMMARY.md`** — 踩坑合集（按 M0~M9 分类）+ 6 条关键技术决策 + 面试 Q&A 大全
- **`package.bat`** — 收拢 exe/dll/sys/inf + 全部脚本 + docs 成 `release/sandbox_demo_release_YYYYMMDD.zip`（内置 Compress-Archive，无需 7-zip）

**全部 12 个 milestone（M0~M11）完成**：从用户态权限收敛一路做到内核 Minifilter，五层纵深完整，每层有 demo 验证 + 深度笔记 + 面试话术。

---

## 7. 参考 & 对齐目标

- **Chromium sandbox**（[design doc](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)）— 工业级Broker/Target 双进程沙箱的黄金标准
- **Windows Job Object docs** — https://learn.microsoft.com/windows/win32/procthread/job-objects
- **Mitigation Policy** — `PROCESS_MITIGATION_POLICY` 官方文档
- **WFP** — Windows Filtering Platform 网络过滤框架
- **Minifilter** — 文件系统过滤驱动模型

本工程的最终形态**不追求覆盖 Chromium sandbox 全部特性**，目标是"覆盖 JD 5 大能力块 + 每个能力块有一个可讲的原型"，作为**面试作品集**使用。

### 深度文档索引（`sandbox_demo/docs/notes/`）

- **`why_sandbox_for_agent.md`** ⭐ 工程动机总纲（讲项目先看这篇）
- **`RECALL_CARDS.md`** 快速回忆卡（主动回忆自测，突然想起项目时快速唤醒知识点）
- `M0.md` ~ `M9.md` — 每个 milestone 的完整笔记（原理 + 踩坑 + 实测 + 话术）
- `kernel_objects_101.md` — 横切基础：Object Manager / HANDLE / SeAccessCheck / PEB / 命名管道
- `minhook_trampoline_deepdive.md` — MinHook inline hook 底层深挖
- `sandbox_vs_codex.md` — 本项目 vs OpenAI Codex Sandbox 对比
- `tools_cheatsheet.md` — 调试工具速查（WinDbg / Process Explorer / WinObj）

---

## 8. License

MIT
