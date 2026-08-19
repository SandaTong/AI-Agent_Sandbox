# Reading Plan — 20 天边写边学（对齐两本教材）

> 本工程 20 天的 milestone 学习计划，**每天/每 milestone 明确对应两本书的章节**：
> - 📕 **《Windows 内核原理与实现》** — 潘爱民，电子工业出版社 2013 版（716 页）
> - 📗 **《Windows 核心编程》** — Jeffrey Richter 第 5 版，清华大学出版社 2008 版（770 页）
>
> **两本书的定位区别**（先搞清楚，读得才有针对性）：
> - 📕 **潘书**："**内核里发生了什么**"。以 WRK 源码为参照，从数据结构角度讲 Windows 内核对象、进程/线程调度、内存管理器、I/O 系统的实现。**读完你懂"为什么这么设计"**。
> - 📗 **Richter**："**你作为 developer 该怎么调 Win32 API**"。API 用法、参数含义、坑、示例。**读完你懂"这个 API 怎么用"**。
>
> **配套姿势**：Richter 是**日常查阅手册**（放手边，做 milestone 时随时翻）；潘书是**周末补基础**（周末花 3~4 小时集中读一次内核概念，把 Richter 里"这个 API 到底动了什么内核结构"补齐）。

---

## 🗓️ 20 天日历（一览表）

| Day | Milestone | 📗 Richter 优先章节 | 📕 潘书优先章节 | 每日投入 |
|---|---|---|---|---|
| **D1** ✅ | M0 基础闭环 | Ch 3 内核对象 · Ch 4 进程 · Ch 5 作业 | Ch 2 §2.5.1 对象管理 · Ch 3 §3.1~3.4 进程线程数据结构 | 已完成 |
| **D2** ✅ | M1（1/2）Low IL | Ch 3 内核对象 复习 · Ch 4 进程 中的安全部分 | **Ch 2 §2.5.4 安全性管理**（重中之重） | 已完成 |
| **D3** ✅ | M1（2/2）Mitigation Policy + Alt Desktop | Ch 4 进程（Mitigation 段落） | Ch 3 §3.4.3 进程创建过程 | 已完成 |
| **D4-5** ✅ | M2 AppContainer / LowBox | Ch 3 内核对象（名字空间部分）| Ch 2 §2.5.1 对象管理器 精读 | 已完成 |
| **D6** ✅ | M3 Broker/Target + Named-Pipe IPC | **Ch 8 用户模式同步** · **Ch 9 内核对象同步** | **Ch 8 §8.2 LPC · §8.3 命名管道** | 已完成 |
| **D7-8** ✅ | M4 注入 + Hook | **Ch 22 DLL 注入和 API 拦截**（这一章就是 W4） · Ch 19-20 DLL | Ch 4 §4.3 进程内存管理 · Ch 3 §3.4.1 句柄表 | 已完成 |
| **D9** ✅ | M5 反注入 | Ch 22 后半（防注入部分） · Ch 20 §DLL 通知 | — | 已完成 |
| **D10-12** ✅ | M6 WFP 网络管控 | —（Richter 未覆盖 WFP，看官方文档） | **Ch 9 §9.1 网络体系结构**（TDI/NDIS/WFP 对比） | 已完成 |
| **D13** ✅ | M7 DNS 域名 | — | — | 已完成 |
| **D14-15** ✅ | M8 用户态文件 Broker | Ch 10 I/O（同步 vs 异步） · Ch 17 内存映射文件 | **Ch 6 I/O 系统** · Ch 7 §7.4 NTFS | 已完成 |
| **D16-18** ✅ | M9 内核 Minifilter | 已跨界到内核态，Richter 不覆盖 | **Ch 6 §6.5 设备驱动 · §6.6 I/O 处理** · Ch 7 §7.4.3 文件系统 I/O 过滤 | 已完成 |
| **D19-20** | M10-11 测试 + 打包 | — | — | 复盘 |

---

## 📍 当前进度（截至 M8）

```
Day 1     M0 ✅  Job + Restricted Token
Day 2-3   M1 ✅  Low IL + Mitigation + Alt Desktop（踩 4 个 0xC0000142坑）
Day 4-5   M2 ✅  AppContainer + LowBox + INetFwPolicy2加餐（踩 5 个坑）
Day 6     M3 ✅  Broker/Target Named-Pipe IPC（DuplicateHandle + 管道 SDDL 双门坑）
Day 7-8   M4 ✅  DLL 注入 + API Hook（MinHook；注入垫片继承 target 权限不提权坑）
Day 9     M5 ✅  反注入 + 运行时检测（内核 mitigation + 用户态自检；用 M4 injector 攻防对照）
Day 10-12 M6 ✅  WFP 用户态网络管控（AppID 形态拦 loopback，还清 M2 § 九的债；IP 精确匹配实测本机不命中）
Day 13    M7 ✅  DNS 域名维度（注入 dns_hook.dll 钩 GetAddrInfoW 做域名白名单；DNS→IP 联动 WFP）
Day 14-15 M8 ✅  用户态文件 Broker（A: 策略引擎增强 防TOCTOU+最小权限 / B: DENY-ACE 剥夺写权限）
Day 16-18 M9 ✅  内核 Minifilter 驱动（A+B: IRP_MJ_CREATE 审计上报 + 敏感路径拦截 + 用户态下发策略）  ← 你在这里
Day 19-20 M10-11 ⏳ 测试 + 打包  ← 下一站
```

**已完成 10 个 milestone（M0~M9）**。M4（攻：注入+hook）和 M5（守：反注入）互为镜像。M6 网络管控（WFP）按进程/IP 拦 outbound。M7 把网络管控升到域名维度。M8 把 M3 的文件 broker 骨架升级成生产级（策略引擎防 TOCTOU + DENY-ACE）。M9 把文件管控下沉到**内核 Minifilter**：挂 FltMgr（altitude 370000），在 IRP_MJ_CREATE 的 Pre 回调里审计上报 + 按敏感路径黑名单拦截（STATUS_ACCESS_DENIED），黑名单经 FltMgr 通信端口由用户态下发——补上 M8 用户态防线可被绕过的缺口。下一站 M10-11 测试 + 打包。

---

## 📖 各 Milestone 详细阅读指引

### ✅ M0（已完成）— Job / Token / CREATE_SUSPENDED 三步舞

**代码用到的核心概念**：Kernel Object、HANDLE、Job Object、Access Token、Restricted Token、Privilege、进程/线程/主线程挂起

**📗 Richter 精读**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 3 内核对象** | 33~ | HANDLE 是什么、CloseHandle 为什么必须、内核对象的引用计数 → 直接解释 `ScopedHandle` 为什么这么设计 |
| **Ch 4 进程** | 65~ | `CreateProcessW` / `CreateProcessAsUserW` 的 10 个参数逐个讲、`STARTUPINFO`、进程句柄的父子关系、退出码 → 你 `ProcessLauncher::Launch` 里的每一行都在这一章 |
| **Ch 5 作业** | 155~ | `CreateJobObject`、`SetInformationJobObject` 的所有 info-class、UI 限制、CPU/内存/进程数限制 → 你 `JobManager` 的完整背景 |

**📕 潘书精读**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 2 §2.5.1 对象管理** | ~65 | 内核对象在内核里的样子（`OBJECT_HEADER` + body）、对象名字空间`\BaseNamedObjects`、句柄表 → 解释"为什么 HANDLE 是 kernel-wide 唯一的" |
| **Ch 3 §3.1~3.2 进程线程模型** | 97~120 | 内核层 `KPROCESS` / `KTHREAD` vs 执行体 `EPROCESS` / `ETHREAD` 的分层设计 → 解释 Access Token 是挂在 EPROCESS 上的一个字段 |
| **Ch 3 §3.3 数据结构** | 120~140 | `_EPROCESS` 结构关键字段（Job 指针、Token 指针、VAD 树根、Handle Table 指针）→ 解释"进程为什么能'属于'一个 Job" |
| **Ch 3 §3.4.3 进程创建过程** | 145~155 | `CreateProcess` 底层调 `NtCreateProcessEx` → 内核建 EPROCESS → 建初始线程（挂起）→ 用户态返回 → **精确解释 `CREATE_SUSPENDED` 为什么可行** |

**读完 M0 你应该能回答**：
- HANDLE 内部是什么？为什么必须 CloseHandle？
- 内核里 Job 对象和一个 Process 对象是怎么建立"属于"关系的？
- CREATE_SUSPENDED 时进程的哪些初始化已经做了，哪些没做？

---

### ✅ M1（已完成）— Integrity Level + Mitigation Policy + Alternate Desktop

**代码将用到**：`SetTokenInformation(TokenIntegrityLevel)`、Mandatory Label SID、`STARTUPINFOEX`、`UpdateProcThreadAttribute`、`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`、`CreateWindowStation`、`CreateDesktop`

**📕 潘书（重中之重）**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 2 §2.5.4 安全性管理** | ~85 | Access Token 内部结构（User SID / Groups / Privileges / **Mandatory Label**）、SID 编码、ACL/ACE 评估算法 → 直接告诉你"降 IL 到底改了 Token 的哪个字段" |

Mandatory Label 段落尤其关键——你会看到 `SECURITY_MANDATORY_LOW_RID = 0x1000` 就是我们要写进 SID 的值。

**📗 Richter**：

- Ch 4 进程的 `CreateProcess` 章节里有 STARTUPINFO 和 STARTUPINFOEX 的对比
- Mitigation Policy 是 Win7+ 新增，Richter 第 5 版覆盖有限，**主要看微软官方文档**：
  - https://learn.microsoft.com/windows/win32/procthread/process-mitigation-policy
  - https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

**外部资源（Alternate Desktop 部分）**：
- MSDN "Window Stations" 概念页 —— 讲 WinSta / Desktop / HKL 三层的关系
- Alex Ionescu "Windows Security Boundaries" 讲座 slides

**读完 M1 你应该能回答**：
- Low IL 和 restricted token 各挡了什么？为什么两者要一起用？
- Mitigation Policy 里 `BLOCK_NON_MICROSOFT_BINARIES` 是内核在哪一步生效的（加载器？syscall？）
- Alternate Desktop 隔离 vs Session 隔离，各自防什么？

---

### ✅ M2（已完成）— AppContainer / LowBox Token

**代码将用到**：`CreateAppContainerProfile`、`DeriveAppContainerSidFromAppContainerName`、`NtCreateLowBoxToken`（未文档化）、Capability SID、`SECURITY_CAPABILITIES` 结构

**📕 潘书**：

| 章节 | 你会明白 |
|---|---|
| **Ch 2 §2.5.1 对象管理** 精读 | AppContainer 内部就是一个**独立的对象名字空间**（`\Sessions\<n>\AppContainerNamedObjects\<sid>\`）。理解这一点你就明白"为什么 AppContainer 里的进程连自己 mutex 都要用不同路径" |

**📗 Richter**：
- Ch 3 内核对象 里对"命名对象"的讲解 —— 复习一遍，然后你就懂 AppContainer 命名空间隔离
- 第 5 版对 AppContainer 覆盖有限（AppContainer 是 Win8+），主要看官方文档

**外部资源**：
- **Chromium sandbox** 的 `broker_services.cc` / `app_container.cc` —— 直接读源码最快
- MSDN "AppContainers for Executables" 概念页

**读完 M2 你应该能回答**：
- AppContainer 和 Low IL 的区别？AppContainer 到底是"更细粒度的 IL"还是别的东西？
- Capability SID 的作用？为什么是"白名单"而不是"权限列表"？
- LowBox Token（NtCreateLowBoxToken 生成的）和普通 Restricted Token 的区别？

---

### ✅ M3（已完成）— Broker/Target 双进程 + Named-Pipe IPC

**代码将用到**：`CreateNamedPipe` / `ConnectNamedPipe`、异步 I/O（Overlapped）、`WriteFileEx` / `ReadFileEx`、消息帧协议、Broker/Target 生命周期管理

**📗 Richter（重头戏）**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 8 用户模式同步** | ~200 | 关键段/互斥锁/条件变量/SRWLock 各自的适用场景 → 你 broker 主循环需要选一个 |
| **Ch 9 内核对象同步** | ~245 | Event / Semaphore / Mutex（内核对象版）、WaitForSingleObject / WaitForMultipleObjects → broker 用它等 target/管道就绪 |
| **Ch 10 同步 I/O 与异步 I/O** | ~285 | Overlapped I/O、I/O 完成端口 → **命名管道服务端必须用异步**，否则 broker 卡死 |

**📕 潘书**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 8 §8.2 LPC**（本地过程调用） | ~555 | Windows 内部 RPC 走的就是 LPC，你写命名管道的原理和它类似（消息驱动 + 端口对象） |
| **Ch 8 §8.3 命名管道** | ~570 | 内核里 npfs.sys 怎么实现命名管道、名字解析、消息 vs 字节流模式 |

**读完 M3 你应该能回答**：
- 命名管道 vs mailslot vs ALPC，为什么 Chromium sandbox 早期用管道现在用 Mojo？
- Overlapped I/O 和 IOCP 的关系？服务端用哪种？
- broker 崩溃时管道端点会发生什么？

---

### ✅ M4（已完成）— 注入 + API Hook（W4 的核心）

**代码将用到**：`OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`（LoadLibrary 注入四件套）、MinHook / Inline Hook、IAT Hook、DllMain

**📗 Richter（这一章直接就是 W4 面试考点）**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 19 DLL 基础** | ~499 | DLL 加载过程、DllMain 四种回调、加载器锁 |
| **Ch 20 DLL 高级技术** | ~525 | 显式加载 / 延迟加载 / 已知 DLL 列表 |
| **Ch 22 DLL 注入和 API 拦截**（**必读**） | ~577 | 5 种注入方式（注册表 / Hook / 远程线程 + LoadLibrary / Trojan DLL / CreateProcess with DLL）+ API 拦截两种（IAT 修改 / 代码修改）——**这一整章就是 M4 的教科书** |

**📕 潘书**：

| 章节 | 你会明白 |
|---|---|
| **Ch 4 §4.3 进程内存管理** | VirtualAllocEx 在目标进程分配内存的内核机制、VAD 树的样子 |
| **Ch 3 §3.4.1 进程的句柄表** | 你为什么能 OpenProcess 拿到别人的 handle、访问检查怎么走 |

**外部资源**：
- **Modexp 博客** https://modexp.wordpress.com/ 有 15+ 种注入姿势的实操 writeup
- **MinHook 源码** —— 轻量级 Inline Hook 库，代码 <2000 行，值得通读

**读完 M4 你应该能回答**：
- CreateRemoteThread 注入的 5 个关键步骤，每一步用了哪个 API，为什么用它？
- IAT Hook 和 Inline Hook 的对比：谁能被 hook 谁的、怎么绕过、检测手段？
- DllMain 里 LoadLibrary 会死锁，为什么？

---

### ✅ M5（已完成）— 反注入 + 运行时检测

**代码将用到**：`LdrRegisterDllNotification`、模块签名验证（`WinVerifyTrust`）、`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` 检测远程线程

**📗 Richter**：
- Ch 20 §DLL 通知 —— `LdrRegisterDllNotification` 官方回调机制
- Ch 22 后半反注入思路

**📕 潘书**：暂无对应章节（反注入是 Win7+ 用户态技巧，内核书没覆盖）

**外部资源**：
- Alex Ionescu 讲过的 "Process Mitigation" 系列——你 M1 装的那 8 项 mitigation 就是反注入的"内核级"版本
- Modexp 的 anti-inject 系列文章

---

### ✅ M6（已完成）— WFP 用户态网络管控

**代码将用到**：`FwpmEngineOpen0`、`FwpmFilterAdd0`、条件字段（App ID / IP / 端口 / 协议）、`FWPM_LAYER_ALE_AUTH_CONNECT_V4`

**📕 潘书（Windows 网络架构必读）**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 9 §9.1 网络** | 592~610 | Windows 网络栈全景：**TDI / NDIS / WSK / WFP** 各自定位。**读完这节你就明白 JD 里为什么 WFP > LSP > NDIS > TDI 优先级**——WFP 是 Vista+ 官方推荐替代 |
| §9.1.3 NDIS | ~600 | 网卡驱动 <-> 协议驱动之间的接口，最底层 |
| §9.1.4 Vista+ 网络结构 | ~608 | WFP filter engine + Callout Driver 架构 |

**📗 Richter**：第 5 版没覆盖 WFP，直接看官方文档

**外部资源（重头戏）**：
- **微软 WFP Programming Guide**：https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page
- **WFP Sample Code**：https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/netds/wfp —— 官方示例，抄改即可
- **Jared Wright 的 "WFP Starter Kit"** GitHub 项目

**读完 M6 你应该能回答**：
- WFP 用户态 Filter Engine 和内核态 Callout Driver 的分工？
- 想按"目的域名"过滤为什么 WFP 不支持，得配合 DNS Hook？
- 出方向拦截应该 hook 在 `ALE_AUTH_CONNECT` 还是 `OUTBOUND_TRANSPORT`？各自区别？

**M6 实测硬结论（写进 M6.md）**：
- **AppID 形态完全成功**：按 exe 路径拦 target 全部 outbound，`ALE_AUTH_CONNECT_V4` 层**连 loopback 都拦**（`WSAErr=10013`）→ 还清 M2 § 九的 loopback 债。
- **按远程 IP 精确匹配本机不命中**：`IP_REMOTE_ADDRESS` 条件 UINT32/ADDR_MASK × 主机序/网络序四种组合装配全对（netsh 可见 8.8.8.8/32）却全不拦；`M6_BLOCK_ALL` 无条件 BLOCK 对照三行全拦 → 定性为"裸 BLOCK 有效、AppID 有效、唯独 IP 条件在纯用户态该层求值被短路"，属环境/仲裁层面，要稳需内核态 callout。
- **两个工程坑**：① netsh 显示按主机序反解，"显示对≠运行时匹配对"；② exe 被残留进程占用致 `LNK1168` 静默未更新，跑的还是旧 exe——改完必"杀进程→删 exe→编译→验时间戳"。

---

### ✅ M7（已完成）— DNS 域名维度

**代码用到**：MinHook 钩 `ws2_32!GetAddrInfoW`（复用 M4 注入骨架）、环境变量传白名单、M6 WFP 联动

**外部资源**：
- MSDN DNS API 页
- WFP 4.0 后的 `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4` 也能间接控 DNS

**M7 实测硬结论（写进 M7.md）**：
- **形态 A（域名白名单 hook）完全成功**：注入 `dns_hook.dll` 钩 `GetAddrInfoW`，白名单内 `example.com` 放行（解析到 IP）、白名单外 `www.bing.com` 被拦（`GetAddrInfoW err=11001` = `WSAHOST_NOT_FOUND`）。一次命中，说明 `GetAddrInfoW` 就是 target 解析入口。
- **为什么 hook 而非 WFP 拦 :53**：解析走进程外 dnscache 服务，WFP 在 :53 看到的源是 svchost 区分不了进程；进程内 hook 才能拿明文域名 + 区分进程 + 挡 DoH。
- **白名单传递零改 core**：`SetEnvironmentVariableW` + 子进程继承环境块，注入的 DLL 在 DllMain 读。
- **形态 C（DNS→IP 联动 WFP）**：broker 侧解析域名拿"域名→IP"，演示 A(hostname 维度)+IP 维度纵深；C 的 IP 白名单部分继承 M6"IP 不命中"坑，用 AppID 兜底，真正落地需内核 callout。

---

### ✅ M8（已完成）— 用户态文件 Broker

**代码用到**：命名管道 IPC（复用 M3）+ broker 侧 `CreateFileW` + `GetFinalPathNameByHandleW`（防 TOCTOU 真身校验）+ `DuplicateHandle`（最小权限复制）；形态 B 用 `GetNamedSecurityInfo`/`SetEntriesInAcl`/`SetNamedSecurityInfo` 给目录加 DENY-WRITE ACE

**📗 Richter**：
- Ch 10 同步/异步 I/O 复习
- Ch 17 内存映射文件（如果要把大文件跨进程共享）

**📕 潘书**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 6 I/O 系统 §6.1~6.2** | 383~410 | IRP / 文件对象 / I/O 请求路径 |
| **Ch 7 §7.4.5 NTFS** | ~510 | NTFS 的 ACL 存储、访问检查流程、DENY 优先命中的内核依据 |

**M8 实测硬结论（写进 M8.md）**：
- **形态 A（策略引擎增强）**：在 M3 骨架上补齐四点——① 多规则白名单读写分离（只读目录 vs 可写目录，命中规则后再判 access 维度，`kDenied` vs `kAccessNotAllowed` 区分）；② 协议扩展读/写/创建（`OpenFileRequest` 4B→12B 加 `access_mode`/`disposition`，version 提到 2 但兼容 v1）；③ **防 TOCTOU**：先开句柄再 `GetFinalPathNameByHandleW` 拿事后真身校验（解 symlink/junction/短名/大小写），校验对象=使用对象；④ 最小权限句柄（DuplicateHandle 按策略最小 access，非 `DUPLICATE_SAME_ACCESS`）。target `--ipc` 四行读/写放行拒绝符合预期。
- **形态 B（DENY-ACE）**：broker 起 target 前给 `C:\sandbox_protected` 加针对当前用户 SID 的 DENY-WRITE ACE（含目录+文件继承），target 自己 CreateFileW 写被内核 DACL 检查一票否决（gle=5）。靠"restricted token 用户 SID 不变"定位 target，`FileAcl` 析构自动回滚。
- **两条路线哲学**：A=主动授予（默认全禁 broker 发句柄，Chromium sandbox 套路），B=被动剥夺（改客体 ACL 从外部收权），纵深防御常一起用。

---

### ✅ M9（已完成）— 内核 Minifilter 驱动（W2 皇冠）

**代码用到**：`FltRegisterFilter` + `FltStartFiltering` + `IRP_MJ_CREATE` Pre 回调 + `FltGetFileNameInformation`(规范化路径) + `FLT_PREOP_COMPLETE`/`STATUS_ACCESS_DENIED`(拦截) + `FltCreateCommunicationPort`/`FltSendMessage`(审计上报) + `PortMessage`(策略下发) + `.inf`(altitude 370000/FSFilter) + `fltmc load`

**📕 潘书（这一步不看内核书完全写不出来）**：

| 章节 | 页码 | 你会明白 |
|---|---|---|
| **Ch 6 §6.5 设备驱动程序** | 425~460 | Driver Object / Device Object / IRP major function 分派 |
| **Ch 6 §6.6 I/O 处理** | 460~475 | IRP 在设备栈上的传播、Completion Routine、IoCallDriver |
| **Ch 7 §7.4.3 文件系统的 I/O 过滤** | 495~505 | Legacy Filter Driver vs Minifilter 对比、**FltMgr 架构**（这就是你写的 sys 挂靠的对象） |
| **Ch 6 §6.7 IRPMon** | 475~490 | 一个类似 minifilter 的实例代码走读 |

**📗 Richter**：完全不覆盖（内核态）

**外部资源（重头戏）**：
- 微软官方 **File System Minifilter Programming Guide**：https://learn.microsoft.com/windows-hardware/drivers/ifs/file-system-minifilter-drivers
- WDK 官方示例 **`swapbuffers`** / **`passThrough`** / **`minispy`** —— 装 WDK 后本地有代码
- Windows Filesystem Filter Manager Concepts 文档

**读完 M9 你应该能回答**：
- Minifilter 和 Legacy Filter Driver 的差别？为什么用 Minifilter？
- Altitude 是什么？为什么必须向微软申请？
- Pre-Callback 里 return `FLT_PREOP_COMPLETE` 和 `FLT_PREOP_SUCCESS_NO_CALLBACK` 的区别？

**M9 实测硬结论（写进 M9.md）**：
- **形态 A+B 合一**：一个 Minifilter 同时审计 + 拦截。挂 FltMgr（altitude 370000），`IRP_MJ_CREATE` 的 `PreCreate` 里 `FltGetFileNameInformation` 拿规范化路径 + `PsGetCurrentProcessId` 拿 PID；命中敏感路径黑名单 → `FLT_PREOP_COMPLETE` + `STATUS_ACCESS_DENIED` 从内核挡死（ntfs.sys 没被调到），否则放行；放行/拦截都经 `FltSendMessage` 上报审计。黑名单经 FltMgr 通信端口由用户态 `mf_ctl` 下发，端口 SD 只放行 Admin/SYSTEM。
- **相对 M8 的三点纵深**：① 覆盖全机任意进程任意路径（用户态绕不过）② 内核拿到的是最终解析对象，天然免疫 TOCTOU/symlink（M8 要靠 GetFinalPathNameByHandle 补）③ 代价是崩溃即蓝屏（须 VM + testsigning）。
- **交付**：驱动本体 `sandbox_minifilter.c`(WDK 编) + `mf_protocol.h` + `.inf` + `.vcxproj` + 用户态 `mf_ctl.cc`(主 CMake 已编译通过) + install/run/uninstall_mf.bat。实测输出待 VM 跑完回填。
- **内核代码铁律**：不信任对端（PortMessage 严格校验 + `__try/__except`）、防溢出（len 夹紧）、并发用 KSPIN_LOCK、只拦 `RequestorMode==UserMode`、回调在 PASSIVE_LEVEL。

---

## 🎯 每周复盘节奏

**Week 1（D1-7）**：主线 M0-M4，读 Richter Ch 3/4/5/8/9/10/22 + 潘书 Ch 2/3。周末（D6/D7）花 4 小时集中读**潘书 Ch 2 §2.5 + Ch 3**，把内核对象/进程线程模型彻底吃透。

**Week 2（D8-14）**：主线 M5-M8，读 Richter Ch 19/20/22 + 潘书 Ch 9 §9.1。周末花 4 小时读**潘书 Ch 6 I/O 系统**，为 M9 内核驱动打底。

**Week 3（D15-20）**：主线 M9-M11，全力啃**潘书 Ch 6/7 + WDK 官方文档 + minispy 示例**。周末不再读书，全用于打磨 demo 和面试话术。

---

## 📌 边写边学的规则

1. **不要试图"读完书再写代码"**——你会读不完
2. **写代码遇到卡壳时立刻查书**，比如"这个 API 参数没搞懂" → Richter 索引查 API 名；"这个概念不懂"（比如 Mandatory Label） → 潘书目录找章节
3. **每完成一个 milestone，回头把对应章节精读一遍**——这时候你会有"原来如此！"的顿悟，比一开始盲读效率高 3 倍
4. **每周挑一个印象深刻的概念写到 `docs/notes/M<x>.md` 里**——用自己的话讲一遍，才是真的学会

---

## 📎 备查清单（放手边）

工程内文档：
- **`docs/notes/why_sandbox_for_agent.md`** ⭐ — **工程动机总纲**：这套 Job/Token/IL/Mitigation/WFP/文件Broker 到底解决 AI Agent 的什么真实风险（模型失控/prompt注入/供应链投毒）、每个 milestone 对应的 agent 场景、五层围栏全景、工业级参照（Chromium sandbox / OpenAI Code Interpreter / EDR）、面试项目背景口径。**讲项目先看这篇**
- `docs/notes/M0.md` — 已写，含 3 个硬伤修复的完整叙述
- `docs/notes/M1.md` — M1 完整笔记 + 7 章 + 4 个 0xC0000142 坑 + 4 条金牌话术
- `docs/notes/M2.md` — M2 完整笔记 + 12 章 + Firewall 加餐 + 6 条金牌话术
- `docs/notes/M3.md` — M3 完整笔记 + Broker/Target IPC + DuplicateHandle + 管道 SDDL 双门坑 + 4 条金牌话术
- `docs/notes/M4.md` — M4 完整笔记 + 注入四件套 + MinHook Inline Hook + "注入垫片继承 target 权限不提权"坑 + 5 条金牌话术
- `docs/notes/M4_appendix.md` — M4 附加深挖：Inline Hook vs OC Swizzling 对比 + jmp 改写调用时序/trampoline + kernel32 共享基址/ASLR开机随机一次 + PE 装载/导入表·导出表·IAT/静态vs动态调用（注入与 hook 的底层地基）
- `docs/notes/minhook_trampoline_deepdive.md` ⭐ — MinHook inline hook 底层深挖：relay/trampoline/detour 四角色 + hook 前后内存布局图 + 安装/调用两张时序图 + 为什么 x64 需 relay + 为什么调原函数名会无限递归（必须调 trampoline）+ 逐句验证。追问"蹦床是什么/怎么调回原函数"来这篇
- `docs/notes/M5.md` — M5 完整笔记 + 反注入双层（内核 mitigation + 用户态 self_defense）+ LdrRegisterDllNotification/远程线程扫描/API inline-hook 自检 + 用 M4 injector 攻防对照（防御ON注入被挡/OFF得手）+ 5 条金牌话术
- `docs/notes/M6.md` — M6 完整笔记 + WFP 原理（vs Firewall / 用户态 filter vs 内核 callout）+ DYNAMIC 会话 + 两种形态（AppID 精确拦成功含 loopback / IP 黑名单）+ ⭐IP 精确匹配踩坑全记录（6 行证伪表 + M6_BLOCK_ALL 终极对照 + 根因 + netsh 显示陷阱 + exe 时间戳编译陷阱）+ 面试三连问
- `docs/notes/M7.md` — M7 完整笔记 + DNS 解析真实链路（薄壳 + 进程外 dnscache）+ 三路线选型对比表 + 形态 A（hook GetAddrInfoW 域名白名单，实测 www.bing.com 被 WSAHOST_NOT_FOUND 拦）+ 白名单环境变量传递 + 形态 C（DNS→IP→WFP 联动纵深）+ 与 M4/M6 复用图谱 + 面试三连问
- `docs/notes/M8.md` — M8 完整笔记 + 文件 Broker 两条路线对比（IPC 代劳 vs DENY-ACE）+ 形态 A 策略引擎四点增强（多规则白名单读写分离 / 协议读写创建扩展 / ⭐GetFinalPathNameByHandle 防 TOCTOU 真身校验 / 最小权限句柄回传）+ 形态 B（file_acl 模块 SetNamedSecurityInfo 加 DENY-WRITE ACE，靠 restricted token 用户 SID 不变定位 target）+ 与 M3/M0 复用图谱 + 面试三连问
- `docs/notes/M9.md` — M9 完整笔记（上篇原理 + 下篇实现）：Minifilter 架构（挂 FltMgr/altitude/Pre-Post）+ IRP 拦截时序图（PreCreate 三返回值）+ 形态 A+B（IRP_MJ_CREATE 审计上报 + 敏感路径拦截 STATUS_ACCESS_DENIED + FltMgr 通信端口下发策略）+ 内核代码铁律（不信任对端/防溢出/KSPIN_LOCK/IRQL）+ 与 M8 纵深关系表 + 编译加载步骤 + 面试话术。配套 `src/minifilter/`（sandbox_minifilter.c/.h/.inf/.vcxproj + mf_ctl.cc + README）+ install/run/uninstall_mf.bat
- `docs/notes/sandbox_vs_codex.md` — 本项目 vs OpenAI Codex Sandbox 对比（Windows 后端撞车点 Restricted Token/DENY ACE/帧式 IPC + 各自独有层 + 架构 Mermaid 图 + 面试口径）
- `docs/notes/resume_polish_feishu.md` — 面向飞书「桌面端 Agent Sandbox」岗位的简历润色稿（公司总览两版 + 腾讯会议/元宝项目 + 沙箱独立高亮项按 JD Windows 五维组织 + 技能关键词栏）
- **`docs/notes/kernel_objects_101.md`** ⭐ — **横切基础**：Object Manager / OBJECT_TYPE / HANDLE 表 / SeAccessCheck / KILL_ON_JOB_CLOSE 回调 / AppContainer 命名空间前缀劫持。所有 milestone 遇到"内核里到底怎么实现的"这类问题先来这里查
- **`docs/notes/tools_cheatsheet.md`** ⭐ — **工具速查表**：Process Explorer / WinObj / ProcMon / dumpbin / WinDbg / wf.msc 等所有沙箱开发调试常用工具，按用途分类 + 每个工具"什么时候用它 + 对应我们代码哪个场景"
- `README.md` — 工程总览 + JD 关键词映射

外部快查：
- 微软 Learn https://learn.microsoft.com/windows/win32/ — Win32 API 官方文档
- Sysinternals Suite — Process Explorer / Process Monitor / WinObj 三件套
- Chromium sandbox 源码 https://source.chromium.org/chromium/chromium/src/+/main:sandbox/win/ — 工业级参考实现
