# 项目回忆卡 — 快速唤醒 AI-Agent Sandbox 的全部知识点

> **这份文档和别的不一样**：README 是门面、PROJECT_SUMMARY 是踩坑汇总、M*.md 是细节。
> **这份是"主动回忆训练卡"**——不是拿来读的，是拿来**自测**的。
>
> **正确用法**：每张卡先**只看问题、遮住答案**，在脑子里（或嘴上）把答案复述出来，卡壳了再展开看。答得出 = 记得牢；答不出 = 那张卡就是你下次要重点回炉的。
>
> **回顾节奏（间隔重复）**：第 1 天 → 第 3 天 → 第 7 天 → 第 14 天 → 第 30 天，之后每月一次。每次只花 10~15 分钟过一遍 §1「30 秒电梯回忆」+ §2「一句话卡」，卡壳的才翻 §3 深水区。

---

## §0 最快唤醒：一张图 + 一句话（看 5 秒就能想起这是什么项目）

**一句话**：把"行为不可预测、却握着数据和执行权的 AI Agent 进程"关进 **五层围栏**，不赌模型不作恶，只在 OS 层把作恶的爆炸半径限制死（defense-in-depth）。

```
资源(M0/M1) → 权限(M1/M2) → 能力(M1/M5) → 网络(M2/M6/M7) → 数据(M3/M8/M9)
Job/CPU内存    Token/Low IL   禁动态代码      WFP/DNS         文件Broker/Minifilter
              /AppContainer  /非签名DLL/禁子进程  拦loopback/域名  /真身校验/内核IRP拦截
                          （M4攻 ⇄ M5守：保证沙箱自身不被劫持）
```

> 唤醒锚点：**一个 target 进程（hello_target.exe）+ 一个 broker + 九个越狱测试（jailbreak-1~9）**，每个越狱测试对应一层围栏，基线全 SUCCESS，加了对应 milestone 就变 BLOCKED。

---

## §1 30 秒电梯回忆（面试自我介绍 / 突然被问起时用）

> 先遮住，试着一口气说完，再对照。

<details>
<summary>点开对照</summary>

"我做了一个 Windows 原生进程级沙箱，专门用来关 AI Agent。核心思路是不信任模型本身，而是在操作系统层建五层围栏：**资源**（Job Object 限 CPU/内存/进程数）、**权限**（受限 Token + 降 Integrity Level + AppContainer）、**能力**（Process Mitigation Policy 禁动态代码/非签名 DLL/子进程）、**网络**（WFP 按进程/IP/域名拦截）、**数据**（用户态文件 Broker 代劳 + 内核 Minifilter 兜底）。中间还做了注入/反注入攻防（M4/M5）保证沙箱自身不被劫持。从 M0 用户态一路做到 M9 内核驱动，每层都有可跑的 demo 和一个通用靶子进程做越狱测试验证。"

</details>

---

## §2 一句话卡（M0~M9，每张先答"它解决什么 + 用什么 API"）

> 遮住右列，看到 M 号就答。这是主干，务必背到条件反射。

| 卡 | 问：它做什么？关键 API？ | <details><summary>答</summary></details> |
|---|---|---|
| **M0** | 沙箱最小闭环？ | Job Object 限资源 + 受限 Token 起 target；`CreateJobObject`/`CreateRestrictedToken`/`KILL_ON_JOB_CLOSE`（broker 死 target 跟着死） |
| **M1** | 权限和能力怎么收敛？ | 降 **Integrity Level** 到 Low + 8 项 **Process Mitigation Policy**（STARTUPINFOEX 传）+ Alt Desktop/WindowStation 隔离 UI |
| **M2** | 更强的隔离？ | **AppContainer/LowBox** token + Capability SID；命名空间天然隔离（jailbreak-6 open global mutex 失败）|
| **M3** | 沙箱内进程怎么安全拿资源？ | **命名管道 IPC** broker/target + **DuplicateHandle** 回传句柄；SDDL 授权 Package SID/降管道 label |
| **M4** | 攻：怎么劫持一个进程？ | 远程线程 + LoadLibrary **注入**四件套 + **MinHook inline hook**（trampoline/relay）钩 CreateFileW |
| **M5** | 守：怎么防被注入？ | 内核 mitigation（禁非签名 DLL）+ 用户态自检（`LdrRegisterDllNotification` 监控模块 + API 完整性校验 + 远程线程扫描）|
| **M6** | 按 IP/进程拦网络？ | **WFP**（Windows Filtering Platform）在 `ALE_AUTH_CONNECT_V4` 层按 **AppID/IP** 拦 outbound（含 loopback）|
| **M7** | 按域名拦网络？ | 注入 **hook `GetAddrInfoW`** 做域名白名单；DNS→IP→WFP 联动纵深 |
| **M8** | 用户态文件管控？ | 文件 **Broker 策略引擎**（多规则白名单读写分离 + **GetFinalPathNameByHandle 防 TOCTOU** + 最小权限句柄）；另一路 **DENY-ACE** 改 NTFS DACL 剥夺写权限 |
| **M9** | 内核兜底文件管控？ | 文件 **Minifilter** 挂 FltMgr(altitude 370000)，`IRP_MJ_CREATE` Pre 回调审计+拦截（`FLT_PREOP_COMPLETE`+`STATUS_ACCESS_DENIED`），FltMgr 通信端口下发策略 |

---

## §3 深水区回忆卡（面试会追问的"为什么"和"最隐蔽的坑"）

> 这些是把项目从"我做过"讲成"我真懂"的分水岭。每张卡是一个"如果被追问……"。

### 卡 3.1 — 为什么用户态做了文件管控（M8），还要内核 Minifilter（M9）？

<details><summary>答</summary>

因为**用户态防线能被绕过**：target 可以直接调 `NtCreateFile` 跳过 broker，或有 `WRITE_DAC` 权限就能改掉我加的 DENY-ACE，还有 TOCTOU。内核 Minifilter 在 IRP 层拦**任何进程任何路径**，绕不过；而且 `FltGetFileNameInformation` 拿到的是**最终解析对象**，天然免疫 symlink/短名/TOCTOU（用户态要靠 GetFinalPathNameByHandle 补）。代价是崩溃即蓝屏，必须 VM + testsigning。**主动授予(broker) vs 被动兜底(内核) 是纵深防御。**
</details>

### 卡 3.2 — 命名管道客户端"连接"就是一个 CreateFile 吗？

<details><summary>答</summary>

**动作**是——命名管道由 `npfs.sys` 承载，是 File 类内核对象，`CreateFileW(\\.\pipe\name, OPEN_EXISTING)` open 成功即连上。但**健壮连接**还要三件事：① `SetNamedPipeHandleState(PIPE_READMODE_MESSAGE)` 对齐消息模式（否则粘包）② `PIPE_BUSY` 用 `WaitNamedPipeW` 等空闲实例 ③ `ACCESS_DENIED` 不重试（这正是沙箱 SD 授权没生效的信号）。收发侧把 `BROKEN_PIPE` 当正常结束。
</details>

### 卡 3.3 — 防 TOCTOU 的关键手法（M8 最亮的点）？

<details><summary>答</summary>

**先开句柄，再让内核回吐真身校验**。传统"先校验字符串路径再打开"有检查时机差：symlink/junction/短名/ADS 能让"看起来在白名单的字符串"实际指向白名单外。做法：先 CreateFileW 拿句柄 → `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED|VOLUME_NAME_DOS)` 拿这个句柄**真正指向**的规范全路径 → 用真身比白名单。**校验对象 = 使用对象**，杜绝检查时机攻击。
</details>

### 卡 3.4 — MinHook inline hook 为什么要 trampoline？直接调原函数会怎样？

<details><summary>答</summary>

会**无限递归栈溢出**。因为 target 开头前 5 字节已被改写成 `jmp relay→detour`，detour 里若直接调 `CreateFileW` 又跳回被改写的开头，回到自己。**必须调 trampoline（`g_orig`）**：trampoline 里放的是"被覆盖的原始指令" + `jmp 回 target+5`（未被覆盖处），绕过入口继续执行真函数。
</details>

### 卡 3.5 — Low IL target 为什么启动就崩 0xC0000142？

<details><summary>答</summary>

`STATUS_DLL_INIT_FAILED`。根因：debug CRT 的 DLL（VCRUNTIME140D 等）非微软签名，被 `BLOCK_NON_MICROSOFT_BINARIES` mitigation 拦。解法：target **静态链接 CRT（/MT /MTd）**。同类坑：Alt Desktop 起不来也是 0xC0000142，因 desktop 继承了 High IL 的 mandatory label，Low IL 通不过 → SDDL 加 `S:(ML;;;;;LW)` 降 label。
</details>

### 卡 3.6 — PreCreate 三种返回值的区别（M9 高频）？

<details><summary>答</summary>

- `FLT_PREOP_SUCCESS_NO_CALLBACK` = 纯放行，不要 PostCreate
- `FLT_PREOP_SUCCESS_WITH_CALLBACK` = 放行但要 PostCreate（审计用）
- `FLT_PREOP_COMPLETE` + `Data->IoStatus.Status = STATUS_ACCESS_DENIED` = **从内核挡死，ntfs.sys 根本没被调到**（拦截用）
</details>

### 卡 3.7 — 内核代码的"铁律"（写驱动不蓝屏的几条）？

<details><summary>答</summary>

① 只拦 `RequestorMode == UserMode`（内核自身 I/O 别碰）② 不信任对端：PortMessage 严格长度校验 + `__try/__except` 防非法指针 ③ 防溢出：字符串 len 夹紧 ④ 并发用 `KSPIN_LOCK` 保护黑名单 ⑤ 回调在 PASSIVE_LEVEL ⑥ 通信端口 SD 只放行 Admin/SYSTEM。
</details>

### 卡 3.8 — 我们的沙箱和 OpenAI Codex Sandbox 的关系？

<details><summary>答</summary>

**Codex 的 Windows 后端和我们高度重合**：都是 `Restricted Token + DENY ACE + 受限令牌启动 + 帧式 IPC 管道`。差异：Codex 求**广度**（一层 SandboxPolicy 抽象分发到 macOS Seatbelt / Linux Landlock+Seccomp / Windows），我们求**深度**（单 Windows 平台把内核对象一路夯到 Minifilter，额外做了 Mitigation/AppContainer/注入攻防/WFP/DNS hook 这些 Codex 不覆盖的层）。
</details>

---

## §4 记忆钩子（把知识点挂到好记的锚点上）

> 突然想不起某层用什么时，靠这些"钩子"倒推。

- **五层围栏顺序**：资源→权限→能力→网络→数据。记忆法：**"关进笼子(资源权限能力) → 断网(网络) → 锁数据(数据)"**，由外向内收权。
- **九个越狱测试 = 九把锁的钥匙孔**：jailbreak-1 写桌面(IL)、2 起子进程(禁子进程)、3 RWX内存(禁动态代码)、4 非签名DLL、5 剪贴板(Job UI)、6 global mutex(AppContainer)、7 TCP连接(WFP)、8 域名解析(DNS hook)、9 写受保护目录(DENY-ACE/Minifilter)。**编号 = milestone 递进**。
- **攻守镜像**：M4 是矛（注入+hook），M5 是盾（反注入），**背一个就想起另一个**。
- **文件管控三级跳**：M3(只读最小骨架) → M8(用户态生产级策略引擎) → M9(内核兜底)。**越往后越底层、越绕不过、代价越大（进程崩→蓝屏）**。
- **网络管控两维度**：M6 是 IP/进程维度（WFP，内核过滤平台），M7 是域名维度（hook，用户态）。**IP 靠内核、域名靠钩子**。

---

## §5 "我到底交付了什么"清单（证明这不是纸上谈兵）

> 突然怀疑"我真做完了吗"时看这里。

- **代码**：`src/core/`（token/job/mitigation/pipe/injector/file_acl 等骨架）+ `src/demo/`（m0~m8 各 demo + hello_target 通用靶子）+ `src/minifilter/`（.c/.h/.inf/.vcxproj 内核驱动 + mf_ctl 控制程序）
- **可跑**：~20 个 `run_*.bat`（自动提权/建目录/`--once` 跑完即退）+ `run_all.bat` 一键回归 M0~M8 + `package.bat` 打 release zip
- **编译验证**：M0~M8 全量 clean build；M9 的 `.sys` 本机 WDK 编译通过（8.7KB），加载在 VM
- **文档**：`README.md`（门面）+ `M0~M9.md`（逐层细节）+ `PROJECT_SUMMARY.md`（踩坑/决策/Q&A）+ `kernel_objects_101.md`（内核对象基础）+ `sandbox_vs_codex.md`（对标）+ 本文档
- **实测存档**：M6/M7/M8 的 demo 输出已回填对应 M*.md；M9 待 VM 跑完回填

---

## §6 下次回顾清单（勾一下，形成习惯）

```
[ ] 第 1 遍（今天）      ：读完 §0~§2，遮答复述
[ ] 第 3 天              ：只过 §2 一句话卡，卡壳的翻 §3
[ ] 第 7 天              ：§1 电梯回忆 + §3 深水区随机抽 3 张
[ ] 第 14 天             ：完整过一遍，重点补上次卡壳的
[ ] 第 30 天             ：只看 §0 图能不能自己展开整个项目
[ ] 之后每月            ：§0 + §4 记忆钩子，5 分钟
```

> 找不回细节时的跳转：具体 API/坑 → 对应 `M*.md`；横切踩坑 → `PROJECT_SUMMARY.md`；内核对象基础 → `kernel_objects_101.md`；项目动机 → `why_sandbox_for_agent.md`。
