# 项目记忆 — sandbox_demo (Windows 沙箱)

## 项目目标
基于 Windows 安全机制实现一个进程沙箱。当前已推进到 M6(WFP 用户态网络管控层,还 M2 留下的网络债)。
M0~M6 路线图全部完成。

## M0 架构(双支柱 + 三步舞)
- **支柱一 TokenManager**(`core/token_manager.cc`):`CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`
  移除全部 privilege,身份仍是原用户。约束"能调用哪些特权 API"。
  所需权限: TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT。
- **支柱二 JobManager**(`core/job_manager.cc`):`SetInformationJobObject` 设资源/UI/生命周期限制。
  - 进程数 / 单进程内存 / CPU 硬顶(HARD_CAP);UI 限制;
  - `KILL_ON_JOB_CLOSE`(broker 崩则 target 一起死,防孤儿)、`DIE_ON_UNHANDLED_EXCEPTION`;
  - 刻意不设 BREAKAWAY,子进程的子进程也逃不出 Job。
- **启动器 ProcessLauncher**(`core/process_launcher.cc`):CREATE_SUSPENDED 三步舞
  `CreateProcessAsUserW(受限token, CREATE_SUSPENDED)` → `AssignProcessToJobObject` → `ResumeThread`,
  保证 Job 约束在 target 第一行代码前生效。bInheritHandles=FALSE(M3 改白名单只给通信管道)。
- **入口**(`demo/m0_demo.cc`):组装 Job+Token,启动 target,永久等待。
- **KILL_ON_JOB_CLOSE 的两条触发路径**(关键纠正,新手易踩坑):
  - 正常 return:`JobManager` 析构 → `ScopedHandle` 调 `CloseHandle` 关 Job handle。
  - crash/被 kill:析构**不走**!但进程销毁时内核清理该进程的 handle table,
    逐个关闭所有内核对象 handle(包括 Job 的)→ 仍是"最后一个 handle 被关" → 触发。
  - 共同点:都靠"Job 最后一个 handle 关闭"触发,**不依赖用户态析构**——这才是它作为沙箱生命线的本质。
  - 隐含前提:只有 broker 持有 Job handle。`bInheritHandles=FALSE` 保证 target 不继承 Job handle,
    否则 broker 死了 handle 不到 0,KILL_ON_JOB_CLOSE 在 crash 场景就不会触发。
    (所以 `bInheritHandles=FALSE` 不仅为 M3 通信白名单,也间接保证 crash 时兜底生效。)

## 路线图(来自 token_manager.h)
- ~~M1: 降 Integrity Level 到 Low/Untrusted + Mitigation Policy(STARTUPINFOEX)。~~ 已完成。
  - 新增 `core/mitigation.{h,cc}`:`MitigationAttrList` 用 STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_LIST
    在进程创建时把 8 项 Mitigation Policy 绑到 EPROCESS(加载器跑前生效,非事后拦截)。
    8 项(strict 0..8):DEP / ASLR / PROHIBIT_DYNAMIC_CODE / CHILD_PROCESS_RESTRICTED /
    IMAGE_LOAD_NO_REMOTE / IMAGE_LOAD_NO_LOW_LABEL / BLOCK_NON_MICROSOFT_BINARIES(反注入绝杀)/
    EXTENSION_POINT_DISABLE。disable_win32k 默认关(太激进)。
  - CHILD_PROCESS_RESTRICTED 是独立属性 PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,不在 Mitigation 位图里。
  - 新增 `core/desktop_iso.{h,cc}`:Alt WindowStation+Desktop UI 隔离,需 GrantAccessToLowIntegrity 授权给 Low IL target。
  - `demo/m1_demo.cc`:Job+Token(IL=Low)+Mitigation+Desktop 四件套组装;--strict N 可 bisect。
- M2: ~~NtCreateLowBoxToken 生成 AppContainer 的 LowBox Token。~~ 已完成。
  - 新增 `core/appcontainer.{h,cc}`:`AppContainer` 类封装 profile/SID/capability。
    `CreateAppContainerProfile` 注册 profile(同名幂等,已存在则 `DeriveAppContainerSidFromAppContainerName` 复用),
    得到 Package SID(形如 S-1-15-2-...)。
    `AddCapability` 把 well-known capability(internetClient=S-1-15-3-1 等)转成 SID 存入。
    `View()` 组装 `SECURITY_CAPABILITIES` 结构(AppContainerSid + Capabilities 数组 + Count)。
    注意:用户态 API 叫 SECURITY_CAPABILITIES,"LowBox" 是内核术语。
  - 新增 `core/firewall.{h,cc}`:`FirewallGuard` 用 INetFwPolicy2 COM 给 Package SID 写
    outbound TCP Block 规则(需管理员权限,非管理员 E_ACCESSDENIED 只警告)。析构自动删规则。
    原因:AppContainer 单靠自身**不禁网**,出方向必须 broker 主动写 firewall 规则。
  - `MitigationAttrList::Configure` 新增第三参数 `sec_caps`(SECURITY_CAPABILITIES*),
    内部装 `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` 属性槽 → 内核创建 EPROCESS 时走 AppContainer 访问检查路径。
  - `demo/m2_demo.cc`:AppContainer + Job + Token(IL=Low)+ Mitigation + Firewall 五件套组装。
    `--net` 加 internetClient capability 并跳过 firewall block;不带则出方向被拦(WSAEACCES)。
  - **M2 踩坑(重要)**:
    1. alt desktop 默认**关**:AppContainer 自带独立 winsta/desktop 命名空间
       (\Sessions\<n>\AppContainerNamedObjects\<pkg_sid>\),再叠加手工 alt desktop 会冲突
       → 0xC0000142 STATUS_DLL_INIT_FAILED。Chromium AppContainer 分支也不做 alt desktop。
       `--desk` 反向开关保留只为复现坑。
    2. `strict_signed_dll`(BLOCK_NON_MICROSOFT_BINARIES)在 M2 里**关掉**:
      AppContainer runtime 需加载非微软签名 DLL(如 winsock helper),强开会挂。
    3. AppContainer target 走私有命名空间,看不见 broker 的 global mutex(演示 namespace isolation)。
  - **与 M1 的本质区别**:M1 Restricted Token 是"你原来是谁 - 去掉权限";M2 LowBox 是"换成新身份(Package SID),完全不同访问检查路径,默认拒绝,声明什么才能用什么"。
- M3: ~~Broker/Target IPC(handle 白名单 PROC_THREAD_ATTRIBUTE_HANDLE_LIST)。~~ 已完成。
  - 新增 `core/ipc_message.h`:IPC 消息协议。定长 MsgHeader(magic/version/type/payload_size)+
    变长 payload。`#pragma pack(4)` 保证跨进程二进制稳定。payload 硬上限 64KB(防 DoS)。
    ValidateHeader 固化"不信任对端"铁律。消息类型:Ping/Pong、OpenFile 请求/响应。
  - 新增 `core/pipe_server.{h,cc}`:Broker 侧命名管道服务端。
    `Create(package_sid_sddl)`:用 SDDL 构造 SD,DACL 授权 SY/BA/WD(+ 可选 Package SID),
    SACL 放 mandatory label 降到 Low(让 Low IL target 能过完整性检查)。
    `WaitForClient`(ConnectNamedPipe 阻塞)→ `ServeOneRequest`(收消息→校验→分发)。
    `HandleOpenFile`:路径白名单(前缀 `C:\sandbox_share\` + 拒 `..` 穿越)+ broker 代劳 CreateFileW +
    **DuplicateHandle** 把句柄复制进 target handle table(关键:HANDLE 进程私有,必须内核复制)。
  - 新增 `core/pipe_client.{h,cc}`:Target 侧客户端,CreateFileW 连管道 + 收发消息。
  - `demo/m3_demo.cc`:broker 建管道 → launch target(带 --ipc)→ WaitForClient → 循环 ServeOneRequest。
    `--ac` 叠加 AppContainer 并把管道 SD 授权 Package SID。冒烟:target 读 hello.txt 成功,读 hosts 被拒。
  - **M3 核心价值**:M0~M2 把 target 关进笼子(越严越什么都干不了),M3 给 target 一条"委托 broker 代劳"
    的安全通道。broker 收到的每条消息都当恶意输入处理(校验头/边界/白名单)。
  - **M3 踩坑/要点**:
    1. AppContainer target 默认对 broker 管道无权限 → 管道 SD 必须显式授权 Package SID。
    2. Low IL target 连 Medium IL 管道会被 NoWriteUp 一票否决 → SACL 把管道 label 降到 Low。
    3. HANDLE 是进程私有 handle table 索引,不能直接传数值 → 必须用 DuplicateHandle 让内核在 target 里建新句柄。
    4. demo 的 SD 用 Everyone(WD) 图省事,生产应精确到目标 user SID/Package SID(最小授权)。
    5. 消息协议用 PIPE_TYPE_MESSAGE,内核维护消息边界,省粘包处理。
- M4: ~~DLL 注入 + API Hook 运行时拦截层。~~ 已完成。
  - 新增 `core/injector.{h,cc}`:`Injector::InjectDll` 远程线程注入四件套:
    VirtualAllocEx(在 target 分配内存)→ WriteProcessMemory(写 DLL 路径)→
    GetProcAddress(kernel32,LoadLibraryW)(拿地址,kernel32 同 session 基址相同)→
    CreateRemoteThread(在 target 起线程入口=LoadLibraryW 参数=路径)→ 等退出码。
  - 新增 `third_party/minhook/`:MinHook 库(第三方,inline hook)。
  - 新增 `demo/sandbox_hook.cc` → `sandbox_hook.dll`:被注入的"拦截垫片"DLL。
    DllMain attach 时用 MinHook 钩 `kernel32!CreateFileW` → `HookedCreateFileW`。
    钩子里:OutputDebugStringW + 追加写 `%TEMP%\sandbox_hook_log.txt`(必须用 g_orig_CreateFileW 防递归)。
  - `demo/m4_demo.cc`:launch target(CREATE_SUSPENDED)→ InjectDll → ResumeThread。
    关键时序:hook 必须在 target 跑用户代码前装好(start_suspended=true)。
  - **M4 踩坑/要点**:
    1. AppContainer + 强 mitigation(PROHIBIT_DYNAMIC_CODE / BLOCK_NON_MICROSOFT_BINARIES)会拦注入 → M4 精简版用普通 Low IL target,关掉这两项 mitigation。
       **本质:强 mitigation 和"自己注入 hook"冲突** —— 生产要么 hook dll 签名,要么用预置 hook 机制。
    2. hook dll 继承 target 的权限,不会提权:钩子逻辑在 target 内存里不受 IL 限制,但钩子里做的 IO 仍受 target 自身沙箱权限约束。
    3. 日志路径用 %TEMP% 而非 C:\sandbox_share —— Low IL target 对 Medium IL 目录无写权限,但自己的 %TEMP%(AppData\Local\Temp\Low)一定有写权限。
    4. 钩子里写日志必须用 g_orig_CreateFileW(trampoline),否则递归触发自己 hook 无限递归。
    5. kernel32.dll 在同一 session 所有进程里加载基址相同 → broker 取的 LoadLibraryW 地址在 target 同样有效(注入成立前提)。
  - **M4 在沙箱里的位置**:M0~M2 是"被动配置内核机制"(内核强制执行),M3 是"target 主动请 broker 代劳",M4 是"broker 主动植入 hook 让 target 的调用被无感知拦截转发"——和 Chromium sandbox 的 "interceptions" 机制对应。
  - **M4 vs M0~M3 维度区别**:M0~M3 是"内核态执行"(约束靠 SRM/Job/EPROCESS);M4 是"用户态拦截"(hook 改函数头几字节,纯用户态)。M4 更早、更细粒度,但可被绕(改内存保护/直接 syscall)。
- M5: ~~target 侧运行时自检(反注入/反篡改检测层)。~~ 已完成。M4 的攻防翻转版。
  - 新增 `core/self_defense.{h,cc}`:`SelfDefense` 类——**跑在 target 自己内部**(与 M0~M4 broker 外部配置的根本区别,不依赖 broker)。
    三个检测手段分别对应 M4 的三种攻击向量:
    ① **DLL 加载通知**(`LdrRegisterDllNotification` ntdll 半公开 API):注册回调,每次 LoadLibrary/映像映射时内核加载器回调带全路径。
       对照白名单(System32/SysWOW64/WinSxS/SystemApps),白名单外 DLL 被加载即告警——正好抓 M4"远程线程 LoadLibraryW(sandbox_hook.dll)"注入。比轮询遍历模块列表实时得多(加载瞬间就知道)。
       `LdrUnregisterDllNotification` 析构注销。SDK 无原型,自己补齐 LDR_DLL_LOADED_NOTIFICATION_DATA 结构。
    ② **可疑远程线程扫描**(`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` + `NtQueryInformationThread(ThreadQuerySetWin32StartAddress=9)` 取线程起始地址):
       起点不在任何已加载模块内(疑似裸内存 shellcode) 或 起点正好是 LoadLibraryW/A(典型远程线程注入入口) → 可疑。
       注:线程起点若是 LoadLibraryW 会落在 kernel32 模块内,单看"是否有归属"抓不到,故额外比对 LoadLibraryW/A 地址。
    ③ **关键 API inline-hook 篡改自检**:读 kernel32!CreateFileW/A 头几字节,看是否被改成跳转指令形态(E9 jmp rel32 / FF25 jmp [rip+disp] / 48B8 mov rax,imm64 / 68 push+ret)。
    - `DefenseFinding` 三种 Kind:kSuspiciousDll / kSuspiciousThread / kApiTampered。
    - API:`StartDllLoadMonitor()`(异步,手段①)、`ScanOnce()`(同步全量,手段②③)、`DrainDllFindings()`(取手段①累积结果)。
    - 回调是 C 风格,用文件级静态 `g_dll_mtx`/`g_dll_findings` 桥接到实例。白名单策略:系统目录可信,其余(尤其 temp/用户目录/UNC)可疑;生产应做签名校验+精确清单。
  - 新增 `demo/m5_demo.cc`:三种对照模式:
    1) 纯防御(默认):开满反注入 mitigation,不注入 → target --selfcheck 自检应干净(基线)
    2) 防御+攻击(`--attack`):开满 mitigation + injector 注入 → ⭐预期注入被内核挡下,自检仍干净
    3) 关防御+攻击(`--defense-off --attack`):复现 M4,注入得手 → ⭐target 自检应报警(可疑DLL/线程/API篡改)
    - M5 mitigation 默认**开满反注入三件套**(与 M4 核心区别):prohibit_dynamic_code + strict_signed_dll + disable_extension_points。`--defense-off` 全关复现 M4。
    - 用法:`m5_demo.exe [--defense-off] [--attack] [--no-il] <target_exe> [args...]`(建议 target 带 `--selfcheck`)
  - `demo/hello_target.cc` 接入 M5:新增 `--selfcheck` 参数。启动时尽早 `StartDllLoadMonitor()`(越狱测试之前,越早越能抓注入);越狱测试后 `RunSelfCheckDemo(sd)` 打印 `[selfcheck]` 结果。
  - 新增 `demo/unsigned_probe.cc`:非微软签名探测 DLL(M1 BLOCK_NON_MICROSOFT_BINARIES 验证用,未签名。LoadLibraryW 加载 exe 走快速路径绕校验,用独立真 DLL 才干净演示拦截点)。
  - **M5 在沙箱里的定位**:M0~M2 是"被动配置内核机制"(内核强制执行),M3 是"target 主动请 broker 代劳",M4 是"broker 主动植入 hook",M5 是"target 自己查自己有没有被注入/被篡改"——双层防御里的第二道。
  - **为什么内核 mitigation 之外还要用户态检测**:内核 mitigation 是第一道(最强,从娘胎带出来无法绕),但两个盲区:① 只"拦"不"报"——被拦的攻击 target 自己不知道,安全产品需"感知到有人在打我"(上报/取证/熔断);② 不是所有环境都能开满(兼容性:target 可能依赖未签名第三方 DLL 就不能开 BLOCK_NON_MICROSOFT_BINARIES),开不满时用户态检测是补位的第二道。所以生产级沙箱(含 Chromium/EDR)都是"内核挡+用户态查"双层。
- M6: ~~WFP 用户态网络管控(还 M2 留下的两笔债)。~~ 已完成。
  - **M6 要解决的债**:M2 firewall 加餐(INetFwPolicy2 COM)有两个硬伤:
    ① loopback bypass——Windows Firewall 对 127.0.0.1/::1 不走规则匹配,回环流量拦不下。
    ② 只能按 Package SID 匹配——普通 Low IL target(非 AppContainer)拦不了。
    且 jailbreak-7(TCP 8.8.8.8)从 M0 到 M5 一直是 SUCCESS——target 网络出口从没被真正精确管控过。M6 用 WFP 补齐。
  - 新增 `core/wfp_filter.{h,cc}`:`WfpFilter` 类,用户态 WFP 过滤器管理器。RAII:析构关 engine,DYNAMIC 会话所有 filter 由 BFE 自动清理(进程崩也不残留脏规则,比 INetFwPolicy2 析构手动删更稳)。
    四个核心概念(编程模型):
    1) **Engine(引擎)**:`FwpmEngineOpen0` 打开到内核过滤引擎的会话句柄。用 `FWPM_SESSION_FLAG_DYNAMIC` 标志。
    2) **Layer(分层)**:内核网络栈固定挂载点。用 `FWPM_LAYER_ALE_AUTH_CONNECT_V4`(ALE 在 connect() 发起出站连接时的授权分层),能拿远程IP/端口/发起进程AppID。
    3) **Sublayer(子层)**:自建 sublayer 把 filter 归组,便于按 key 一次性清理,隔离权重仲裁。
    4) **Filter(过滤器)**:一条规则 = 若干 condition(匹配条件) + action(PERMIT/BLOCK) + weight(权重,高的先裁决)。多条命中时按权重和 BLOCK-override 语义仲裁。
  - `WfpPolicy` 两种形态:
    - `kIpBlocklist`(形态 A):对每个黑名单 IP 加一条 BLOCK(`FWPM_CONDITION_IP_REMOTE_ADDRESS` + `FWP_V4_ADDR_MASK`),其余目标放行。可选叠加 `scope_app_path`(`FWPM_CONDITION_ALE_APP_ID`)限定到只对 target 进程生效。
    - `kBlockAppId`(形态 C):只对指定 exe 的出站连接加 BLOCK(`FWPM_CONDITION_ALE_APP_ID`)。只拦那一个进程,同机其他进程不受影响。AppID 通过 `FwpmGetAppIdFromFileName0` 把 exe 路径转 WFP 认的 blob。
    - **为什么用黑名单而非白名单**:白名单要"默认 BLOCK-all 兜底 + 白名单 IP PERMIT 豁免",PERMIT 要确定性压过 BLOCK 涉及 CLEAR_ACTION_RIGHT / 独立 sublayer 权重等仲裁深水区(实测 PERMIT 压不住兜底 BLOCK)。黑名单只加 BLOCK filter,命中即拦、不命中即放行,行为确定。
  - 新增 `demo/m6_demo.cc`(形态 A):`--block <ip>` 可叠加,默认黑名单 {8.8.8.8}。预期 jailbreak-7:8.8.8.8 BLOCKED / 1.1.1.1 SUCCESS / 127.0.0.1 SUCCESS。
  - 新增 `demo/m6_appid_demo.cc`(形态 C):按 AppID 全拦 target outbound。预期 jailbreak-7 三行全 BLOCKED(含 loopback ⭐)——这是 WFP 相对 Windows Firewall 的关键优势(能拦回环)。
  - **M6 踩坑(重要)**:
    1. **IP 精确匹配在本机不命中**:按 `FWPM_CONDITION_IP_REMOTE_ADDRESS`(`FWP_V4_ADDR_MASK`,addr+全1掩码/32,主机序)在 ALE_AUTH_CONNECT_V4 层对 target outbound connect 实测**不命中**——UINT32/ADDR_MASK × 主机序/网络序四种组合全部装配正确(netsh 可见 8.8.8.8/32)却拦不住,netevents 零 drop。对照实验(去掉 IP 条件、无条件 BLOCK)三行全拦,证明本会话裸 BLOCK 有效,问题锁定在 IP 条件求值本身(connect 授权瞬间远程 IP 未纳入匹配/被环境仲裁短路),属 WFP 分层语义+本机环境层面,纯用户态代码改不动。同层同会话的 ALE_APP_ID 条件正常生效 → 精确按进程管控用 kBlockAppId 形态。
    2. **需管理员权限**:改 WFP filter 要写权限(FwpmEngineOpen 要 RPC 到 BFE 服务)。非管理员得 FWP_E_* / ACCESS_DENIED。
    3. **DYNAMIC 会话是最佳实践**:`FWPM_SESSION_FLAG_DYNAMIC` 打开 engine,句柄一关 BFE 自动清理本会话所有 filter/sublayer——进程崩了也不残留脏规则。比 INetFwPolicy2 析构手动删更稳。
    4. WFP 是 Windows Firewall(mpssvc)的底层——mpssvc 本身建在 WFP 之上。直接对 WFP 编程 = 绕过 Firewall 那层封装/绕过它的 loopback bypass,在更底层按远程IP/端口/本地AppID 精确匹配。
  - **M6 在沙箱里的定位**:M0~M2 是"被动配置内核机制"(内核强制执行),M3 是"target 主动请 broker 代劳",M4 是"broker 主动植入 hook",M5 是"target 自己查自己",M6 是"broker 在内核网络栈装精确 filter 管控 target 出口"——填补 M2 firewall 留下的网络管控缺口(loopback bypass + 非 AppContainer 拦不了)。jailbreak-7 从 M0~M5 一直 SUCCESS,M6 终于能精确拦下。

## 技术约定
- 使用 `ScopedHandle` 做 HANDLE 的 RAII 管理,避免句柄泄漏。
- 权限请求遵循"最小权限集"原则,按后续操作精确列举所需 TOKEN_* 位。
- 代码注释用中文,里程碑用 M0/M1/M2/M3 标记。
- Win32 两阶段 query 模式:先小 buffer,返回 ERROR_MORE_DATA 再按 returned 重试(见 EnumerateProcessIds)。

## 领域知识备忘
- Windows 访问令牌 = 进程"身份凭证":含 User SID / Group SIDs / Privileges / Integrity Level / Default DACL / Logon SID。
- 访问检查:线程访问对象时,SRM 用 token 的 SID 比对对象 SD 中的 DACL(ACE),叠加 IL 检查后裁决。
- primary token 绑定进程;子进程默认继承父 token;线程可 impersonation 临时换用 client token。
- token 管"特权能力",Job 管"资源/生命周期",两者互补缺一不可。

## 用户研究方向(跨会话)
- 用户在研究 Windows 内核(ntoskrnl.exe)内部,想用 WinDbg 深入了解。
- 沙箱属于"用户态构造、内核态执行"——代码在用户态调 Win32 API,约束由内核 SRM/Job/EPROCESS/AppContainer 强制执行。
- 用户可能后续会用 WinDbg 验证沙箱机制(EPROCESS 字段、token 结构、handle table)。
- WinDbg 探索建议:本地内核调试入门(配符号 srv*c:\symbols*msdl)→ 双机调试动态跟踪;
  学习路径:进程线程结构体 → 对象管理器 → 系统调用分发 → 内存管理 → 调度器。
- **已搭好的环境(2026-08-07)**:
  - 用户机器 Secure Boot 开启,`bcdedit /debug on` 被拒 → 改用 **LiveKD** 方案。
  - LiveKD 装在 `C:\Tools\LiveKD\livekd64.exe`(Sysinternals)。
  - 经典版 WinDbg 在 `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe`,Preview 是 `WinDbgX.exe`。
  - `_NT_SYMBOL_PATH = srv*c:\symbols*https://msdl.microsoft.com/download/symbols`(用户级),`C:\symbols` 已建。
  - 启动方式:把 WinDbg 路径加进 PATH + 设好 _NT_SYMBOL_PATH,然后 `livekd64.exe -w`。
  - LiveKD 与本地内核调试等价(都只读),够用于探索结构体/反汇编;要动态断点才需双机调试+关 Secure Boot。
