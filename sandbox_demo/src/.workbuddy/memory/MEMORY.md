# 项目记忆 — sandbox_demo (Windows 沙箱)

## 项目目标
基于 Windows 安全机制实现一个进程沙箱。当前已推进到 M3(在 M2 基础上叠加 Broker/Target IPC 命名管道通道)。
M0~M3 路线图全部完成。

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
