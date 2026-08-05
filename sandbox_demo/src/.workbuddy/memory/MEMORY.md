# 项目记忆 — sandbox_demo (Windows 沙箱)

## 项目目标
基于 Windows 安全机制实现一个进程沙箱:通过"受限 token + Job Object"双支柱限制子进程。
当前处于 M0(最基础一层),后续有 M1/M2/M3 路线图。

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
- **入口**(`demo/m0_demo.cc`):组装 Job+Token,启动 target,永久等待,return 时 JobManager 析构触发 KILL_ON_JOB_CLOSE。

## 路线图(来自 token_manager.h)
- M1: 降 Integrity Level 到 Low/Untrusted + Mitigation Policy(STARTUPINFOEX)。
- M2: NtCreateLowBoxToken 生成 AppContainer 的 LowBox Token。
- M3: Broker/Target IPC(handle 白名单 PROC_THREAD_ATTRIBUTE_HANDLE_LIST)。

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
