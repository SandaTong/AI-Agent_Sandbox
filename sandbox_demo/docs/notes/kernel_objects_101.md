# Windows 内核对象 101：Object Manager / HANDLE / OBJECT_TYPE

> M0/M1/M2 里我们所有 `Create*` API（Job / Token / Process / Mutex / File / WindowStation / Desktop）**背后都是同一套内核机制**——Windows Object Manager。这份笔记把这套机制系统整理一遍，作为面试作品集的"内核基础"底座。
>
> 前置：`docs/notes/M0.md` / `M1.md` / `M2.md`（这里讨论的是它们代码背后的内核实现）。

## 一、一句话讲清 Windows Object Manager

**Windows 内核里几乎所有 "可命名 / 可 handle 化" 的资源** —— Process、Thread、File、Event、Mutex、Semaphore、Job、Token、Section、Key（注册表 hive）、Directory（namespace）、SymbolicLink、WindowStation、Desktop、Port（ALPC）、IoCompletion、Section、Timer …… **都是 Object Manager 管的对象**。

Object Manager 干四件事：

1. **对象生命周期**：分配内存 → refcount 加减 → refcount 归 0 时调 delete 回调 → 释放内存
2. **命名空间**：维护 `\` 根目录树（`\BaseNamedObjects\` / `\Sessions\<n>\...` / `\Device\` / `\GLOBAL??\` / `\KnownDlls\` 等），负责按字符串路径查找对象
3. **HANDLE 表**：给每个进程维护一张 handle 表，把内核指针"翻译"成用户态可见的 HANDLE 索引
4. **访问检查**：每次 handle 化对象时，用调用者 token 对该对象的 SD 做 `SeAccessCheck`（DACL + Mandatory Label + Capability 三层）

**用一句话精确描述**：Object Manager 是**内核里的"统一资源生命周期 + 命名 + 访问控制服务"**。所有 subsystem（Process Manager / IO Manager / Memory Manager …）都把自己的核心资源注册成 Object Manager 的对象类型。

## 二、OBJECT_TYPE：每种对象是一个"类型"

Windows 有大概 60+ 种对象类型（`WinObj → \ObjectTypes` 目录能看到全部）。每种对象类型注册时都提供一份 `OBJECT_TYPE_INITIALIZER`，声明：

```c
typedef struct _OBJECT_TYPE_INITIALIZER {
    USHORT   Length;
    UCHAR    ObjectTypeFlags;
    ULONG    CaseInsensitive;
  ULONG    UnnamedObjectsOnly;
    ULONG UseDefaultObject;
 ULONG    SecurityRequired;
    ULONG    MaintainHandleCount;
    ULONG    MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG    DefaultPagedPoolCharge;
    ULONG    DefaultNonPagedPoolCharge;
    OB_DUMP_METHOD          DumpProcedure;
 OB_OPEN_METHOD    OpenProcedure;      // handle 打开时调
    OB_CLOSE_METHOD         CloseProcedure;     // handle 关闭时调 ⭐
    OB_DELETE_METHOD        DeleteProcedure;    // 对象 refcount 归 0 调 ⭐
    OB_PARSE_METHOD  ParseProcedure;     // 名字解析时调（Device 用）
    OB_SECURITY_METHOD      SecurityProcedure;  // 访问检查特殊处理
    OB_QUERYNAME_METHOD  QueryNameProcedure;
    OB_OKAYTOCLOSE_METHOD   OkayToCloseProcedure;
    ACCESS_MASK   ValidAccessMask;
    GENERIC_MAPPING    GenericMapping;
} OBJECT_TYPE_INITIALIZER;
```

内核初始化时（`PsInitPhase0` / `IoInit` / 等）为每种类型调 `ObCreateObjectType(L"Job", &init, ...)` 一次，返回一个 `POBJECT_TYPE` 全局变量（`PsJobType` / `PsProcessType` / `PsThreadType` / `IoFileObjectType` / `ExEventObjectType` / ……）。之后**这个类型的所有对象共享同一份 TypeInfo**。

**关键回调 3 个**：

- **`DeleteProcedure`**：对象 refcount 归 0 时调。**释放该对象独占的资源**。比如 `PspJobDelete` 会释放 EJOB 里的 completion port、UI limit 列表、iocomplete key 等
- **`CloseProcedure`**：**handle** 被关闭时调（不是对象销毁！handle 关了对象可能还活着，因为其他 handle 或内核引用还在）。**Job Object 的 `KILL_ON_JOB_CLOSE` 语义就在这里实现**——见 § 六
- **`ParseProcedure`**：名字解析走到这个对象时调。File 对象常用——`\Device\HarddiskVolume2\Users\...` 走到 `\Device\HarddiskVolume2` 就调 `IopParseDevice`，把剩下的路径交给 IoManager 继续解析

## 三、对象在内存里的样子

每个对象在内核 nonpaged pool 里的布局：

```
+-----------------------------+
| OBJECT_HEADER_QUOTA_INFO    | (可选，如果 track 配额)
+-----------------------------+
| OBJECT_HEADER_HANDLE_INFO   | (可选，MaintainHandleCount 开时)
+-----------------------------+
| OBJECT_HEADER_NAME_INFO     | (可选，如果有名字)
+-----------------------------+
| OBJECT_HEADER_CREATOR_INFO  | (可选)
+-----------------------------+
| OBJECT_HEADER   | ⭐ 核心头部（PointerCount / HandleCount /
|   |     TypeIndex / SecurityDescriptor / ...）
+=============================+
| BODY (对象实体，比如 EJOB)  | ← 用户拿到的对象指针指向这里
+-----------------------------+
```

**"对象指针"指向 BODY 而不是 HEADER**。内核代码从对象指针反推 HEADER 用宏：

```c
#define OBJECT_TO_OBJECT_HEADER(o) \
    ((POBJECT_HEADER)((PCHAR)(o) - offsetof(OBJECT_HEADER, Body)))
```

`OBJECT_HEADER` 里最重要的三个字段：

- `PointerCount`（引用计数）：内核引用 + handle 引用 之和；归 0 → 调 `DeleteProcedure` → 释放内存
- `HandleCount`：只算用户态 handle；每 `CloseHandle` 减 1；归 0 → 调 `CloseProcedure`
- `TypeIndex`：指向全局 `ObpObjectTypes[]` 数组的索引，能反查 `POBJECT_TYPE`

**面试话术**：**Windows 内核对象的 `PointerCount` 和 `HandleCount` 是两个不同的计数**——`PointerCount` 归 0 才真的销毁，`HandleCount` 归 0 只是"最后一个用户 handle 关了"。KILL_ON_JOB_CLOSE 语义就利用了这个差异。

## 四、HANDLE 表：进程私有的"索引→内核指针"映射

每个进程的 `_EPROCESS` 有一个 `ObjectTable` 字段，指向一个 `_HANDLE_TABLE`。这是一棵**三层树**（低级 handle 值直接是数组，高级 handle 值是二级/三级指针）。

**HANDLE 的编码**（32-bit 或 64-bit，但内核只用低 32 位）：

```
    31       2 1 0
    +----------+-+-+
    |  index   |P|C|C = "close pending"  P = "protect from close"
    +----------+-+-+
```

- HANDLE 是**索引**，不是内存指针
- 低 2 位是标志位（`HANDLE_FLAG_PROTECT_FROM_CLOSE` 等）
- 剩下的位是 handle 表里的槽索引

一个槽（`_HANDLE_TABLE_ENTRY`）存的核心信息：

```c
struct {
    PVOID Object;     // 指向 OBJECT_HEADER（低 3 位存 access flags）
    ACCESS_MASK GrantedAccess;
};
```

**这就是为什么 HANDLE 是"进程私有"的**：它是当前进程 handle table 里的一个索引，别的进程 table 里没这个索引 → 拿这个 HANDLE 值过去打不开对象。想让另一个进程也拿到 handle → `DuplicateHandle` 会在目标进程 handle table 里造一个新槽指向同一个内核对象，返回目标进程视角的新 HANDLE 值。

**关键操作**：
- 用户态 `HANDLE h = ...` → 内核走 `ObReferenceObjectByHandle(h, ...)` → 查当前进程 handle table → 拿到 OBJECT 指针 + 校验 access
- `CloseHandle(h)` → 内核走 `NtClose(h)` → 从 handle table 删槽 → `HandleCount--` → 如果归 0 → 调 CloseProcedure → 如果 PointerCount 也归 0 → 调 DeleteProcedure

## 五、对象生命周期完整时序

用 M0 的 `CreateJobObjectW` 举例：

```
用户态:
CreateJobObjectW(NULL, NULL)     (kernel32)
    └── NtCreateJobObject(&h, JOB_ALL, &oa)      (ntdll, syscall)
       │
────────────────── syscall 边界 ──────────────────────┼─────────
           ▼
内核态:
  NtCreateJobObject
    ├── ObCreateObject(PsJobType, ...)
    │     ├── 内存分配（nonpaged pool，sizeof(EJOB) + sizeof(OBJECT_HEADER)）
    │     ├── 初始化 OBJECT_HEADER：
    │     │     PointerCount = 1
    │     │     HandleCount  = 0
    │     │     TypeIndex    = <PsJobType的索引>
    │     └── 返回 EJOB 对象指针
    ├── PspJobInit(job)   ← EJOB body 初始化
    │     ├── InitializeListHead(&ProcessListHead)
    │     ├── quota / UI limit 默认值
    │     └── ...
    └── ObInsertObject(job, ..., &h)
    ├── (可选)按名字挂到目录，比如 \BaseNamedObjects\<name>
          ├── SeAccessCheck(broker.token, job.SD, JOB_ALL)   ← 访问检查
          ├── 分配 handle table 槽，槽.Object = OBJECT_HEADER
          ├── HandleCount++ (0→1)
 ├── PointerCount++ (1→2)   ← handle 引用的一个 pointer
          └── 返回 HANDLE h
    └── 返回 h 到用户态
```

**从这里出发**，Job 的生命周期就走两条独立轨道：

**HandleCount 轨道**：
```
broker CloseHandle(job) → HandleCount-- (1→0) → PspJobClose 触发
 └── 如果 job 设了 KILL_ON_JOB_CLOSE：
        └── 遍历 ProcessListHead，PsTerminateProcess 强杀每个进程
```

**PointerCount 轨道**：
```
handle 关了 (Pointer-- 1→...) + 内核引用也全部释放 (Pointer-- 到 0)
  → 触发 PspJobDelete
        └── 释放 EJOB 里的动态资源（completion port / io key / ...）
  → ObpFreeObject 归还 nonpaged pool 内存
```

**两条轨道分离的意义**：即使 broker `CloseHandle(job)` 触发了 `PspJobClose` 杀所有进程，只要还有内核引用（比如某个 EPROCESS 还没走完 rundown）保持着 `PointerCount > 0`，EJOB 结构就不会立刻销毁——直到最后一个引用释放才 delete。**这就是"handle 关和对象销毁是两件事"**。

## 六、`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 背后

M0.md 里我们说"broker 死则 target 死"。真实的机制：

1. `SetInformationJobObject(job, JobObjectExtendedLimitInformation, {LimitFlags: LIMIT_KILL_ON_JOB_CLOSE})`
2. 内核把这个 flag 存到 EJOB 里
3. broker 退出 → 系统自动 CloseHandle 所有 broker 持有的 HANDLE → `NtClose(job_handle)`
4. `NtClose` → handle table 删槽 → HandleCount-- 到 0
5. `HandleCount = 0` 触发 `PspJobClose` 回调
6. `PspJobClose` 检查 LimitFlags 里有 `KILL_ON_JOB_CLOSE` → 遍历 `EJOB.ProcessListHead` 里每个 EPROCESS 调 `PsTerminateProcess(..., STATUS_JOB_ASSIGN_NOT_KILLABLE)`
7. 每个 target 进程被内核强杀（不是发信号，是内核直接 terminate thread + tear down process）

**为什么这个机制是"沙箱安全的关键一环"**：

- broker crash / 被 kill / 忘了 CloseHandle —— **不需要写任何清理代码**
- target 进程一定跟着死，没有孤儿 target
- 不依赖用户态代码正确性（用户态代码可能 crash，但内核 `NtClose` 一定会执行）
- **这是 Chromium sandbox 的 renderer 生命周期管理基石**

**面试话术**：

> "M0 里的 `KILL_ON_JOB_CLOSE` 语义不是我代码里写的什么循环实现的，是**内核 Object Manager 的 `CloseProcedure` 回调机制**。EJOB 的 TypeInfo 里注册了 `PspJobClose`，broker 一 `CloseHandle` → 内核 `NtClose` → HandleCount 减到 0 触发 `PspJobClose` → 检查 LimitFlags → 遍历 ProcessListHead 调 `PsTerminateProcess` 强杀所有进程。**这个机制的价值在于它不依赖用户态代码正确性**——broker 就算 crash 了 handle 也会被系统自动关，target 一定跟着死，天生没有孤儿进程问题。这是 Chromium sandbox renderer 生命周期管理的基石。"

## 七、命名空间：`\` 根目录树

Object Manager 维护一个虚拟的目录树，根是 `\`。用 WinObj（管理员）能看到全貌。核心节点：

| 节点 | 内容 | 谁写入 |
|---|---|---|
| `\` | 根 | 内核 |
| `\ObjectTypes\` | **所有 OBJECT_TYPE 的名字列表**（Job/Process/File/...） | 内核（ObCreateObjectType 时） |
| `\BaseNamedObjects\` | **全局命名对象**（`Global\` 前缀落这里，跨 session 可见） | 用户态进程用 `Global\Foo` 造对象 |
| `\Sessions\<n>\BaseNamedObjects\` | **per-session 命名对象**（`Local\` 前缀 / 无前缀落这里，Vista+ 默认） | 同 session 的用户态进程 |
| `\Sessions\<n>\AppContainerNamedObjects\<pkg_sid>\` | **AppContainer 私有命名空间**（M2 关键） | 内核在 AppContainer 起来时自动创建 |
| `\Device\` | IO 设备（\Device\HarddiskVolume2 等） | 驱动 `IoCreateDevice` |
| `\GLOBAL??\` | Win32 名字空间（`C:\Users\...` 这类路径先在这里解析） | Session Manager |
| `\KnownDlls\` | 预加载的系统 DLL 的 Section 对象 | Session Manager |
| `\Windows\` | WindowStation 的容器 | 内核 |
| `\RPC Control\` | RPC endpoint | RPC subsystem |

**AppContainer 命名空间隔离的物理实现**（M2 § 八亲拍确认）：

- 普通进程 `CreateMutexW(L"Global\\Foo")` → 内核走 `\BaseNamedObjects\Foo`
- 普通进程 `CreateMutexW(L"Local\\Foo")` → 内核走 `\Sessions\<n>\BaseNamedObjects\Foo`
- AppContainer 进程 `CreateMutexW(L"Global\\Foo")` → **内核把 Global 前缀劫持** → 走 `\Sessions\<n>\AppContainerNamedObjects\<pkg_sid>\Foo`
- AppContainer 进程 `CreateMutexW(L"Local\\Foo")` / 无前缀 → 通过私有命名空间根里的 `Local` / `Session` **SymbolicLink** 指向自己 → 私有命名空间

**M2 里 jailbreak-6 gle=2 (FILE_NOT_FOUND) 的完整证据链**：broker 造在根 `\BaseNamedObjects\WEMEET_SANDBOX_PROBE_MUTEX`，target 因为是 AppContainer 走**前缀劫持**落到 `\Sessions\1\AppContainerNamedObjects\<pkg>\WEMEET_SANDBOX_PROBE_MUTEX` —— 两个不同位置，target 找不到。

## 八、SD（Security Descriptor）与 SeAccessCheck 三层

每个可命名 kernel object 都在 OBJECT_HEADER 里挂一个 SD（`SECURITY_DESCRIPTOR`）。当有 handle 化操作时（`Create*` / `Open*`），内核走 `SeAccessCheck`。

**AppContainer 出现之前**，SeAccessCheck 只做**两层**：
1. **DACL 检查**：token 的 SID 集合 vs SD.DACL 的 ACE 集合，匹配到 Allow ACE + 覆盖 desired access → 通过；匹配到 Deny ACE → 拒
2. **Mandatory Label 检查**：token IL 数字 ≥ SD.SACL 里 Mandatory Label ACE 的最小 IL → 通过

**M1 里 desktop 起不来 = STATUS_DLL_INIT_FAILED 的元凶就是第 2 层**（M1.md § 七坑 #4）：desktop 从父 winsta 继承的 mandatory label 是 System/High IL，我们 Low IL target 被拒，user32 的 NtUserOpenDesktop 失败。修法是 SDDL 里加 `S:(ML;;;;;LW)` 把 desktop 的 label 降到 Low。

**AppContainer 出现后**，SeAccessCheck 加**第三层**：
3. **Capability 检查**：如果 token 是 LowBox token（token.Flags 里 `TOKEN_LOWBOX` 位为 1），token 的 Package SID + Capability SIDs 都要作为 subject 参与访问检查

**LowBox token 的关键**：`_TOKEN.Flags` 里 `TOKEN_LOWBOX` 位 = 1（内核 `SeAccessCheck` 特殊处理），而 Package SID 挂在 `_TOKEN.Package` 字段 + TokenGroups 里那条特殊 flag=`AppContainer` 的 SID（Process Explorer 显示的"AppContainer" flag 就是这个）。

## 九、跟我们代码对应的对象类型清单

M0/M1/M2 用到的所有 `Create*` API 都对应一种 OBJECT_TYPE：

| 用户态 API | 对应对象类型 | 全局 POBJECT_TYPE 变量 | 生命周期特殊回调 |
|---|---|---|---|
| `CreateJobObjectW` (M0) | Job | `PsJobType` | `PspJobClose` (KILL_ON_JOB_CLOSE) |
| `OpenProcessToken` / `CreateRestrictedToken` (M0/M1) | Token | `SeTokenObjectType` | delete 时释放 groups/privileges 数组 |
| `CreateProcessW` 内部 (M0/M1/M2) | Process | `PsProcessType` | delete 时清理 EPROCESS 各种资源 |
| `CreateThread` 内部 | Thread | `PsThreadType` | 同上 |
| `CreateFileW`（隐式） | File | `IoFileObjectType` | ParseProcedure = `IopParseDevice`（走 IoManager） |
| `CreateMutexW` (jailbreak-6) | Mutant | `ExMutantObjectType` | delete 时抛异常若线程还持有 |
| `CreateSemaphoreW` | Semaphore | `ExSemaphoreObjectType` | delete 时释放等待队列 |
| `CreateEventW` | Event | `ExEventObjectType` | 简单 |
| `CreateFileMappingW` | Section | `MmSectionObjectType` | delete 时解除 mapping |
| `CreateWindowStationW` (M1) | WindowStation | `ExpWindowStationObjectType` | user32 相关清理 |
| `CreateDesktopW` (M1) | Desktop | `ExpDesktopObjectType` | 同上 |
| `CreateAppContainerProfile` (M2) | 无独立 kernel object！ | —— | 只在注册表落地，不创建 kernel object；生成 Package SID + 建 `\Sessions\<n>\AppContainerNamedObjects\<pkg>\` 目录 |
| `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (M2) | LowBox Token | (走 SeTokenObjectType) | 派生token 时打 TOKEN_LOWBOX 位 |

**注意最后两行**——AppContainer profile 本身**不是**一个内核对象。`CreateAppContainerProfile` 只做两件事：
1. 往 `HKCU\...\AppContainer\Storage\` 写一份 profile 元信息
2. 派生 Package SID 并造出 `\Sessions\<n>\AppContainerNamedObjects\<pkg>\` 目录（这个目录 **是** 一个内核对象，`\Directory` 类型）

真正跟"AppContainer 语义"绑定的 kernel object 是 **LowBox Token**——它是 `Token` 类型加了 `TOKEN_LOWBOX` flag 位。

## 九点五、PEB 与环境块：用户态进程结构（vs EPROCESS / handle table）

> 前面 § 三~九 讲的都是**内核态**结构（EPROCESS、OBJECT_HEADER、handle table 都在内核地址空间）。但进程还有一块**用户态**的核心结构——**PEB（Process Environment Block）**。M7 的 DNS 白名单通过环境变量传给 target，就落在 PEB 里，正好补这一节。

### PEB 在哪、装什么

```
进程用户态地址空间（每进程独立）
   └─ PEB (Process Environment Block)   ← 用户态！不是内核 EPROCESS
        ├─ Ldr                          模块加载链表（LoadLibrary 挂在这）
        ├─ ProcessParameters (RTL_USER_PROCESS_PARAMETERS)
        │     ├─ ImagePathName / CommandLine
        │     └─ Environment  ──────────► 环境块字符串:
        │                                  "NAME=VALUE\0NAME=VALUE\0...\0\0"
        ├─ BeingDebugged                 (被调试标志)
        └─ ...堆、AppCompat、gflags 等
```

**两个容易混的"Environment"**：
- **PEB = Process Environment Block**：进程用户态的大结构，装模块链表、启动参数、堆等，**在用户态**（`EPROCESS.Peb` 字段存的是这块用户态内存的地址）。
- **环境块（Environment Block）**：只是 PEB 里 `ProcessParameters->Environment` 指向的那块字符串，格式 `NAME=VALUE\0...\0\0`（双 `\0` 收尾）。

`GetEnvironmentVariableW` 本质就是**读自己进程 PEB 里那块字符串**，纯用户态操作、不陷入内核，所以很快。

### 环境块怎么传给子进程：值拷贝，不是引用

`CreateProcess`（`lpEnvironment=NULL` 时）会把**父进程当前的环境块复制一份**到子进程地址空间：

```
父进程(broker) PEB.Environment          子进程(target) PEB.Environment
  "M7_DNS_ALLOWLIST=example.com\0.."  ── 创建瞬间复制内容 ──►  "M7_DNS_ALLOWLIST=example.com\0.."
  （父的用户态内存）                                          （子的用户态内存，独立一份）
```

**是拷贝不是引用**，两个铁证：
1. **地址空间隔离**：父子是两个独立虚拟地址空间，父的用户态指针在子进程里无效，不可能引用共享。
2. **改了互不影响**：子进程 `SetEnvironmentVariable` 改自己的，父进程看不到；反之亦然。

机制上：`lpEnvironment=NULL` 时 `CreateProcess` 读父环境块，经 ntdll 的 `RtlCreateProcessParameters` 组织进新进程的 `RTL_USER_PROCESS_PARAMETERS`，随新进程 PEB 一起建好。

### ⭐ 时序铁律：先 SetEnv，再 CreateProcess

因为拷贝发生在**创建瞬间**的快照：

```
1. broker: SetEnvironmentVariableW(M7_DNS_ALLOWLIST)  ← 改 broker 自己 PEB 的环境块
2. broker: CreateProcess(...)                          ← 此刻把 broker 环境块【拷贝】给 target
3. target 起来 → 它 PEB 有了那份拷贝 → 注入的 dns_hook.dll 读到
```

第 2 步之后 broker 再改自己的，已拷过去的 target 不会变（各自独立内存）。M7 的 m7_demo 顺序正是"先 Set 再 Launch"。

### vs 句柄继承：两种完全不同的"进程间传递"

| | 环境块 | 句柄（handle） |
|---|---|---|
| 传递方式 | **值拷贝**（复制字符串内容） | **拷贝句柄值 + 内核对象 PointerCount+1** |
| 存哪 | 用户态 PEB | 内核 handle table（在 EPROCESS 里，见 § 四） |
| 共享吗 | ❌ 各一份独立内存 | ✅ 句柄值可不同，但指向**同一个内核对象** |
| 我们哪里用 | M7 传 DNS 白名单 | M3 `DuplicateHandle` 传管道句柄 |

M3 的 `DuplicateHandle` 是"共享同一个内核 pipe 对象"（§ 四），M7 的环境变量是"复制一份字符串"——正好是进程间传递的两个典型面：**一个共享内核对象，一个值拷贝用户态数据**。

### 面试话术 K6：环境块在 PEB、值拷贝、vs 句柄继承

> "环境块不在内核 EPROCESS 里，它在进程**用户态的 PEB**（PEB->ProcessParameters->Environment）里，是一块 `NAME=VALUE\0...` 的字符串。`CreateProcess` 传给子进程是**值拷贝**——创建瞬间把父环境块复制一份到子进程地址空间，之后各自独立、改了互不影响。所以 M7 传 DNS 白名单必须'先 SetEnvironmentVariable 再 CreateProcess'。这跟 M3 的 `DuplicateHandle` 是两种传递机制：句柄继承是**共享同一个内核对象**（PointerCount+1），环境块是**值拷贝用户态数据**，不共享。选环境变量传白名单是因为它轻量、零改 launcher；但它对 target 自己也可见（非保密通道），传敏感策略就该走 M3 的命名管道 IPC。"

## 十、面试话术合集（内核层）

### 话术 K1：Object Manager 全景

> "Windows 内核里几乎所有可 handle 化的资源——Process/Thread/File/Event/Mutex/Job/Token/Section/WindowStation/Desktop——都是 **Object Manager** 管的对象。每种资源类型注册时提供一份 `OBJECT_TYPE_INITIALIZER`，塞了 create/close/delete 回调，Object Manager 统一负责命名、生命周期、访问控制。这跟 Linux 里 file descriptor 相似但抽象层次更高——Linux 每种资源自己管生命周期，Windows 把它统一到 Object Manager。这也是为什么 Windows 编程一切都是 HANDLE：HANDLE 是 Object Manager 给每个进程分配的对象索引。"

### 话术 K2：HANDLE 是索引不是指针

> "很多人以为 HANDLE 是内核对象的内存地址——**不是**。HANDLE 是当前进程 handle table 里一个槽的索引，低 2 位还塞了标志位。想让别的进程也拿到某个对象要 `DuplicateHandle`，本质是在目标进程的 handle table 里造新槽指向同一个对象，返回的 HANDLE 值是目标进程视角的索引。**这就是为什么 HANDLE 天生进程隔离**——broker 手里的 handle 值传给 target 是没用的。"

### 话术 K3：PointerCount vs HandleCount

> "Object Header 里有两个计数：`PointerCount` 和 `HandleCount`。前者算所有引用（内核引用 + handle 引用），后者只算用户态 handle。**它俩归 0 分别触发不同回调**——`HandleCount = 0` 调 `CloseProcedure`，`PointerCount = 0` 调 `DeleteProcedure` 真的销毁对象。**Job 的 KILL_ON_JOB_CLOSE 语义就利用这个差异**：broker CloseHandle → HandleCount 归 0 → `PspJobClose` 触发 → 遍历 ProcessListHead 杀所有进程。这就是为什么沙箱 broker 挂了 target 会自动死——**内核回调机制不依赖用户态代码正确性**。"

### 话术 K4：SeAccessCheck 三层

> "访问检查在 AppContainer 出现之前是**两层**——DACL 按 SID 匹配 + Mandatory Label 按 IL 数字比较。M1 里 alt desktop 报 STATUS_DLL_INIT_FAILED 就是第 2 层挂了：desktop 从父 winsta 继承 System IL 的 mandatory label，Low IL target 通不过。修法是 SDDL 里加 `S:(ML;;;;;LW)` 降 label。AppContainer 出现后加了**第三层**——LowBox token 走 Capability 检查，token 的 Package SID 和 Capability SIDs 都要作为 subject 参与。**三层与门都过才放行**，缺一不可。"

### 话术 K5：AppContainer 命名空间是内核 Object Manager 前缀劫持

> "M2 里 target 打不开 broker 造的 mutex——不是权限拒，是**根本看不到**。物理机制：AppContainer 进程写 `Global\Foo` 时**内核 Object Manager 把 Global 前缀劫持**到 `\Sessions\<n>\AppContainerNamedObjects\<pkg_sid>\Foo`，不再指向根 `\BaseNamedObjects\`。同时私有命名空间根里预置了 `Local` 和 `Session` 两个 SymbolicLink 指向自己，把这两个前缀也拉进私有空间。**target 侧完全无感知**，一样的字符串在不同主体眼里落到完全不同的物理位置。用 WinObj 展开命名空间树能亲眼看到这些 SymbolicLink——命名空间隔离机制的物理证据。"

## 十一、跟 M0/M1/M2 各章的对应关系

| 内核概念 | 用到的 milestone | 相关笔记 |
|---|---|---|
| Object Manager 生命周期 | M0（Job）/ M1（Token/WinSta/Desktop）/ M2（Firewall COM） | 本文 § 三、五 |
| HANDLE 表 & DuplicateHandle | M0（broker 持 job handle） | 本文 § 四 |
| `PsJobType.CloseProcedure = PspJobClose` | M0（KILL_ON_JOB_CLOSE） | 本文 § 六 |
| Mandatory Label ACE | M1 § 七坑 #4 | M1.md |
| AppContainer 命名空间前缀劫持 | M2 § 八 | M2.md § 八 |
| LowBox Token 的 `TOKEN_LOWBOX` 位 | M2 § 九、话术 B/B' | M2.md |
| SeAccessCheck 三层 | 全部 milestone 都用 | 本文 § 八 |

## 十二、想深挖的参考资源

- **Windows Internals 7th Ed. Part 1**（Russinovich/Solomon）：
  - Chapter 2 System Architecture（讲 Object Manager 全景）
  - Chapter 7 Security（讲 Token / SeAccessCheck 内部）
  - Chapter 6 I/O System（讲 File 对象和 IRP）
- **Alex Ionescu 博客**：`ionescu.club/blog`（AppContainer / LowBox Token 深度文章）
- **Windows Research Kernel (WRK)**：微软 2007 年公开的一份 XP-era 内核源码，Object Manager 那部分（`ntos/ob/`）现在还能读
- **WinDbg + kd 命令**：
  - `!object <addr>` — 看某个对象的 header + type
  - `!handle <h>` — 看某个 handle 指向什么
  - `!process 0 0` — 看所有进程和它们的 handle table
  - `!job <addr>` — 看 EJOB 结构
  - `!token <addr>` — 看 EPROCESS 的 primary token

## 十三、下次触发本文档的场景

以后再遇到下面这些问题，来这份笔记查：

- "为什么 `CloseHandle` 后对象还能被别人访问一小会？" → § 五 PointerCount vs HandleCount
- "为什么 M1 里 alt desktop 起不来？" → § 八 SeAccessCheck 双层 → M1.md § 七坑 #4
- "AppContainer target 为什么看不到 broker 造的对象？" → § 七 命名空间前缀劫持 → M2.md § 八
- "为什么 broker 挂了 target 自动死？" → § 六 KILL_ON_JOB_CLOSE 回调机制
- "为什么 HANDLE 不能跨进程传？" → § 四 HANDLE 是索引不是指针
- "为什么某某内核 API 需要 privilege？" → § 八 SeAccessCheck + 各类型的 `ValidAccessMask`
- "环境变量在哪、怎么传给子进程、是引用还是拷贝？" → § 九点五 PEB 与环境块（值拷贝 vs 句柄继承） → M7.md
