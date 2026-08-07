# 工具速查表：Windows 沙箱开发/调试常用工具

> M0/M1/M2 里我们已经用过或建议用的**所有工具**，按用途分类。每个工具附带：**下载/获取路径** + **典型用法** + **"什么时候用它"** + **对应我们代码里哪个场景**。
>
> 建议：把这些工具都装到手边，需要用时不假思索。

## 一、观察类（进程/内核对象/token）

### 1.1 Process Explorer ⭐⭐⭐

- **用途**：实时看进程详情，最强大的进程观察器
- **下载**：Sysinternals Suite <https://learn.microsoft.com/sysinternals/downloads/process-explorer>（免费，微软官方）
- **必备操作**：管理员启动
- **关键页面（以 hello_target 为例）**：
  - **Security 页** — 看 Token 详情
    - **顶部 User / SID** — 是 Token 的 `TokenUser` 字段（AppContainer target 依然显示你的域账号，见 M2 § 八话术 B'）
    - **Group 列表 + Flags 栏** ⭐ — 看 Package SID 那行的 Flags 是 `AppContainer` 还是 `Mandatory` —— LowBox Token 的**唯一直观证据**
    - **Mandatory Label** — 看当前完整性等级（High / Medium / Low / AppContainer）
  - **Privileges 列表** — 看 `CreateRestrictedToken` 后剩几个 privilege（M0 后应该只剩 `SeChangeNotifyPrivilege`）
  - **Job 页** — 看进程是否属于 Job、Job 上的 limits（M0 沙箱标志）
  - **Threads 页 + Stack** — 看每个线程当前调用栈；调 kernel 栈需要配符号服务器
  - **Handles 栏** — 看进程持有的所有 kernel object handle
  - **Environment 页** — 看进程的环境变量（`ChildProcessRestrictionPolicy` 之类的 attr 不在这里，那是 attr list 里的）
- **场景用法**：
  - **M0 验证**：target 是不是真的在 job 里？→ Job 页 tab 直接看
  - **M1 验证**：target IL 是不是真的降到 Low？→ Security 页 → Mandatory Label 那行
  - **M2 验证**：target 是不是 AppContainer？→ Security 页放大 → Group 列表里 Package SID 行 Flags = `AppContainer` ⭐
  - **调 crash**：target 挂了但 broker 没打错误码？→ 找到 hello_target 的 exit code
- **对应我们代码**：`m0_demo.cc` / `m1_demo.cc` / `m2_demo.cc` 起来后立刻打开 Process Explorer 观察 target
- **面试话术触发**：讲 M2 时"我用 Process Explorer 看 target token，Group 列表里 Package SID 那行 Flags 栏是 `AppContainer`，其他 group 都是 `Mandatory`"

### 1.2 WinObj ⭐⭐⭐

- **用途**：浏览 Windows 内核 Object Manager 命名空间（`\` 根目录树）
- **下载**：Sysinternals Suite <https://learn.microsoft.com/sysinternals/downloads/winobj>（免费）
- **必备操作**：管理员启动
- **关键树节点**：
  - **`\BaseNamedObjects\`** — 全局命名对象（`Global\` 前缀落这里，跨 session 可见）
  - **`\Sessions\<n>\BaseNamedObjects\`** — per-session 命名对象（`Local\` 前缀 / 无前缀落这里）
  - **`\Sessions\<n>\AppContainerNamedObjects\<pkg_sid>\`** — AppContainer 私有命名空间（M2 核心）
  - **`\ObjectTypes\`** — 所有 kernel object 类型（Process/Thread/File/Event/Mutex/Job/Token/...）
  - **`\Device\`** — I/O 设备（driver 创建）
  - **`\Sessions\<n>\Windows\WindowStations\`** — 你的 WinSta（M1 会看到 `sandbox_winsta_xxxxxxxx`）
- **场景用法**：
- **M1 验证**：alt desktop 真的建出来了吗？→ 展开 `\Sessions\1\Windows\WindowStations\` 找 `sandbox_winsta_*`
  - **M2 验证**：broker 造的 mutex 在哪、target 的私有命名空间在哪？→ 两处对照看：
    - broker 造的：`\BaseNamedObjects\WEMEET_SANDBOX_PROBE_MUTEX`（Type: Mutant）
    - target 眼里的：`\Sessions\1\AppContainerNamedObjects\S-1-15-2-...\`（里面只有 Local/Session SymLink + WilStaging_* 系列）
  - **深入 Object Manager**：所有 kernel object 到底长什么样一览无余
- **对应我们代码**：`desktop_iso.cc` 建的 winsta / `appcontainer.cc` 派生的 profile 命名空间
- **面试话术触发**："AppContainer 的命名空间隔离是内核 Object Manager 层的前缀劫持——用 WinObj 展开 `\Sessions\1\AppContainerNamedObjects\<pkg>\` 能亲眼看到 Local/Session 两个 SymbolicLink 指向自己"

### 1.3 Process Monitor (ProcMon)

- **用途**：实时监控进程的 4 类操作 — 文件 / 注册表 / 网络 / 进程/线程事件
- **下载**：Sysinternals Suite <https://learn.microsoft.com/sysinternals/downloads/procmon>
- **必备操作**：管理员启动；**必须先加 filter** 否则事件洪水
- **典型 filter**：
  - `Process Name is hello_target.exe` — 只看 target
  - `Result is ACCESS DENIED` — 只看失败的操作（**M0/M1/M2 沙箱验证利器**）
  - `Operation is CreateFile` — 只看文件打开
- **场景用法**：
  - **M1 验证**：Low IL target 尝试写用户桌面文件 → 看事件 `CreateFile ... Result: ACCESS DENIED`（gle=5 的现场）
  - **调 mitigation 拦截**：BLOCK_NON_MICROSOFT_BINARIES 拦下某个 DLL → ProcMon 记录 `Load Image` 事件失败
  - **抓 target 到底想访问什么资源**：M4/M5/M8 时用来"照见"target 的行为
- **对应我们代码**：hello_target 的 7 个 jailbreak 测试
- **面试话术触发**："我用 ProcMon 加 filter `Process=hello_target Result=ACCESS DENIED`，直接看到 Low IL 拦了哪些文件访问"

### 1.4 regedit

- **用途**：查看/编辑 Windows 注册表
- **来源**：系统自带
- **场景用法**：
  - **M2 验证 AppContainer profile 落地**：`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\<profile_name>` — 看 `Sid`、`Moniker`、`Capabilities` 值
  - **看沙箱相关注册表**：`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\` 底下有很多 Windows 启动相关的键
- **对应我们代码**：`CreateAppContainerProfile` 的落地位置
- **面试话术触发**："我用 regedit 确认了 `CreateAppContainerProfile` 落地的位置——`HKCU\...\AppContainer\Storage\com.wemeet.sandbox.demo.m2\` 里存了 profile 元信息 + Package SID"

### 1.5 Task Manager（任务管理器）

- **用途**：最基础的进程列表
- **来源**：系统自带（Ctrl+Shift+Esc）
- **场景用法**：
  - **快速看 target PID / CPU / 内存**
  - **强杀卡死的 target** 或 broker
- **局限**：**不显示 Token/Job 详情**——那种深度只能靠 Process Explorer

## 二、静态分析类（exe/dll 依赖）

### 2.1 dumpbin ⭐

- **用途**：dump PE 文件的元信息（依赖 DLL / 导出表 / 导入表 / section）
- **来源**：Visual Studio 自带，路径类似 `C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\<版本>\bin\Hostx64\x64\dumpbin.exe`
- **常用命令**：
  ```
  dumpbin /dependents hello_target.exe   # 看 target 依赖哪些 DLL
  dumpbin /imports  hello_target.exe    # 详细的导入符号（哪个函数从哪个 DLL 来）
  dumpbin /exports  unsigned_probe.dll  # 看 DLL 导出了什么符号
  dumpbin /headers  hello_target.exe     # 看 PE header（subsystem / entry point / image base）
  ```
- **场景用法**：
  - **M1 踩坑 #1 排查**：`BLOCK_NON_MICROSOFT_BINARIES` 报 0xC0000142 → `dumpbin /dependents hello_target.exe` 一看依赖 `VCRUNTIME140D.dll` 等 debug CRT DLL → 判断出是它们不带微软签名被拦
  - **改用静态 CRT 后再看**：应该只剩 `KERNEL32/ADVAPI32/USER32/WS2_32/OLE32/OLEAUT32`（都是微软根签名）
- **对应我们代码**：M1 加 `MSVC_RUNTIME_LIBRARY = MultiThreaded$<$<CONFIG:Debug>:Debug>` 那次踩坑
- **面试话术触发**："M1 里 BLOCK_NON_MICROSOFT_BINARIES 报 0xC0000142，我用 dumpbin /dependents 一看 target 依赖 vcruntime140d.dll—— debug CRT 不带微软根签名"

### 2.2 PE Explorer / CFF Explorer（可选，图形版）

- **用途**：图形化查看 PE 文件（比 dumpbin 直观）
- **下载**：CFF Explorer 免费 <https://ntcore.com/?page_id=388>
- **场景用法**：想看 PE 结构但懒得记 dumpbin 命令时

## 三、命令行/PowerShell 类

### 3.1 PowerShell (with admin) ⭐⭐

- **用途**：日常自动化 + 查看 Windows 各种系统状态
- **来源**：系统自带
- **必备命令（沙箱开发）**：
  ```powershell
  # 查看进程 token 情况
  Get-Process hello_target | Select-Object *
  
  # 查看 Windows Firewall 状态
  Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultOutboundAction
  Get-NetFirewallRule -DisplayName 'sandbox_demo_m2_block_outbound' | Format-List
  Get-NetFirewallRule -DisplayName 'sandbox_demo_m2_block_outbound' | Get-NetFirewallApplicationFilter
  
  # 查看 AppContainer profile
  Get-ChildItem 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage'
  
  # 查看 Windows 事件日志（Application 类别下的错误）
  Get-WinEvent -FilterHashtable @{LogName='Application';Level=2} -MaxEvents 5
  
  # 系统信息
  systeminfo
  Get-ComputerInfo
  
  # 强杀相关进程
  Get-Process hello_target,m0_demo,m1_demo,m2_demo,WerFault -ErrorAction SilentlyContinue | Stop-Process -Force
  ```
- **场景用法**：
  - **M2 验证 firewall 规则**：加规则后用 `Get-NetFirewallRule + Get-NetFirewallApplicationFilter` 确认 `Package = S-1-15-2-...` 绑定成功
  - **bisect 脚本化**：M1 里我们写了 PowerShell 脚本一键跑 9 档 `--strict N` 组合
  - **杀干净残留进程**：`Get-Process ... | Stop-Process`

### 3.2 cmd（普通命令行）

- **用途**：主要是跑 `.bat` 文件
- **来源**：系统自带
- **场景用法**：`run.bat` / `run_m1.bat` / `run_m2.bat` 都是 cmd 脚本

## 四、编译/构建

### 4.1 CMake ⭐

- **用途**：跨平台构建系统
- **下载**：<https://cmake.org/download/>
- **场景用法**：
  ```powershell
  cd sandbox_demo
  cmake -S . -B build_m0 -A x64       # 生成 VS 项目
  cmake --build build_m0 --config Debug   # 编译
  ```
- **对应我们代码**：`CMakeLists.txt`（含 M2 加的 firewall 静态 CRT / m2_demo target 等）

### 4.2 Visual Studio 2022 ⭐

- **用途**：IDE + MSVC 编译器
- **下载**：<https://visualstudio.microsoft.com/vs/community/>（社区版免费）
- **场景用法**：
  - CMake 生成的 .sln 直接打开
  - 断点调试 broker / target
- **注意**：Community 版 licence 允许个人和小团队使用

### 4.3 clang-format

- **用途**：代码自动格式化
- **路径**：VS 2022 自带 `C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\Llvm\x64\bin\clang-format.exe`
- **场景用法**：保存前跑一遍格式化，代码风格统一
  ```powershell
  clang-format -i -style=file src/**/*.cc src/**/*.h
  ```

## 五、调试类

### 5.1 WinDbg (Preview 版) ⭐⭐

- **用途**：**Windows 内核/用户态调试器**——查看 token / handle / kernel object 内部
- **下载**：Microsoft Store 搜 "WinDbg"（免费）
- **典型场景（M2/M4/M5/M9 会大量用到）**：
  - `!token` — 打印当前进程 token 完整信息（TokenIsAppContainer 位 / Package SID / Groups）
  - `!handle 0x<h>` — 看某个 handle 指向的 object 类型 + refcount
  - `!object <addr>` — 看某个 object 的 header + type
  - `!process 0 0` — 列所有进程（handle table 位置也在这里）
  - `!job <ejob_addr>` — 看 EJOB 结构（ProcessListHead / LimitFlags / KILL_ON_JOB_CLOSE）
  - `dt nt!_TOKEN <addr>` — 结构化 dump 内核 TOKEN 结构
  - `dt nt!_EPROCESS <addr>` — dump EPROCESS
  - `.sympath srv*C:\symbols*http://msdl.microsoft.com/download/symbols` — 配符号服务器
  - `!analyze -v` — 分析 crash dump
- **配置一次终身受益**：
  1. 装 WDK（Windows Driver Kit）—— 附带 symbol store 工具
  2. 环境变量 `_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols`
  3. WinDbg 里输入 `.reload /f` 强制加载所有符号
- **场景用法**：
  - **M2 验证 LowBox Token**：`!token` 看 `TokenIsAppContainer = 1` + `Package = <pkg_sid>` —— 内核层证据
  - **M4 调注入**：断在 `LoadLibraryW` 看远程线程是不是真的进了 target
  - **M9 调 minifilter driver**：kernel debug 唯一选择
- **对应我们代码**：所有 milestone 都可以用它验证内核层实现
- **面试话术触发**："我用 WinDbg 敲 !token 看过 target 的 kernel TOKEN 结构，TokenIsAppContainer 位是 1，Package 字段指向 Package SID"（如果你做过）

### 5.2 Visual Studio 调试器

- **用途**：日常用户态源码级调试
- **来源**：VS 2022 自带
- **场景用法**：
  - 断点 broker 的 `CreateProcess` 前，看 attr list 内容
  - Attach 到 target 看它执行到哪一步（如果它没被 mitigation 拦下）

### 5.3 gflags (Global Flags Editor)

- **用途**：给某个 exe 打调试标志（加载器 debug / heap debug / dump loading）
- **来源**：WDK 或 Debugging Tools for Windows 里
- **常用场景**：`gflags /i hello_target.exe +sls` 打开 loader snap（可以看到 target 加载每个 DLL 的详细过程 —— **M1 排查 0xC0000142 神器**）
- **对应我们代码**：M1 踩 4 个 0xC0000142 坑时可用它精确定位是加载哪个 DLL 挂了

## 六、Windows 内建管理工具

### 6.1 事件查看器 (eventvwr.msc)

- **用途**：查看系统/应用事件日志
- **来源**：系统自带
- **常看**：
  - `Windows Logs → Application` — 应用崩溃事件（0xC0000142 会写在这）
  - `Applications and Services Logs → Microsoft → Windows → SecurityAuditing` — 审计事件
  - `Windows Filtering Platform` — WFP 事件（M4/M6 用）
- **场景用法**：M1 target 报 0xC0000142 后来这里找详细 stacktrace（如果 WER 写了）

### 6.2 Windows Defender Firewall (wf.msc) ⭐

- **用途**：图形化查看防火墙规则
- **来源**：系统自带
- **场景用法**：
  - **M2 加餐补丁验证**：wf.msc → 右键 Outbound Rules → 找 `sandbox_demo_m2_block_outbound` → 右键 Properties → Programs and Services / Protocols and Ports 各页看细节
  - 手工加规则测试
- **对应我们代码**：`core/firewall.cc` 的 `INetFwPolicy2::Rules::Add` 落地效果

### 6.3 secpol.msc / gpedit.msc

- **用途**：本地安全策略 / 组策略编辑器
- **来源**：Windows 专业版及以上
- **场景用法**：
  - 查看/调整 UAC 设置
  - 修改 Windows Defender / Firewall 全局策略
  - 查看审计策略

### 6.4 services.msc

- **用途**：查看 Windows 服务列表
- **来源**：系统自带
- **场景用法**：确认 `Windows Defender Firewall (mpssvc)` 服务正在跑（M2 加餐 firewall 规则的前提）

## 七、Windows SDK 相关

### 7.1 Windows SDK（含 Debugging Tools）

- **下载**：<https://developer.microsoft.com/windows/downloads/windows-sdk/>
- **提供**：
  - **头文件**：`netfw.h`（M2 `INetFwPolicy2`）/ `winuser.h` / `winbase.h` / `sddl.h` / `securityappcontainer.h`（AppContainer API）
  - **导入库**：`user32.lib` / `advapi32.lib` / `ws2_32.lib` / `ole32.lib` / `oleaut32.lib`
  - **`dumpbin.exe`**（也在 MSVC 里）
  - **`signtool.exe`**：签名工具（M5 反注入验证 DLL 签名会用）
- **典型路径**：`C:\Program Files (x86)\Windows Kits\10\Include\<version>\um\`

### 7.2 WDK (Windows Driver Kit)

- **下载**：<https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk>
- **场景用法**：**M9 内核 minifilter 驱动开发的必需品**
- **提供**：
  - 驱动开发头文件 + 库
  - 内核调试符号
  - `minispy` / `swapbuffers` 等 minifilter 示例
  - `sc create` / `fltmc load` 等驱动加载工具

## 八、外部好用的分析工具（可选）

### 8.1 API Monitor（rohitab）

- **下载**：<http://www.rohitab.com/apimonitor>（免费）
- **用途**：拦截并显示进程调用的 Windows API 及参数
- **场景用法**：想不动源码知道 target 调了哪些 API 就用它

### 8.2 x64dbg

- **下载**：<https://x64dbg.com/>（免费开源）
- **用途**：反汇编 + 动态调试（Ollydbg 后继者）
- **场景用法**：分析可疑二进制、debug 无源码程序

### 8.3 IDA Free / Ghidra

- **IDA Free**：<https://hex-rays.com/ida-free/>（免费版够用）
- **Ghidra**：<https://ghidra-sre.org/>（NSA 开源，免费）
- **场景用法**：**M4 反注入研究时对可疑注入 DLL 做静态分析** / 深入 kernel32 反编译看 API 内部实现

### 8.4 Sysinternals Suite（合集）

- **下载**：<https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite>
- **包含**（除了前面提到的 Process Explorer / ProcMon / WinObj，还有）：
  - **Handle.exe** — 命令行版查 handle
  - **PsExec.exe** — 远程/本地起进程（多种 token 模式）
  - **Autoruns.exe** — 看开机自启项（M5 反注入排查用）
  - **Streams.exe** — 看 NTFS 备用数据流（ADS）
  - **AccessChk.exe** — 查某个 SID 对某个对象的访问权
- **建议**：所有 Sysinternals 工具都拷进一个目录加进 PATH

## 九、按 milestone 分组的"最常用工具三件套"

**M0（Job + Restricted Token）**：
1. Process Explorer（Job 页 + Security 页）
2. cmd（跑 `run.bat`）
3. 事件查看器（如果 target 挂了）

**M1（Low IL + Mitigation + Alt Desktop）**：
1. **dumpbin** ⭐（排查 BLOCK_NON_MICROSOFT_BINARIES）
2. Process Explorer（Mandatory Label / Threads 页看 WinSta）
3. **WinObj** ⭐（看 alt winsta 是不是真建出来了）
4. PowerShell（bisect 脚本 `--strict N` 组合）

**M2（AppContainer + Firewall）**：
1. **Process Explorer** ⭐⭐（放大看 Package SID Flags = `AppContainer`）
2. **WinObj** ⭐⭐（`\Sessions\1\AppContainerNamedObjects\<pkg>\` vs `\BaseNamedObjects\`）
3. **regedit**（AppContainer Storage 落地位置）
4. **PowerShell + wf.msc** ⭐（验证 firewall 规则）

**M3-M9（预告）**：
- M3 IPC：ProcMon（看 named pipe 事件）
- M4 注入：API Monitor / WinDbg
- M5 反注入：Autoruns / signtool
- M6 WFP：wf.msc / WFP tracing
- M9 minifilter：**WinDbg + WDK**（kernel debug）

## 十、装机建议清单（按优先级）

**⭐⭐⭐ 必装**：
- Visual Studio 2022 Community + Windows SDK
- Sysinternals Suite（Process Explorer / WinObj / ProcMon）
- CMake
- WinDbg (Preview 版，Microsoft Store)

**⭐⭐ 强烈建议**：
- clang-format（VS 自带）
- WDK（M9 之前必装）

**⭐ 想深挖时装**：
- x64dbg
- API Monitor
- IDA Free / Ghidra
- gflags（WDK 附带）

## 十一、面试话术：工具熟练度是加分项

> "调试沙箱代码我用一整套工具协同——**Process Explorer 看进程 token 的 Group + Flags**，**WinObj 看内核对象命名空间和符号链接结构**，**ProcMon 加 filter 抓 target 的 ACCESS_DENIED 事件**，**dumpbin 查 exe 依赖排查签名问题**，**wf.msc + PowerShell Get-NetFirewallRule 验证防火墙规则落地**，**WinDbg !token / !object 看内核对象层**。**每一层沙箱效果我都能定位到具体的观察点**——不是'我调了 API 应该会拦'，而是'我用工具亲眼看到内核在这里拦下'。"

**这段话讲出来**面试官会立刻明白你不是照抄 API，而是"能观察 + 能验证"的完整工程师。

## 十二、快速查阅索引（按你脑子里的问题）

| 你问 | 用哪个工具 |
|---|---|
| "target 到底是不是 AppContainer？" | Process Explorer → Security 页 → Group 列表 |
| "命名空间隔离真的生效吗？" | WinObj → `\Sessions\1\AppContainerNamedObjects\<pkg>\` |
| "target 想访问什么资源？" | ProcMon + filter |
| "target 依赖哪些 DLL？为什么加载失败？" | dumpbin /dependents |
| "firewall 规则真的加进去了吗？" | wf.msc 或 PowerShell Get-NetFirewallRule |
| "AppContainer profile 落地在哪？" | regedit 到 `HKCU\...\AppContainer\Storage` |
| "target 崩了，为什么？" | Process Explorer 看 exit code + 事件查看器 |
| "kernel token 结构长啥样？" | WinDbg !token |
| "target 加载 DLL 的详细过程？" | gflags +sls 打开 loader snap |
