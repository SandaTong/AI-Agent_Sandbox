# M4 附加知识笔记（消化 M4 时的深挖）

> 这份是 [`M4.md`](M4.md) 的补充。M4 主文档讲"怎么做"，这份讲消化过程中两个"为什么"的深挖：
>
> 1. Inline Hook 和 OC Method Swizzling 到底是不是一回事？
> 2. 为什么 broker 里取的 `LoadLibraryW` 地址能直接喂给 target 用？（kernel32 共享基址原理）
>
> 都是面试延伸高频点，值得单独沉淀。

---

## 一、Inline Hook vs OC Method Swizzling —— 相似的意图，不同的层级

消化 `sandbox_hook.cc` 时的一个直觉类比：`MH_CreateHookApi` 这段是不是很像 OC 的方法交换（Method Swizzling）？

**结论：意图相同（都是"拦截 + 替换 + 选择性放行原逻辑"），但实现层级差一个抽象层。**

### 1.1 相似点：同一个灵魂

两者都是 hooking / 拦截，核心思想都是：

```
调用方 ──想调 A──►  [被我们改了]  ──►  实际先进 B(我的) ──►(可选)回头调 A
```

- Swizzling：`method_exchangeImplementations` 交换两个 selector 的 IMP
- Inline Hook：把 `CreateFileW` 导向 `HookedCreateFileW`，钩子里再调原函数

### 1.2 关键区别：改"高层表"还是改"底层机器码"

| 维度 | OC Method Swizzling | MinHook Inline Hook（本项目） |
|---|---|---|
| **改什么** | 改 `Class` 的**方法表**（IMP 指针数组里的一项） | 改**函数机器码本身**——`CreateFileW` 头几字节覆写成 `jmp 我的函数` |
| **依赖的机制** | OC 运行时的**动态消息派发**（`objc_msgSend` 查 selector→IMP） | 无任何运行时协助，直接改内存里的 x86/x64 指令 |
| **改的位置** | 一张**数据表**（IMP 指针） | **可执行代码段**（`.text`） |
| **粒度** | 按 selector（方法名） | 按函数地址 |
| **需不需要语言运行时** | **需要**（离开 OC runtime 就没这机制） | **不需要**（C/汇编级别，对任何原生函数都能干） |
| **反汇编能看出被改吗** | ❌ 方法机器码一字节没变，变的是 runtime 那张表 | ✅ 函数头第一条指令变成 `jmp`（x64dbg 里肉眼可见） |

### 1.3 一句话点破本质

- **Swizzling 是"合法换岗"**：OC runtime 本来就设计成"方法调用要查表决定跳哪"，你只是**合法地改了那张表的一项**。你没碰任何机器码，是在 runtime 允许的框架内操作。
- **Inline Hook 是"拦路改道"**：`CreateFileW` 是一段**编译死的机器码**，调用方硬编码跳到它的地址，没有任何"表"给你改。所以 MinHook 只能**动手术改机器码本身**——把开头覆写成一条 `jmp`，硬生生把执行流劫走。

这正是为什么 x64dbg 里能看到 `CreateFileW` 第一条指令变成了 `jmp`——**代码被物理改写了**；而 Swizzling 你在反汇编里看方法机器码一个字节都没变。

### 1.4 更贴切的 OC 对应物（类比谱系）

如果一定要在苹果生态找 Inline Hook 的**真正对应物**，不是 Swizzling，而是改机器码的库：

```
改高层表（最温和）        改绑定/符号表      改机器码（最底层/最通用）
OC Method Swizzling  <  fishhook / IAT Hook  <  MinHook Inline Hook / Dobby / frida-gum
```

- `fishhook`（Facebook）：hook C 函数，改的是 Mach-O 的**符号表 / lazy binding 指针**——比 Swizzling 底层，但仍是改"绑定表"，不是改机器码。
- `Dobby` / `frida-gum` 的 inline hook：才是和 MinHook 同级的"改机器码"手法。

**Windows 侧的对照**：IAT Hook（改导入地址表）≈ fishhook 那一档（改表，不碰指令），Inline Hook（MinHook）才是改机器码那一档。

### 1.5 回到 `sandbox_hook.cc:115-121` 两步动作

MinHook 内部把"登记"和"动手"分成了两步，正好对应上面的层级区别：

```cpp
MH_CreateHookApi(L"kernel32", "CreateFileW", &HookedCreateFileW, &g_orig_CreateFileW);  // 第 116 行
MH_EnableHook(MH_ALL_HOOKS);         // 第 121 行
```

1. **`MH_CreateHookApi`**：只是"**登记**"——按模块名+函数名找到 `CreateFileW` 地址，记下"以后导向 `HookedCreateFileW`"，并生成 trampoline。**此刻还没改任何机器码**（这一步最像 Swizzling 的"准备交换"，但还没动手）。
2. **`MH_EnableHook`**：**这一步才真正改机器码**——反汇编 CreateFileW 头部、算好覆盖几个字节、写入 `jmp`。**这是 Swizzling 完全没有的动作**。

---

## 一.5、"头字节改成 jmp"到底做了什么？—— 调用时序对比

`MH_EnableHook` 把 `CreateFileW` **开头几个字节**覆写成一条 `jmp HookedCreateFileW`。这一条 jmp 是整个 inline hook 的开关。下面对比"改前 / 改后"调用链的分岔。

### 1.5.1 没改（正常状态）—— 直达

```
target 调 CreateFileW(path)
     │
     ▼
CreateFileW 入口 @0x7FFC12345000
     │  mov  r10, rcx          ← 原始第 1 条指令
     │  mov  eax, 0x55         ← 原始第 2 条指令
     │  syscall / ...      ← 继续原始逻辑（真正打开文件）
     ▼
返回 target
```

调用方硬编码跳到 CreateFileW 地址，从第一条指令老实执行，直接返回。**没有任何人插进来。**

### 1.5.2 改了（hook 状态）—— 被劫持到钩子，再由钩子决定放行

`MH_EnableHook` 干了两件事：
- 把 CreateFileW **入口头字节**覆写成 `jmp HookedCreateFileW`；
- 把**被覆盖掉的原始指令**搬到一块叫 **trampoline（蹦床）** 的新内存保存，trampoline 末尾接一条 `jmp` 跳回 CreateFileW 未被覆盖的部分。`g_orig_CreateFileW` 就指向这个 trampoline。

```
target 调 CreateFileW(path)
 │
     ▼
CreateFileW 入口 @0x7FFC12345000
     │  jmp HookedCreateFileW    ← ⭐ 头字节被改成这条！执行流一进门就被劫走
     ▼
HookedCreateFileW（我们的钩子，在 sandbox_hook.dll 里）
     │  HookLog(记录 path)       ← 插入我们的逻辑（观察 / 策略检查）
     │  ...
 │  return g_orig_CreateFileW(path)        ← 想放行，就调 trampoline
     │         │
     │ ▼
     │      trampoline（MinHook 分配的新内存）
     │              │  mov  r10, rcx           ← 被 jmp 覆盖掉的那几条原始指令，搬到这里
     │      │  mov  eax, 0x55
     │            │  jmp  CreateFileW+N  ← 跳回 CreateFileW 未被覆盖的部分（第 N 字节起）
     │       ▼
     │      CreateFileW+N
     │ │  syscall / ...            ← 继续原始逻辑，真正打开文件
     │    ▼
     │            返回 → 回到 HookedCreateFileW
     │  （钩子拿到原函数返回值，可再加工/放行）
  ▼
返回 target（target 毫无感知，以为自己直接调了 CreateFileW）
```

### 1.5.3 一句话对比分岔

- **没改**：`调用方 → CreateFileW → 返回`（直线）
- **改了**：`调用方 → CreateFileW入口的 jmp → 钩子 →（放行时）trampoline → CreateFileW剩余部分 → 回钩子 → 返回`（绕一大圈，但对调用方完全透明）

### 1.5.4 三个必须理解的点

**① 为什么头字节改 `jmp` 就能劫持？**
调用方硬编码跳到 CreateFileW 地址、**从第一条指令开始执行**。把第一条指令换成 `jmp 钩子`，执行流一进门就被带走——调用方完全不知情，连"我被改道了"都感觉不到。

**② trampoline（蹦床）为什么非要它？**
因为 `jmp` **覆盖并破坏了** CreateFileW 开头的原始指令。钩子里若想执行"原始 CreateFileW"，直接跳回 CreateFileW 入口会**死循环**（一进门又是那条 jmp → 又跳回钩子……）。所以把"被覆盖的原始指令 + 一条跳回未覆盖部分的 jmp"另存到 trampoline，`g_orig_CreateFileW` 指向它。调它 = 执行完整原始逻辑，且**绕过入口那条 jmp**，不会再触发钩子。

→ 这就是 `sandbox_hook.cc` 那条铁律的物理根源：**钩子内部调原函数必须走 `g_orig_`（trampoline），不能走 `CreateFileW`（否则无限递归崩溃）**。

**③ jmp 覆盖几个字节？为什么需要反汇编引擎（hde64）？**
x64 下 `jmp rel32` 是 5 字节。但**不能只覆盖 5 字节就停**——必须覆盖到**完整指令的边界**。假设 CreateFileW 开头是 `mov r10,rcx`(3字节) + `mov eax,0x55`(5字节)，要塞 5 字节 jmp 就得覆盖到第 8 字节（两条完整指令都盖住），不能停在第 5 字节切断第二条 `mov` 中间——否则搬进 trampoline 的是半条残指令，一执行就崩。**hde64 反汇编引擎就是算"从头凑够 ≥5 字节最少吃掉几条完整指令"的**。这是 inline hook 比 Swizzling 麻烦得多的核心原因（Swizzling 只换 IMP 指针，不碰指令边界）。

---

## 二、为什么 broker 取的 `LoadLibraryW` 地址能直接喂给 target？—— kernel32 共享基址原理

这是远程线程注入（`injector.cc` 第 49-55 行）的**地基假设**。当时的一句话结论：

> kernel32.dll 在同一次开机的所有进程里加载基址相同，所以 broker 里算出的 LoadLibraryW 地址在 target 里同样有效。

下面把这句话彻底拆开。

### 2.1 先破除一个常见误解

**❌ 错误想象**：每个进程各自加载一份 kernel32，基址各不相同。

```
broker 进程           target 进程
┌──────────────┐   ┌──────────────┐
│ kernel32 @ A │          │ kernel32 @ B │   ← 若 A ≠ B，注入就不成立
└──────────────┘        └──────────────┘
```

**✅ 真实情况**：同一次开机内，所有进程的 kernel32 **虚拟基址是同一个值**，而且**物理内存里只有一份**。

```
✅ 同一次开机内，所有进程的 kernel32 虚拟基址都 = 0x7FFC_1234_0000（举例）
broker 进程        target 进程
┌──────────────────┐            ┌──────────────────┐
│ kernel32         │            │ kernel32      │
│ @ 0x7FFC12340000 │            │ @ 0x7FFC12340000 │  ← 虚拟地址完全相同！
└────────┬─────────┘            └────────┬─────────┘
         │ │
         └───────────┐       ┌───────────┘
   ▼     ▼
     物理内存里其实是同一份（共享页）
              ┌─────────────────────────┐
          │ kernel32.dll 的物理页    │  ← 全系统只有一份拷贝
              │ （LoadLibraryW 在这里）  │
              └─────────────────────────┘
```

所以 `LoadLibraryW` 的虚拟地址在 broker 和 target 里**是同一个数值**，broker 算出来直接喂给 target 就对了。

### 2.2 单进程虚拟地址空间布局（64 位）

```
target 进程的虚拟地址空间（每个进程都有自己独立的一套 0 ~ 2^47）
┌────────────────────────────────────────┐ 0x00000000_00000000
│  你的 exe 映像 (hello_target.exe)     │ ← 每进程可以不同
│  堆 / 栈 / 你自己的 DLL           │ ← 每进程基址可能不同
├────────────────────────────────────────┤
│  ntdll.dll      @ 0x7FFC_AAAA_0000    │ ┐
│  kernel32.dll   @ 0x7FFC_1234_0000       │ ├ ⭐ 系统核心 DLL
│  kernelbase.dll @ 0x7FFC_5678_0000       │ │   这几个的基址全系统统一
│  ...             │ ┘
└────────────────────────────────────────┘ 0x00007FFF_FFFFFFFF
```

**要点**：虚拟地址是每进程独立的一套（靠各自页表映射）。但对 kernel32 这类系统 DLL，Windows **让所有进程的页表都把这个虚拟地址映射到同一份物理内存**，且**保证这个虚拟地址值全系统一致**。

### 2.3 为什么物理上只有一份？——共享只读页

kernel32 的代码段（`.text`，含 LoadLibraryW 的机器码）是**只读、不可改**的。大家用的都是同一份只读代码，没必要每个进程复制一遍——**物理内存加载一份，所有进程的页表都指向它**（共享内存页 + copy-on-write）。

→ **"为什么共享"的答案：省内存。** 全系统几百个进程都用 kernel32，复制几百份纯属浪费。

### 2.4 为什么虚拟基址也统一？是不是故意设计的？——是，刻意为之

关键在 ASLR 对**两类东西**的不同处理粒度：

```
         什么时候随机基址？
┌─────────────────────────────────────────────────────────────┐
│ 类别 A：系统核心 DLL（kernel32/ntdll/kernelbase/user32...）    │
│   随机时机：★ 每次系统启动随机一次   │
│   作用范围：这一次开机内，所有进程共用这个随机出来的基址     │
│   → 所以 broker 和 target 的 kernel32 基址相同       │
├─────────────────────────────────────────────────────────────┤
│ 类别 B：普通 DLL / EXE（你自己的 exe、你自己写的 dll） │
│   随机时机：★ 每次加载可能重新随机（视 /DYNAMICBASE 等）      │
│   作用范围：进程之间可能不同      │
│   → 所以不能拿 broker 里"你自己 dll 的地址"去喂 target      │
└─────────────────────────────────────────────────────────────┘
```

系统 DLL 设计成"开机随机一次、全系统统一"的两个动机：

- **动机 1（内存/性能）**：让共享页成为可能。若 kernel32 每进程虚拟基址不同，"物理一份大家共享"就要大量重定位修补、破坏共享。基址全系统统一 → 物理页**原样共享**，一个字节不用改。
- **动机 2（安全够用）**：ASLR 的目标是攻击者**无法预测**关键函数地址、不能跨重启硬编码 exploit。这只要求"每次开机变一次"就够了，**不需要每进程都不一样**。

**折中结论**：系统 DLL = **开机随机一次 + 全系统统一基址**。既拿到 ASLR 安全收益（攻击者不能跨重启预测），又保住共享页的内存/性能收益。**这是安全与性能的刻意折中。**

### 2.5 "开机随机一次"图解

```
第一次开机              重启后（第二次开机）
───────────── ──────────────────
系统启动掷骰子：          系统启动重新掷骰子：
kernel32 = 0x7FFC_1234_0000          kernel32 = 0x7FF9_ABCD_0000  ← 变了！
        │              │
        ├─ broker  = 0x7FFC12340000          ├─ broker  = 0x7FF9ABCD0000
        ├─ target  = 0x7FFC12340000          ├─ target  = 0x7FF9ABCD0000
 └─ 记事本   = 0x7FFC12340000          └─ 记事本  = 0x7FF9ABCD0000
       （本次开机内所有进程一致）             （本次又都一致，但和上次不同）
```

- **同一次开机内**：broker 和 target 的 kernel32 基址必然相同 → 注入成立。
- **跨重启**：基址会变，但注入代码不硬编码地址（运行时 `GetProcAddress` 现算），照样成立。

### 2.6 回到注入代码：为什么必须运行时取地址

```cpp
// injector.cc 第 51-55 行
HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");         // broker 自己的 kernel32
auto load_library = ::GetProcAddress(k32, "LoadLibraryW");  // broker 里现算的地址
// ...
CreateRemoteThread(target, ..., load_library, remote_mem, ...);  // 直接喂给 target
```

- broker `GetProcAddress` 算出的地址 = `kernel32基址 + LoadLibraryW偏移`
- 因为 target 的 kernel32 基址 = broker 的（本次开机统一）、偏移是 DLL 内部固定的
- 所以这个地址值在 target 里**正好指向 target 自己那份 kernel32 的 LoadLibraryW** → 远程线程能正确执行

**反例（为什么不能借你自己的 dll）**：你在 broker 里 `LoadLibrary("mydll")` 拿到地址 X——但 target 里可能根本没加载 mydll，就算加载了基址也可能不是 X（类别 B，每加载可能重随机）。喂 X 给 target 远程线程 = 跳到 target 里一个无意义地址 → 崩。**所以注入只能借全系统基址统一的 kernel32/ntdll 的导出函数**（LoadLibraryW 住在 kernel32，天选之子）。

### 2.7 一句话总结

> kernel32 全系统**物理只有一份**（共享只读页省内存），且 ASLR 对它是"**每次开机随机一次基址、这次开机内所有进程统一**"（安全够用 + 保住共享）。这个"统一基址"是**刻意设计**的折中，它让 broker 里算出的 `LoadLibraryW` 地址能直接在 target 里生效——这就是远程线程注入的地基。

---

## 二.5、更底层：PE 装载 / 导入表 / 导出表 / IAT

上面 §二 讲的"kernel32 装在哪个基址、能不能共享"，再往下一层就是 **PE 装载**。M4 的注入、两种 hook、共享基址，根子全在这里。

### 2.5.1 进程虚拟地址空间 = 一堆 PE 映像 + 动态内存

进程地址空间里的每一块，几乎都来自某个 PE（Portable Executable，Windows 可执行文件格式：.exe / .dll）的一次装载：

```
target 进程虚拟地址空间
┌────────────────────────────────────────┐
│  hello_target.exe 映像                  │ ← PE 装载（主模块，第一个装的）
│    .text（代码）.data（数据）.rdata...│
├────────────────────────────────────────┤
│  堆 / 栈 / TEB / PEB                     │ ← 运行时动态分配，不是 PE
├────────────────────────────────────────┤
│  ntdll.dll / kernel32.dll / kernelbase  │ ← PE 装载（系统 DLL）
│  sandbox_hook.dll 映像                  │ ← ⭐ PE 装载（M4 注入进来的）
├────────────────────────────────────────┤
│  VirtualAllocEx 分配的那块（存 DLL 路径）│ ← 裸内存，不是 PE
└────────────────────────────────────────┘
```

把磁盘上的 PE 变成地址空间里"能跑的映像"，这个过程叫 **PE 装载（image mapping）**，由 ntdll 里的加载器（Ldr）完成。

### 2.5.2 PE 装载做的4 步（每步都对应一个 M4 知识点）

| 步骤 | 加载器做什么 | 对应 M4 知识点 |
|---|---|---|
| 1. **映射节** | 按 PE 头把 `.text`/`.data`/`.rdata` 映射到虚拟地址，各节带内存权限 | `.text` 只读 → 系统 DLL 可**共享物理页**（§二） |
| 2. **重定位** | 实际基址≠首选ImageBase 时，按 `.reloc` 修正硬编码绝对地址 | 系统 DLL 基址统一免重定位（类别 A）；自己的 dll 每次重定位（类别 B） |
| 3. **解析导入表** | 读导入表清单，装载依赖 DLL，把函数真实地址填进 IAT | **IAT Hook 的战场**（§一类比谱系中间档） |
| 4. **调入口点** | exe → CRT → main；**dll → DllMain** | ⭐ 注入链条终点：`LoadLibraryW(hook.dll)` →装载 → 调 `DllMain`装 hook |

**关键结论**：`LoadLibraryW` 本质 = **运行时触发一次完整的 PE 装载 + 调 DllMain**。你M4 的注入（injector.cc 让 target 远程线程调 LoadLibraryW）就是"运行时硬塞一次 PE 装载"。

### 2.5.3 三张表别搞混：导入表 / IAT / 导出表

| 表 | 在谁的 PE 里 | 作用 | 谁来读| 何时定|
|---|---|---|---|---|
| **导入表**（Import Directory） | 调用方（你的 exe） | "我要用别人哪些函数"的**名字清单** | 加载器 | **构建期**（链接器写死） |
| **IAT**（Import Address Table） | 调用方（你的 exe） | 给导入表每个函数**填真实地址** | 你的代码取地址用 | **加载期**（加载器填） |
| **导出表**（Export Table） | 被调方（那个 dll） | "我对外提供哪些函数"的清单 | `GetProcAddress` / 加载器 | 被调 dll 构建期 |

一句话：**导入表=要谁（名字），IAT=谁在哪（地址，运行时填），导出表=我提供谁（被调方的对外清单）。**

### 2.5.4 静态导入 vs 动态调用（LoadLibrary/GetProcAddress）—— 两条完全不同的路

一个高频疑问：**动态调用的函数怎么写进导入表？** 答案是——**它根本不进导入表**。静态和动态是两套机制：

```
                        想调用一个 DLL 里的函数
          ┌───────────────────────┴───────────────────────┐
          ▼▼
   路 A：静态导入                                    路 B：动态调用
   （构建期就知道调谁）                              （运行期才决定调谁）
          │                                                │
   编译器：生成 call [__imp_Func]                    你手写：
   链接器：据导入库把 "dll→Func"                LoadLibraryW("...")
           写进【exe 的导入表】                GetProcAddress(h,"Func")
          │                                                │
   加载器：读导入表→查目标dll导出表                  运行时：LoadLibraryW 触发 PE 装载
           →地址填进【exe 的 IAT】                          GetProcAddress 查目标dll【导出表】
          │                                                │
   运行时：call 走 IAT 取地址跳                运行时：函数指针直接跳
          │                                                │
   ⭐ 全程有exe 的导入表/IAT 参与                   ⭐ 完全不碰 exe 的导入表/IAT
```

- **路 A（静态）**：`#include <windows.h>` + 直接调 `CreateFileW` + 链 `kernel32.lib`。"写进导入表"是**链接器**干的（编译器生成引用，链接器据导入库落实）。你的直觉"编译器只能做静态的"——准确说是**链接器**在构建期定死。
- **路 B（动态）**：`LoadLibraryW` 的参数可能是运行时算的字符串，构建期**根本不知道你要调谁**，所以没法写进导入表，**也不需要**。它在运行时自己去查目标 dll 的**导出表**（`GetProcAddress` 干的就是这个）。

### 2.5.5 回接 M4 注入代码

```cpp
// injector.cc
HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
auto load_library = ::GetProcAddress(k32, "LoadLibraryW");  // ← 走路 B：查 kernel32 导出表
```

injector 用的正是**路 B（动态查导出表）**。为什么不直接写 `&LoadLibraryW`？因为它要的是**这个地址的数值**（好传给 target 远程线程当入口），`GetProcAddress` 现查最直接，且这个数值在 target 里也有效（§二共享基址）。

### 2.5.6 一张图串起 M4 全部 hook /注入知识

```
磁盘 PE 文件（.exe/.dll）
   │ 加载器（ntdll Ldr）装载
   ├─ 1. 映射各节到虚拟地址（.text 只读→可共享 ← §二基址共享）
   ├─ 2. 按 .reloc 重定位（系统 DLL 免，自己的 dll 要）
   ├─ 3. 解析导入表、填 IAT（← IAT Hook 改这张表）
   └─ 4. 调入口点（dll:DllMain ← M4 在这里装 hook）
   ▼
内存里"活的映像"（.text 字节 ← Inline Hook 改这里，§一.5）
```

---

## 三、由此延伸的面试题（自测）

1. **"注入时为什么不把 LoadLibraryW 地址写死，而要运行时 GetProcAddress？"**
   > 因为跨重启 ASLR 会给 kernel32 换基址，写死的地址下次开机就失效；运行时取当次开机的真实地址才可靠。

2. **"Inline Hook 和 Method Swizzling 有什么区别？"**
   > 意图相同（拦截+替换），但 Swizzling 改的是 OC runtime 的方法表（高层数据表，依赖语言运行时，机器码不变），Inline Hook 直接改函数机器码头字节为 jmp（底层、不依赖任何运行时、对任何原生函数都适用）。真正对应 Inline Hook 的 OC 侧是 fishhook / Dobby 这类，不是 Swizzling。

3. **"动态调用（LoadLibrary/GetProcAddress）的函数会出现在 exe 的导入表里吗？"**
   > 不会。导入表是构建期链接器写死的静态依赖清单，而 LoadLibrary 的目标运行时才确定，构建期不知道也就写不进去。动态调用绕开导入表/IAT，运行时自己查目标 dll 的**导出表**拿地址。

4. **"导入表、IAT、导出表分别是什么？"**
   > 导入表=调用方 exe 的"要谁"名字清单（构建期定）；IAT=加载期给导入表每个函数填真实地址的表（运行时静态调用从这取地址）；导出表=被调 dll 的"我提供谁"清单，GetProcAddress 查的就是它。

5. **"LoadLibraryW 到底做了什么？"**
   > 运行时触发目标 dll 的一次完整 PE 装载——映射节、重定位、解析它自己的导入表、最后调它的 DllMain。M4 注入就是让 target 远程线程调 LoadLibraryW，从而在 target 里"运行时硬塞一次 PE 装载"并在 DllMain 装 hook。
