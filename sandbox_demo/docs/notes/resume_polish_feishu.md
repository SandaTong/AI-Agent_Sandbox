# 简历润色稿 — 面向「桌面端 Agent Sandbox 研发工程师 / 专家 - 飞书」

> 用法：直接从下面各项目段落拷贝进简历。润色主线 = 同样的工作，换成 JD 的系统底层 / 安全边界术语讲；把 Windows 平台层 + Qt 源码 + sandbox 串成"Windows 系统底层"一条主线。

---

## 公司维度总览（放在具体项目之上的概括段，二选一）

### 版本 A：贴合原结构（5 条，直接替换原总览 5 点）

**2021-10 ~ 至今 ｜ 深圳市腾讯计算机系统有限公司 ｜ 资深桌面端研发工程师**

- 负责腾讯会议桌面端从原生框架到 Qt 框架的整体迁移，实现 Win/Mac/Linux 三端跨平台统一。
- 负责 Qt 平台抽象层（QPA）源码维护与升级，直接对接各 OS 原生 API（Windows GDI/DirectWrite、消息循环、窗口/DPI），修复框架底层 bug 保障基础框架稳定性，并维护 Qt 日常构建流水线。
- 负责跨平台基础库从 0 到 1 建设，封装三端基础控件、复杂定制控件与统一 QSS 样式引擎，抽象平台差异支撑业务快速开发。
- 负责腾讯会议 Windows 端 32 → 64 位架构迁移，处理指针宽度、调用约定、ABI 兼容等底层问题；主导线上 crash 治理，用 WinDbg/livekd 分析 Ring3/Ring0 崩溃 dump，将 crash 率稳定压至 0.05% 以内。
- 主导团队 AI 提效实践：构建 Qt 6.8 源码 AI 代码知识库（9.4 万函数结构化）、Qt/UIKit 问题分析机器人、UIKit skill 集驱动 Agent 设计稿还原；并独立预研 Windows AI-Agent 安全沙箱（权限收敛/网络管控/文件隔离/注入攻防）。

### 版本 B：更"系统底层"人设（一段式概述 + bullet，适合放最上面当 summary）

**2021-10 ~ 至今 ｜ 深圳市腾讯计算机系统有限公司 ｜ 资深桌面端研发工程师**

长期深耕桌面端 Qt 框架底层与 Windows 系统平台层，兼具跨平台工程与系统底层问题定位能力：

- **框架底层**：主导腾讯会议原生框架 → Qt 框架迁移（Win/Mac/Linux 三端）、维护 Qt QPA 平台层源码与构建流水线、从 0 到 1 搭建跨平台基础控件库。
- **系统底层**：完成 32→64 位架构迁移；用 WinDbg/livekd 做 Ring3/Ring0 崩溃逆向定位，crash 率压至 0.05% 以内。
- **AI 与安全预研**：构建 Qt 源码 AI 知识库与问题分析机器人、Agent 设计稿还原；独立预研 Windows AI-Agent 安全沙箱，实践权限收敛、WFP 网络管控、文件系统隔离与注入/反注入攻防。

> 取舍：若简历下方已有项目明细（腾讯会议/元宝/沙箱），用**版本 A** 保持结构一致、避免与明细重复过多；若这段作为个人 summary 放最上面统领全篇，用**版本 B** 更突出系统底层人设。

---

## 腾讯会议 ｜ 桌面端工程师 ｜ 2021-10 ~ 至今（主场）

**项目贡献：**

1. **Qt 跨平台底层源码维护（Win/Mac/Linux 平台插件层）**：深入 Qt QPA 平台抽象层源码，直接对接各 OS 原生 API（Windows GDI/DirectWrite、消息循环、窗口/DPI 管理），解决字体渲染、多屏热插拔、HiDPI 等平台层疑难问题，具备读源码 + 改系统调用层的底层工程能力。

2. **Ring3/Ring0 崩溃与卡顿逆向定位**：使用 WinDbg / livekd 分析用户态与内核态崩溃 dump，定位跨越应用层与驱动层的疑难问题（句柄泄漏、锁竞争死锁、堆损坏等）；主导线上 crash 治理，将腾讯会议 crash 率稳定压到 0.05% 以内。

3. **32 → 64 位架构迁移**：完成腾讯会议从 x86 到 x64 的整体迁移，处理指针宽度、调用约定、内存布局、第三方库 ABI 兼容等底层问题，进一步提升会议稳定性。

4. **原生框架到 Qt 框架迁移 + 跨平台基础库从 0 到 1**：主导腾讯会议从原生框架迁移到 Qt 框架，实现 Win/Mac/Linux 三端跨平台；封装跨三端的基础控件、复杂定制控件与统一 QSS 样式引擎，抽象平台差异，支撑上层业务快速开发。

5. **Qt 底层知识体系沉淀**：定期输出 Qt 平台层原理文档与踩坑总结，团队内推广（含 QPA、事件分发、内核对象生命周期等主题）。

**AI 实践：**

1. **iMate Qt/UIKit 问题分析机器人**：基于 iMate 创建 Qt 与 UIKit 的问题分析机器人，对接内部反馈系统，智能识别用户反馈中 Qt/UIKit 相关问题，分析并输出解决方案，并把每次分析结果以 skill 形式沉淀到 iMate 知识库，让知识飞轮自动转起来。

2. **Qt 6.8 源码 AI 炼化与代码知识库构建**：针对约 9.4 万个函数的大型 C++ 代码库（Qt 6.8），使用静态分析工具（CodeQL + tree-sitter）提取函数骨架与调用关系，调度多个免费 LLM 接力生成摘要与代码审计，最终将 ~5GB 源码压缩为 55MB 可查询的结构化代码地图，供其他 AI Agent 以零成本进行代码理解与缺陷定位。

3. **UIKit skill 集沉淀 + Agent 设计稿还原**：配合公司标准化 AI 工作流（内部 dtmf），将 UIKit 使用方法与注意事项沉淀为 skill 集合，导出到标准工作流的界面设计模块；实现 Agent 调用 UIKit skill 完成上层 UI 设计稿还原，业务层只需微调代码即可落地界面。

---

## 腾讯元宝 ｜ 桌面端研发工程师 ｜ 2025-05 ~ 2025-07（辅助）

**项目贡献：**

1. **Tauri / wry 底层源码改造，实现组件截图能力**：深入 Tauri 的 wry（WebView 封装层）源码，对接 Windows WebView2 与 macOS WKWebView 的原生接口，实现跨平台 WebView 组件截图功能，打通 Web 容器与原生渲染层的能力边界。

2. **跨平台消息推送与系统通知接入**：设计并实现跨平台层（内部 dtmp）消息推送系统，统一封装 Win/Mac 的系统通知与自定义消息通知能力，屏蔽各端通知机制差异。

---

## ⭐ Windows AI-Agent 安全沙箱 ｜ 个人项目 / 技术预研（建议紧跟其后，逐条命中 JD Windows 方向）

**项目背景**：为 AI Agent 提供 Windows 平台安全运行环境，从内核对象机制出发，逐层构建进程管控、权限收敛、网络访问控制、文件系统隔离的纵深防御体系（对标 Chromium Sandbox / OpenAI Codex Sandbox 的 Windows 后端）。C++17 / Win32 / WFP / MinHook 实现。

**核心贡献（按 JD Windows 五维组织）：**

1. **权限收敛与进程约束**：基于 Restricted Token + Integrity Level 降级 + Job Object + AppContainer/LowBox Token 构建多层权限笼子；用 STARTUPINFOEX + Process Mitigation Policy（PROHIBIT_DYNAMIC_CODE / BLOCK_NON_MICROSOFT_BINARIES / DISABLE_CHILD_PROCESS 等 8 项）做进程加固；Job 的 KILL_ON_JOB_CLOSE 内核回调实现 broker/target 生死联动。

2. **注入与 API Hook 攻防**：实现远程线程 + LoadLibrary 注入四件套，基于 MinHook（inline hook / trampoline / relay）拦截 CreateFileW、GetAddrInfoW 等关键 API；配套反注入检测（LdrRegisterDllNotification 模块监控 + 远程线程扫描 + API 完整性自检），攻防镜像验证。

3. **多维度网络访问控制**：基于 WFP（Windows Filtering Platform）在 ALE_AUTH_CONNECT_V4 层按进程 AppID / IP / 端口拦截 outbound（含 loopback）；通过注入 hook GetAddrInfoW 实现域名维度白名单管控（可区分进程、可挡 DoH），完成 DNS → IP → WFP 联动纵深。

4. **文件系统隔离与访问代理**：实现用户态文件 Broker（命名管道帧协议 IPC + DuplicateHandle 最小权限句柄回传 + 多规则白名单读写分离），并用 GetFinalPathNameByHandle 事后真身校验防 TOCTOU / 符号链接绕过；另用 NTFS DACL DENY-ACE（SetNamedSecurityInfo）实现从外部剥夺目标进程写权限，两条路线纵深互补。（Minifilter 内核文件过滤驱动开发进行中）

5. **系统底层机制沉淀**：产出内核对象（Object Manager / handle 表 / SeAccessCheck 三层 / PEB 环境块）、命名管道 IPC、MinHook trampoline 等深度技术文档，并与 OpenAI Codex Sandbox 做架构对比分析。

**技术栈**：C++17、Win32 API、WFP、MinHook、命名管道 IPC、WinDbg / Process Explorer / WinObj。

---

## 技能关键词（建议补进技能栏，便于检索命中 JD）

Windows 系统底层：`NT 架构` `Object Manager` `Access Token` `Integrity Level` `Job Object` `AppContainer/LowBox` `Process Mitigation Policy` `PE 结构`
Hook / 注入：`Inline Hook / MinHook` `远程线程注入` `IAT Hook` `反注入`
网络管控：`WFP` `DNS Hook` `进程/IP/端口/域名维度访问控制`
文件 / 内核：`NTFS DACL` `DENY-ACE` `命名管道 IPC` `DuplicateHandle` `Minifilter(在建)`
调试逆向：`WinDbg` `livekd` `Process Explorer` `WinObj`
语言 / 工程：`C/C++17` `多线程与同步` `静态/动态库` `跨平台(Win/Mac/Linux)`
