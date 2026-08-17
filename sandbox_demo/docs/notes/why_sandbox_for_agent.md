# 为什么给 AI Agent 做 Windows 沙箱 —— 工程动机总纲

> 这是整个 `AI-Agent_Sandbox` 工程的"动机总纲"：我们辛辛苦苦逐 milestone 搭的这套 Job / Token / IL / Mitigation / WFP / 文件 Broker，到底解决 AI Agent 的什么真实风险、对应哪些产品落点。面试讲项目背景可直接用这一篇。

---

## 一、AI Agent 的风险本质

AI Agent（能执行任意命令的 Copilot / 自动化 agent）跑起来时，本质是**一个行为不可预测的进程，却被赋予了执行代码、读写文件、发网络的能力**。

> 风险等价于：**让一个人格不完全可控的陌生人，拿着你的 user token 登录你的电脑，还握着你的源码、密钥和执行权。**

三类风险源：

1. **模型自己失控**：幻觉生成危险命令（`rm -rf`、格式化盘）、被诱导执行恶意逻辑。
2. **Prompt 注入 / 越狱**：外部输入（网页、文件、工具返回）里藏指令，劫持 agent 去干坏事（偷数据、连 C2）。这是 agent 时代**最主要的新型攻击面**。
3. **供应链 / 工具投毒**：agent 装的第三方包、调的 MCP 工具本身带毒。

**沙箱的核心假设**：不信任 agent 的善意——**假设 agent 一定会被诱导做坏事，用 OS 级围栏把"坏事的爆炸半径"限制死**。这就是 **defense-in-depth（纵深防御）**：不在"让模型别做坏事"上赌，只在 OS 层堵死能力。

---

## 二、每个 milestone 对应的 Agent 真实场景

| milestone | 堵的 Agent 风险 | 真实例子 |
|---|---|---|
| **M0/M1 Job + Token + IL** | agent 跑飞占满 CPU/内存拖垮机器；起一堆子进程；提权 | agent 死循环 fork 炸弹；agent 想 `runas` 提权装驱动 |
| **M1/M5 Mitigation（禁动态代码/非签名DLL/子进程）** | agent 下载执行 shellcode、加载恶意 DLL、逃逸起 cmd | prompt 注入让 agent"下载并运行这个 exe"；恶意 MCP 工具注入 DLL |
| **M2/M6 网络管控（Firewall + WFP）** | **agent 偷数据外传 / 连 C2 / 访问内网** ⭐最高频 | agent 被注入后把你的代码/密钥 POST 到攻击者服务器；SSRF 打内网 |
| **M3 Broker/IPC + M8 文件 Broker** | agent 越权读写敏感文件 | agent"帮我整理文件"时读了 `~/.ssh`、`.env`、浏览器 cookie |
| **M4/M5 注入与反注入** | agent 被恶意软件注入劫持 / agent 反向攻击宿主 | EDR 之外的进程往 agent 里注入偷它的 API key；agent 注入宿主 IDE |

---

## 三、最贴合 Agent 的三个"杀手级"落点

### ① 网络管控（M2/M6）—— Agent 沙箱最刚需的一层

Agent 时代最大的新风险是**数据外泄**：agent 手里有你的源码、密钥、聊天记录，一旦被 prompt 注入，最简单的攻击就是"把这些 POST 出去"。M6 的 **WFP AppID 形态**正是解药——

> **默认禁网，只放行 agent 真正需要的 LLM API 端点（白名单）**。agent 想连别的地址一律 BLOCK。这就是 M6 做的"按进程精确管控 outbound"，而且**能拦 loopback**（防 agent 通过本地代理绕过）。

真实产品参照：Cursor / Claude Code 企业版都在做"网络出口白名单"；OpenAI Code Interpreter 直接**完全禁网**。

### ② 文件隔离（M3 + M8）—— Agent 只能碰工作区

Agent "读代码/改文件"是核心能力，但必须框死在**工作目录**内。读系统敏感路径（凭据、SSH key、其他项目）要么直接拒，要么走 broker 审批。M3 的 broker + M8 的文件代理就是这个模型——**agent 本身低权限、碰不到的东西委托 broker 判断该不该给**。

### ③ 能力剥离（M1 Mitigation）—— 掐死"下载执行"链

Prompt 注入最经典的 payload 是"下载并运行 X"。M1/M5 三件套从 OS 层掐断：
- `BLOCK_NON_MICROSOFT_BINARIES` → 下载的恶意 exe/dll 加载不了
- `PROHIBIT_DYNAMIC_CODE` → shellcode 分配不了可执行内存
- 禁子进程 → agent 起不了 `cmd`/`powershell` 去执行下载的东西

---

## 四、五层围栏全景

```
        行为不可预测、握着你数据和执行权的 AI Agent 进程
                              │
   ┌──────────────────────────┼──────────────────────────┐
   ▼          ▼               ▼              ▼            ▼
 资源围栏   权限围栏         能力围栏        网络围栏      数据围栏
 (M0/M1)   (M1)            (M1/M5)        (M2/M6)      (M3/M8)
 Job       Token/IL        Mitigation     Firewall     Broker
 CPU/内存  受限token       禁动态代码       WFP AppID    文件代理
 /进程数   /Low IL         /非签名DLL       出口白名单    /工作区隔离
 /UI       /AppContainer   /禁子进程        /拦loopback  /敏感路径审批
   │          │               │              │            │
   └──────────┴───────────────┴──────────────┴────────────┘
                              │
              agent 崩了/作恶，爆炸半径被限死在沙箱内
                    （M4/M5 反注入保证沙箱自身不被劫持）
```

---

## 五、工业级参照（证明方向正确）

- **Chromium sandbox**：我们整套 Job + Token + IL + Mitigation + AppContainer 模型直接源自它——"渲染进程不可信，OS 层围死"的教科书。Agent 沙箱本质是把浏览器 renderer 的隔离思路搬到 agent 进程。
- **OpenAI Code Interpreter / E2B / Daytona**：主流用**容器 / gVisor / microVM** 做 agent 沙箱（Linux 侧）。我们做的是 **Windows 原生进程级沙箱**——更轻量（无需虚拟化）、启动快、和宿主集成好，适合"agent 就在用户 Windows 机器上跑"的桌面场景。
- **企业 EDR（如实测撞到的腾讯 iOA）**：M4/M5 的注入/反注入正是 EDR 核心技术，agent 沙箱需要它来防"agent 被劫持"和"agent 反噬宿主"。

---

## 六、一句话总结（面试口径）

> "我做的是**一个专门关 AI Agent 的 Windows 原生进程沙箱**：把'行为不可预测、还握着你数据和执行权的 agent 进程'关进 **Job（资源）+ Token/IL（权限）+ Mitigation（能力）+ WFP（网络）+ 文件 Broker（数据）** 五层围栏。核心假设是'agent 一定会被诱导做坏事，我只在 OS 层把坏事的爆炸半径限制死'。其中**网络出口白名单（M6）和文件工作区隔离（M8）是 agent 场景最刚需的两层**——因为 agent 最大的新风险是**拿着你的数据往外发**。这套东西的产品形态，就是给 Cursor / Claude Code 这类桌面 agent 或企业内部 agent 平台做**运行时安全底座**。"
