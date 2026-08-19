// -----------------------------------------------------------------------------
// minifilter/mf_protocol.h
// -----------------------------------------------------------------------------
// 【M9】Minifilter 驱动 <-> 用户态控制程序 的共享协议。
//
// 内核侧（sandbox_minifilter.c）和用户侧（mf_ctl.cc）都 include 本头，保证两端
// 结构体二进制布局一致。通过 FltMgr 通信端口（FltSendMessage / FilterGetMessage
// / FilterSendMessage）传递。
//
// 两类消息：
//   1) 内核 -> 用户：审计上报（AuditRecord）—— "哪个进程打开了哪个路径，放行还是被拦"
//   2) 用户 -> 内核：策略下发（PolicyUpdate）—— "把这批敏感路径前缀设为黑名单"
//
// 安全铁律（和 M3/M8 IPC 一致）：内核侧收到用户态下发的任何数据都当不可信输入，
// 长度/条数/字符串边界全部校验后才用。
// -----------------------------------------------------------------------------
#pragma once

// 本头被内核态(.c, 用 ntddk 类型)和用户态(.cc, 用 windows.h)共用。
// 只用两边都有的固定宽度类型，不引平台头，避免类型冲突。

// 通信端口名：内核 FltCreateCommunicationPort 建，用户 FilterConnectCommunicationPort 连。
// 用宽字符串常量，两端一致。
#define MF_PORT_NAME L"\\SandboxMiniFilterPort"

// 路径 / 前缀的字符数上限（含结尾），防超长 DoS。
#define MF_MAX_PATH_CHARS 512u

// 一次策略下发最多多少条敏感路径前缀。
#define MF_MAX_RULES 32u

// 消息类型。
enum MfMsgType {
    kMfAudit = 1,       // 内核 -> 用户：一条审计记录
    kMfPolicySet = 2,   // 用户 -> 内核：整表覆盖式下发敏感路径策略
};

// 内核对某次 create 的判定结果（审计记录里带）。
enum MfVerdict {
    kMfAllowed = 0,   // 放行
    kMfBlocked = 1,   // 命中黑名单，被内核 STATUS_ACCESS_DENIED 拦下
};

#pragma pack(push, 8)

// 内核 -> 用户：一条审计记录。
// 注意：FltMgr 消息在用户侧收取时前面还有一个 FILTER_MESSAGE_HEADER，
// 我们的结构体紧跟其后；发送侧 FltSendMessage 只发本结构体。
struct MfAuditRecord {
    unsigned int  msg_type;      // MfMsgType::kMfAudit
    unsigned int  verdict;       // MfVerdict
    unsigned int  process_id;    // 发起 create 的进程 PID
    unsigned int  path_chars;    // path 有效字符数（不含结尾 NUL）
    wchar_t       path[MF_MAX_PATH_CHARS];  // 目标文件规范化路径（定长内嵌，简化传输）
};

// 用户 -> 内核：策略下发。整表覆盖：内核收到后用这批前缀替换旧黑名单。
// 每条前缀是一个"路径包含匹配"的关键词（大写），命中即视为敏感路径。
// 简化设计：不做通配符，只做大小写不敏感的子串包含（demo 够用，注释说明生产应做规范化前缀树）。
struct MfPolicyRuleItem {
    unsigned int  len_chars;                 // 本条前缀字符数
    wchar_t       text[MF_MAX_PATH_CHARS];   // 敏感路径关键词（大写）
};

struct MfPolicyUpdate {
    unsigned int      msg_type;   // MfMsgType::kMfPolicySet
    unsigned int      rule_count; // <= MF_MAX_RULES
    struct MfPolicyRuleItem rules[MF_MAX_RULES];
};

#pragma pack(pop)
