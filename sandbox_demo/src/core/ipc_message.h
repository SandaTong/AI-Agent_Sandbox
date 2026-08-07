// -----------------------------------------------------------------------------
// core/ipc_message.h
// -----------------------------------------------------------------------------
// M3 Broker/Target IPC 的消息协议定义。
//
// 【M3 在整套沙箱里的位置】
//   M0~M2 解决的是"怎么把 target 关进笼子"。笼子越严，target 越什么都干不
// 了——真实的 renderer 被 AppContainer 关死后连读一个文件都做不到。所有
//   敏感操作必须委托给沙箱外的 broker 代劳。这个"委托通道"就是 IPC。
//
//       target（沙箱内，无权限）
//          │  "帮我打开 C:\path\to\file"   ← IPC 请求
//          ▼
//       broker（沙箱外，有权限）
//          │  1. 收请求 2. 策略检查(白名单) 3. 代劳打开 4. DuplicateHandle 回传
//      ▼
//       target 拿到 handle 继续干活
//
// 【为什么消息协议要单独一个头文件 + 极度重视边界安全】
//   target 是**不可信**的——它可能已经被攻破。broker 收到的每一条消息都要
//   当**恶意输入**处理。这个头文件定义的协议要满足：
//     1. 定长消息头（固定字节布局，跨进程二进制稳定）
//     2. 变长 payload，但 payload_size 有**硬上限**（防 target 说"我要发 4GB"）
//     3. 所有字段解析前先校验（magic / version / size 边界）
//     4. 结构体 POD + #pragma pack，避免不同编译选项下布局漂移
//
// 【传输层选择】
//   M3 用 Named Pipe（消息模式 PIPE_TYPE_MESSAGE），因为：
// - 有公开文档、消息边界由内核维护（一次 ReadFile 拿一条完整消息）
//     - Security Descriptor 可控 —— 这是给 AppContainer target 授权的关键
//   生产级组件（RPC/DCOM 底层）用 ALPC，性能更高但半公开；Chromium 现代版
//   用 Mojo，Windows 上底层仍是 named pipe。M3 不实现 ALPC。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <cstdint>

namespace sandbox::ipc {

// -----------------------------------------------------------------------------
// 协议常量
// -----------------------------------------------------------------------------

// 管道名。真实前缀 \\.\pipe\ 由 server/client 拼接。这里只放"短名"部分，
// 便于在 broker/target 两侧共用同一个字符串常量，避免手抖打错。
inline constexpr const wchar_t* kPipeShortName = L"wemeet_sandbox_m3_ipc";

// 协议魔数 + 版本：每条消息头都带，broker 收到第一时间校验，防止对端发来
// 的是垃圾数据 / 版本不匹配的旧客户端。'WMS3' = WeMeet Sandbox v3。
inline constexpr uint32_t kProtocolMagic = 0x33534D57;  // 'W''M''S''3' (小端)
inline constexpr uint32_t kProtocolVersion = 1;

// payload 硬上限：任何一条消息的变长体不允许超过这个字节数。
// 目的：target 就算发一个 payload_size=0xFFFFFFFF 的头，broker 也不会真去
// alloc 4GB（经典 DoS / 整数溢出攻击面）。文件路径这类请求 4KB 绰绰有余。
inline constexpr uint32_t kMaxPayloadBytes = 64 * 1024;  // 64 KB

// 路径字符串的字符数上限（含结尾）。Windows MAX_PATH=260，长路径可达 32767，
// M3 demo 取一个安全中间值；超过一律拒。
inline constexpr uint32_t kMaxPathChars = 1024;

// -----------------------------------------------------------------------------
// 消息类型
// -----------------------------------------------------------------------------
enum class MsgType : uint32_t {
    kInvalid = 0,

    // target -> broker：请 broker 代劳按只读方式打开一个文件，成功则通过
    // DuplicateHandle 把文件句柄复制进 target 的 handle table，句柄值随
    // 响应回传。broker 侧会先做路径白名单校验（M3 简化：只允许某个目录）。
    kOpenFileRequest = 1,

    // broker -> target：kOpenFileRequest 的响应。
    kOpenFileResponse = 2,

    // target -> broker：一次简单的 ping（连通性冒烟），broker 回 pong。
    kPingRequest = 3,
    kPongResponse = 4,
};

// broker 处理请求后的结果码（放在响应 payload 里）。不用 Win32 gle 直接透
// 传，避免把 broker 内部错误细节暴露给不可信的 target。
enum class ResultCode : uint32_t {
    kOk = 0,
    kDenied = 1,         // 策略拒绝（路径不在白名单等）
    kBadRequest = 2,     // 请求格式非法
    kInternalError = 3,  // broker 内部错误（打开失败等）
};

// -----------------------------------------------------------------------------
// 消息头（定长，跨进程二进制稳定）
// -----------------------------------------------------------------------------
// #pragma pack(4)：显式指定 4 字节对齐，避免 broker/target 用不同结构体对齐
// 选项编译时布局不一致。所有字段都是固定宽度整型（POD），可直接 memcpy。
#pragma pack(push, 4)
struct MsgHeader {
    uint32_t magic;         // 必须 == kProtocolMagic
    uint32_t version;       // 必须 == kProtocolVersion
    uint32_t type;          // MsgType
    uint32_t payload_size;  // 紧跟在头后面的 payload 字节数，<= kMaxPayloadBytes
};

// kOpenFileRequest 的 payload 布局：定长头 + 紧随其后的宽字符路径。
// path_chars 是路径的字符数（不含结尾 L'\0'），broker 必须校验：
//   path_chars <= kMaxPathChars 且 path_chars*2 + sizeof(OpenFileRequest) 与
//   MsgHeader.payload_size 自洽——绝不信任单一字段。
struct OpenFileRequest {
    uint32_t path_chars;  // 后跟 path_chars 个 wchar_t（不含结尾 NUL）
    // wchar_t path[path_chars];  // 变长，紧跟在本结构体之后
};

// kOpenFileResponse 的 payload 布局：纯定长。
// 句柄传递说明：broker 用 DuplicateHandle 把文件句柄复制到 target 进程后，
// 得到一个在 target handle table 里有效的句柄值。HANDLE 在 64 位进程里是
// 64 位指针大小的值，为了协议跨位数稳定，这里用 uint64_t 承载。target 收到
// 后 reinterpret 回 HANDLE 即可直接用。若 result != kOk，dup_handle 无意义。
struct OpenFileResponse {
    uint32_t result;      // ResultCode
    uint32_t reserved;    // 对齐填充，保持 8 字节边界
    uint64_t dup_handle;  // 在 target 进程里有效的文件句柄（DuplicateHandle 产物）
};
#pragma pack(pop)

// 静态断言：布局一旦被无意改动，编译期就报错，避免协议悄悄漂移。
static_assert(sizeof(MsgHeader) == 16, "MsgHeader 必须是 16 字节");
static_assert(sizeof(OpenFileRequest) == 4, "OpenFileRequest 必须是 4 字节");
static_assert(sizeof(OpenFileResponse) == 16, "OpenFileResponse 必须是 16 字节");

// -----------------------------------------------------------------------------
// 头部校验：broker/client 收到任何消息，第一步都调它。返回 true 才继续解析。
// 把"不信任对端"这条铁律固化成一个函数，避免每个调用点各写各的校验。
// -----------------------------------------------------------------------------
[[nodiscard]] inline bool ValidateHeader(const MsgHeader& h) noexcept {
    if (h.magic != kProtocolMagic)
        return false;
    if (h.version != kProtocolVersion)
        return false;
    if (h.payload_size > kMaxPayloadBytes)
        return false;
    return true;
}

}  // namespace sandbox::ipc
