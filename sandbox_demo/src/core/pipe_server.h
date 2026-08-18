// -----------------------------------------------------------------------------
// core/pipe_server.h
// -----------------------------------------------------------------------------
// M3 Broker 侧的命名管道服务端。
//
// 【M3 全场最难的一环：给 AppContainer target 授权连接管道】
//   命名管道也是内核对象，受 Security Descriptor 保护。默认情况下 broker 用
//   CreateNamedPipeW 建的管道，其 SD 只授权创建者（broker 的用户 SID）和
//   SYSTEM。而 M2 里的 target 是 AppContainer / LowBox token——它的主体是
//   Package SID（S-1-15-2-...），**默认对 broker 的管道没有任何访问权限**，
//   CreateFileW 会直接 ERROR_ACCESS_DENIED (gle=5)。
//
//   所以 pipe 的 SD 必须**显式加一条 ACE 授权 target 的 Package SID**（或某个
//   capability SID）。这一步把 M2 的 AppContainer 和 M3 的 IPC 缝在一起，也
//   是"我真做过沙箱 IPC"最硬的证明点。
//
//   ⚠️ 常见错误：给管道 SD 加 Everyone(WD) 图省事——这等于把管道对全机开放，
//   任何低权限进程都能连 broker，反而制造了新攻击面。正确做法是**只授权那个
//   特定 target 的 Package SID**（最小授权原则）。
//
// 【SD 构造方式】
//   用 SDDL 字符串 + ConvertStringSecurityDescriptorToSecurityDescriptorW。
//   SDDL 里 Package SID 用它的字符串形式直接嵌：
//       D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<PackageSidString>)
//   分别是：SYSTEM 全权 / Administrators 全权 / 该 AppContainer 全权。
//   (M1 坑 #2 的教训：能在 Create 时传 SD 就绝不事后 SetSecurityInfo。)
//
// 【线程模型】
//   M3 先做最简单的"一 target 一实例、单线程阻塞收发"：
//  Create() -> WaitForClient()(ConnectNamedPipe 阻塞) -> ServeOneRequest()
//   多 target 并发（IOCP / 线程池）留到 M5 优化。
//
// 【消息模式】
//   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE：一次 ReadFile 读一条完整消息，
//   内核维护消息边界，省掉自己拆包 / 粘包处理。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <system_error>
#include <vector>

#include "common/scoped_handle.h"
#include "core/ipc_message.h"

namespace sandbox {

// -----------------------------------------------------------------------------
// 【M8】文件访问策略引擎的一条规则。
//   dir_prefix：被授权的目录前缀（已规范化为大写、含尾部反斜杠）。
//   allow_write：该目录是否允许写/创建（false = 只读目录）。
// 多条规则组成白名单，broker 对每个请求做"规范化路径 -> 命中某条规则 -> 该规则
// 是否允许本次 access_mode"的两级判定。这是相较 M3 单目录只读白名单的核心增强。
// -----------------------------------------------------------------------------
struct FilePolicyRule {
    std::wstring dir_prefix;  // 形如 L"C:\\SANDBOX_SHARE\\"（大写规范化）
    bool allow_write = false;
};

class PipeServer {
 public:
    PipeServer() = default;
    ~PipeServer() = default;

    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;

    // 创建命名管道服务端实例。
    //   package_sid_sddl：target 的 Package SID 字符串（AppContainer::
    //     PackageSidString() 的返回值）。为空表示不做 AppContainer 授权
    //     （M0/M1 场景，target 是普通/受限 token，走默认 SD 即可）。
    //   非空时，管道 SD 会额外授权这个 Package SID 连接权限。
    //
    // 成功后管道处于监听状态，等待 target 连过来。
    std::error_code Create(const std::wstring& package_sid_sddl = L"");

    // 【M8】设置文件访问策略（多规则白名单）。不调用时使用内置默认策略
    //   （只读目录 C:\sandbox_share\，兼容 M3 行为）。M8 demo 会显式配置
    //   一个只读目录 + 一个可写目录来演示读写分离。
    void SetFilePolicy(std::vector<FilePolicyRule> rules);

    // 阻塞等待 target 连接（ConnectNamedPipe）。target 侧 CreateFileW 连上后
    // 返回。已有客户端在管道创建和本调用之间就连上的情况也正确处理
    // （ERROR_PIPE_CONNECTED）。
    std::error_code WaitForClient();

    // 处理一条请求：ReadFile 收一条消息 -> 校验 -> 按 MsgType 分发处理 ->
    // WriteFile 回响应。返回 error_code{} 表示成功处理一条；对端断开返回
    // 对应错误码，调用方据此结束服务循环。
    //
    //   target_process：target 进程句柄，DuplicateHandle 回传文件句柄时需要
    //     把句柄复制到这个进程的 handle table。
    std::error_code ServeOneRequest(HANDLE target_process);

    [[nodiscard]] HANDLE pipe() const noexcept { return pipe_.get(); }
    [[nodiscard]] bool valid() const noexcept { return pipe_.valid(); }

 private:
    // 处理 kOpenFileRequest：校验路径白名单 -> 代劳打开 -> DuplicateHandle。
    std::error_code HandleOpenFile(const ipc::MsgHeader& hdr, const void* payload,
                                   HANDLE target_process);

    // 处理 kPingRequest：直接回 pong。
    std::error_code HandlePing(const ipc::MsgHeader& hdr);

    ScopedHandle pipe_;
    std::vector<FilePolicyRule> policy_;  // M8 策略规则；空则用内置默认
};

}  // namespace sandbox
