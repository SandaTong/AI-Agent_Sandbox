// -----------------------------------------------------------------------------
// core/pipe_client.h
// -----------------------------------------------------------------------------
// M3 Target 侧的命名管道客户端。
//
// target 跑在沙箱里（M2 场景是 AppContainer），几乎什么都干不了，所有敏感操
// 作委托给 broker。client 逻辑只做三件事：
//   1. Connect()：CreateFileW 连上 broker 的命名管道
//      —— 只有 broker 把管道 SD 授权了本 target 的 Package SID，这一步才成功；
//         否则 ERROR_ACCESS_DENIED (gle=5)，这本身就是"沙箱 IPC 授权"生效的证据。
//   2. RequestOpenFile()：发一条 kOpenFileRequest，收回 broker 用
//      DuplicateHandle 复制进本进程的文件句柄——拿到后可直接 ReadFile。
//   3. Ping()：连通性冒烟。
//
// 设计原则：client 侧代码越简单越好（沙箱内进程应尽量少逻辑、少攻击面）。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <system_error>

#include "common/scoped_handle.h"
#include "core/ipc_message.h"

namespace sandbox {

class PipeClient {
 public:
    PipeClient() = default;
    ~PipeClient() = default;

    PipeClient(const PipeClient&) = delete;
    PipeClient& operator=(const PipeClient&) = delete;

    // 连接 broker 的命名管道。timeout_ms 内反复重试等待管道可用。
    std::error_code Connect(DWORD timeout_ms = 5000);

    // 发 Ping，收 Pong。成功返回 error_code{}。
    std::error_code Ping();

    // 请 broker 代劳打开文件。成功时 out_handle 是本进程 handle table 里有效
    // 的文件句柄（broker DuplicateHandle 过来的），可直接 ReadFile 使用；
    // out_result 带回 broker 的策略判定结果（kOk / kDenied / ...）。
    std::error_code RequestOpenFile(const std::wstring& path, HANDLE& out_handle,
                                    ipc::ResultCode& out_result);

    [[nodiscard]] bool valid() const noexcept { return pipe_.valid(); }

 private:
    ScopedHandle pipe_;
};

}  // namespace sandbox
