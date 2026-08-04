// -----------------------------------------------------------------------------
// core/token_manager.h
// -----------------------------------------------------------------------------
// 构造一个受限的 primary token，用于启动 target 进程。
//
// 对应 JD Windows 方向 W1（权限收敛）:
//   "熟悉 Windows 权限与安全边界机制，包括 Access Token、Integrity Level ...
//    具备权限收敛、进程约束与沙箱加固实践经验"
//
// M0 版本只做最基础一层：CreateRestrictedToken + DISABLE_MAX_PRIVILEGE。
// M1 会额外把 Integrity Level 降到 Low / Untrusted；
// M2 会用 NtCreateLowBoxToken 生成 AppContainer 的 LowBox Token。
//
// 相比初版的改进：
//   - 打开父进程 token 时不再要求 TOKEN_ALL_ACCESS。我们只需要
//     TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
//     TOKEN_ADJUST_DEFAULT。最小权限原则对 broker 自己也适用。
//   - 全程用 ScopedHandle 包裹，杜绝 HANDLE 泄漏。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <system_error>

#include "common/scoped_handle.h"

namespace sandbox {

class TokenManager {
 public:
    TokenManager() = default;

    TokenManager(const TokenManager&) = delete;
    TokenManager& operator=(const TokenManager&) = delete;
    TokenManager(TokenManager&&) = default;
    TokenManager& operator=(TokenManager&&) = default;

    // 从当前进程 token 派生一个 restricted token：
    //   1) OpenProcessToken（只取必要权限）
    //   2) CreateRestrictedToken 传 DISABLE_MAX_PRIVILEGE，让源 token 里的
    //      每一项 privilege 都被标记为 SE_PRIVILEGE_REMOVED（比如
    //      SeDebugPrivilege、SeTcbPrivilege 等永久无法再激活）
    //   3) 得到一个 primary token，供后续 CreateProcessAsUserW 使用
    std::error_code CreateRestricted();

    [[nodiscard]] HANDLE handle() const noexcept { return token_.get(); }
    [[nodiscard]] bool valid() const noexcept { return token_.valid(); }

 private:
    ScopedHandle token_;
};

}  // namespace sandbox
