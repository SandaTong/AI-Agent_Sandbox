// -----------------------------------------------------------------------------
// core/token_manager.h
// -----------------------------------------------------------------------------
// 构造一个受限的 primary token，用于启动 target 进程。
//
// 对应 JD Windows 方向 W1（权限收敛）:
//   "熟悉 Windows 权限与安全边界机制，包括 Access Token、Integrity Level ...
//    具备权限收敛、进程约束与沙箱加固实践经验"
//
// 分阶段能力：
//   M0：CreateRestricted()— CreateRestrictedToken + DISABLE_MAX_PRIVILEGE
//   M1：SetLowIntegrity()       — 把 Token 的 Mandatory Label 改成 Low IL
//   M2：将新增 AppContainer/LowBox 支持
//
// 相比初版的改进（M0 起）：
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

// Mandatory Integrity Level 等级。RID 常量来自 Windows SDK。
// 参考：https://learn.microsoft.com/windows/win32/secauthz/well-known-sids
// https://learn.microsoft.com/windows/win32/secauthz/mandatory-integrity-control
enum class IntegrityLevel : DWORD {
    kUntrusted = SECURITY_MANDATORY_UNTRUSTED_RID,  // 0x00000000
    kLow = SECURITY_MANDATORY_LOW_RID,              // 0x00001000
    kMedium = SECURITY_MANDATORY_MEDIUM_RID,        // 0x00002000
    kHigh = SECURITY_MANDATORY_HIGH_RID,            // 0x00003000
    kSystem = SECURITY_MANDATORY_SYSTEM_RID,        // 0x00004000
};

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

    // 【M1】把当前 token 的 Mandatory Label 改成 `level`。
    //
    // 一定要在 CreateRestricted() 之后、CreateProcessAsUserW 之前调用。
    // 内部会：
    //   1) 构造 SID：S-1-16-<RID>  例如 Low = S-1-16-4096
    //   2)用 SetTokenInformation(TokenIntegrityLevel, TOKEN_MANDATORY_LABEL)
    //      把这个 SID 写进 token 的 Mandatory Label 字段
    //
    // 效果：
    //   * 该 token 启动的进程，其内核对象访问检查会用 Low IL 参与判定。
    //   * NTFS 里普通用户目录默认带 "Medium 及以上可访问" 的 mandatory ACE，
    //     Low IL 进程尝试写这些位置 -> ACCESS_DENIED。
    //   * 是"目录/注册表ACL 层收敛"的第一步，是沙箱味变浓的关键一步。
    std::error_code SetIntegrityLevel(IntegrityLevel level);

    [[nodiscard]] HANDLE handle() const noexcept { return token_.get(); }
    [[nodiscard]] bool valid() const noexcept { return token_.valid(); }

 private:
    ScopedHandle token_;
};

}  // namespace sandbox
