// -----------------------------------------------------------------------------
// core/token_manager.h
// -----------------------------------------------------------------------------
// Builds a restricted primary token that will be used to spawn the target.
//
// JD mapping (Windows W1 - 权限收敛):
//   "熟悉Windows权限与安全边界机制，包括 Access Token、Integrity Level ...
//    具备权限收敛、进程约束与沙箱加固实践经验"
//
// This M0 version does the *basic* layer: CreateRestrictedToken with
// DISABLE_MAX_PRIVILEGE. In M1 we'll additionally lower Integrity Level to
// Low/Untrusted, and in M2 we'll produce an AppContainer/LowBox token via
// NtCreateLowBoxToken.
//
// What we deliberately DID improve vs the old code:
//   - No longer requests TOKEN_ALL_ACCESS when opening the parent token. We
//     only need TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
//     TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID. Principle of least
//     privilege applies to us too.
//   - Wrapped in ScopedHandle so leaks are impossible.
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

    // Build a restricted token from the current process token.
    // Steps:
    //   1) OpenProcessToken (least privileges we need)
    //   2) CreateRestrictedToken with DISABLE_MAX_PRIVILEGE
    //      => every privilege on the source token is turned into
    //         SE_PRIVILEGE_REMOVED (SeDebugPrivilege, SeTcbPrivilege, etc.)
    //   3) The result is a *primary* token suitable for CreateProcessAsUserW.
    std::error_code CreateRestricted();

    [[nodiscard]] HANDLE handle() const noexcept { return token_.get(); }
    [[nodiscard]] bool valid() const noexcept { return token_.valid(); }

 private:
    ScopedHandle token_;
};

}  // namespace sandbox
