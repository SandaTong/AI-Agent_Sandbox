// -----------------------------------------------------------------------------
// core/token_manager.cc
// -----------------------------------------------------------------------------
#include "core/token_manager.h"

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

std::error_code TokenManager::CreateRestricted() {
    // Minimum rights required to duplicate this token into a restricted primary
    // token usable by CreateProcessAsUserW:
    //   TOKEN_DUPLICATE       — CreateRestrictedToken internally duplicates.
    //   TOKEN_QUERY           — CreateRestrictedToken reads SIDs/privileges.
    //   TOKEN_ASSIGN_PRIMARY  — needed later by CreateProcessAsUserW.
    //   TOKEN_ADJUST_DEFAULT  — needed if we ever call SetTokenInformation
    //on the returned handle (M1 will set IL).
    constexpr DWORD kDesired =
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
        TOKEN_ADJUST_DEFAULT;

    HANDLE raw_parent = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), kDesired, &raw_parent)) {
        return LastError();
    }
    ScopedHandle parent(raw_parent);

    // DISABLE_MAX_PRIVILEGE:
    //   marks every privilege as SE_PRIVILEGE_REMOVED. Equivalent to passing
    //   the full privilege list into DisableSidsCount, but future-proof.
    //
    // We pass zero for the SidsToDisable / SidsToRestrict slots. That means
    // the token keeps its original group membership. Real production sandbox
    // would add a "logon SID"-only restricted-SID list here to further clamp
    // ACL evaluation — we'll do that after M2.
    HANDLE raw_restricted = nullptr;
    if (!::CreateRestrictedToken(parent.get(),
                                 DISABLE_MAX_PRIVILEGE,
                                 /*DisableSidCount   */ 0, nullptr,
                                 /*DeletePrivCount   */ 0, nullptr,
                                 /*RestrictedSidCount*/ 0, nullptr,
                                 &raw_restricted)) {
        return LastError();
    }
    token_ = ScopedHandle(raw_restricted);

    LOG_INFO << L"TokenManager: restricted token created "
             << L"(all privileges removed)";
    return {};
}

}  // namespace sandbox
