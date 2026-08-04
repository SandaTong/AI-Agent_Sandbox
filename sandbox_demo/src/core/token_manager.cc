// -----------------------------------------------------------------------------
// core/token_manager.cc
// -----------------------------------------------------------------------------
#include "core/token_manager.h"

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

std::error_code TokenManager::CreateRestricted() {
    // 我们复制父 token 并生成受限 primary token，需要的最小权限如下：
    //   TOKEN_DUPLICATE    — CreateRestrictedToken 内部会 duplicate。
    //   TOKEN_QUERY           — CreateRestrictedToken 需要读源 SID/privilege。
    //   TOKEN_ASSIGN_PRIMARY  — 后面 CreateProcessAsUserW 需要该权限。
    //   TOKEN_ADJUST_DEFAULT  — M1 我们会 SetTokenInformation 改 IL，需要它。
    constexpr DWORD kDesired =
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT;

    HANDLE raw_parent = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), kDesired, &raw_parent)) {
        return LastError();
    }
    ScopedHandle parent(raw_parent);

    // DISABLE_MAX_PRIVILEGE:
    //   把源 token 里的每一项 privilege 都标记为 SE_PRIVILEGE_REMOVED。
    //   等价于把所有 privilege 名字都塞进 DisableSidsCount 参数，但更省心，
    //   且面向未来（新增 privilege 类型也会被自动囊括）。
    //
    // SidsToDisable / SidsToRestrict 传 0/nullptr，表示不动组成员——
    // token 依然属于原来的用户组（比如 BUILTIN\Users）。M2 之后会往
    // SidsToRestrict 塞 "logon SID only" 之类的 SID 进一步收紧 ACL 判断。
    HANDLE raw_restricted = nullptr;
    if (!::CreateRestrictedToken(parent.get(), DISABLE_MAX_PRIVILEGE,
                                 /*DisableSidCount   */ 0, nullptr,
                                 /*DeletePrivCount */ 0, nullptr,
                                 /*RestrictedSidCount*/ 0, nullptr, &raw_restricted)) {
        return LastError();
    }
    token_ = ScopedHandle(raw_restricted);

    LOG_INFO << L"TokenManager: restricted token created " << L"(all privileges removed)";
    return {};
}

}  // namespace sandbox
