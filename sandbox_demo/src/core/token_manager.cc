// -----------------------------------------------------------------------------
// core/token_manager.cc
// -----------------------------------------------------------------------------
#include "core/token_manager.h"

#include <sddl.h>  // ConvertStringSidToSidW / SID相关

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

std::error_code TokenManager::CreateRestricted() {
    // 我们复制父token 并生成受限 primary token，需要的最小权限如下：
    //   TOKEN_DUPLICATE       — CreateRestrictedToken 内部会duplicate。
    //   TOKEN_QUERY— CreateRestrictedToken 需要读源 SID/privilege。
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
    //   且面向未来（新增privilege 类型也会被自动囊括）。
    //
    // SidsToDisable / SidsToRestrict 传 0/nullptr，表示不动组成员——
    // token 依然属于原来的用户组（比如 BUILTIN\Users）。M2 之后会往
    // SidsToRestrict 塞 "logon SID only" 之类的 SID 进一步收紧 ACL 判断。
    HANDLE raw_restricted = nullptr;
    if (!::CreateRestrictedToken(parent.get(), DISABLE_MAX_PRIVILEGE,
                                 /*DisableSidCount   */ 0, nullptr,
                                 /*DeletePrivCount   */ 0, nullptr,
                                 /*RestrictedSidCount*/ 0, nullptr, &raw_restricted)) {
        return LastError();
    }
    token_ = ScopedHandle(raw_restricted);

    LOG_INFO << L"TokenManager: 受限 token 已创建（所有 privilege 已 REMOVE）";
    return {};
}

// -----------------------------------------------------------------------------
// SetIntegrityLevel — 【M1 新增】
//
// 背景（读书对应：潘书 §2.5.4 安全性管理 / Windows Internals Ch 7）：
//   Access Token 里除了 UserSid / Groups / Privileges 外，还有一个字段叫
//   **Mandatory Label**（TOKEN_MANDATORY_LABEL），本质是一个 SID：
//    S-1-16-<RID>
//   RID 值决定 IL 等级，例如：
//   Untrusted = 0x0000     Low       = 0x1000
// Medium    = 0x2000     High     = 0x3000
// System    = 0x4000
//   系统对内核对象（文件、注册表、命名管道……）做访问检查时，如果客体
//   有 mandatory label ACE，会先做"完整性等级比较"再走DACL，一票否决。
//
// SetTokenInformation(TokenIntegrityLevel, ...) 就是改这个字段。
// -----------------------------------------------------------------------------
std::error_code TokenManager::SetIntegrityLevel(IntegrityLevel level) {
    if (!valid())
        return MakeWinError(ERROR_INVALID_STATE);

    // 步骤 1：构造 Mandatory Label SID —— "S-1-16-<RID>"。
    // 用字符串形式构造最省事，AllocateAndInitializeSid 也能做但更啰嗦。
    wchar_t sid_str[32] = {};
    ::swprintf_s(sid_str, L"S-1-16-%u", static_cast<unsigned int>(level));

    PSID label_sid = nullptr;
    if (!::ConvertStringSidToSidW(sid_str, &label_sid)) {
        return LastError();
    }

    // 步骤 2：把 SID 塞进 TOKEN_MANDATORY_LABEL 结构体，写到 token 里。
    // Attributes 必须是 SE_GROUP_INTEGRITY（说明这是 mandatory label 而非普通组）。
    TOKEN_MANDATORY_LABEL tml{};
    tml.Label.Sid = label_sid;
    tml.Label.Attributes = SE_GROUP_INTEGRITY;

    // TokenIntegrityLevel 这个 info-class 要求传入的结构体大小包含 SID 本身
    // 的实际长度。GetLengthSid 拿到 SID 字节数后累加进sizeof 之外的部分。
    const DWORD info_size = sizeof(TOKEN_MANDATORY_LABEL) + ::GetLengthSid(label_sid);

    BOOL ok = ::SetTokenInformation(token_.get(), TokenIntegrityLevel, &tml, info_size);
    const DWORD gle = ::GetLastError();
    ::LocalFree(label_sid);  // ConvertStringSidToSid 的返回值必须 LocalFree

    if (!ok) {
        return MakeWinError(gle);
    }

    const wchar_t* name = L"?";
    switch (level) {
        case IntegrityLevel::kUntrusted:
            name = L"Untrusted";
            break;
        case IntegrityLevel::kLow:
            name = L"Low";
            break;
        case IntegrityLevel::kMedium:
            name = L"Medium";
            break;
        case IntegrityLevel::kHigh:
            name = L"High";
            break;
        case IntegrityLevel::kSystem:
            name = L"System";
            break;
    }
    LOG_INFO << L"TokenManager: Integrity Level 已降至 " << name;
    return {};
}

}  // namespace sandbox
