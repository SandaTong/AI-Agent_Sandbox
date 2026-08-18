// -----------------------------------------------------------------------------
// core/file_acl.cc
// -----------------------------------------------------------------------------
#include "core/file_acl.h"

#include <sddl.h>    // ConvertStringSidToSidW / ConvertSidToStringSidW
#include <aclapi.h>  // Get/SetNamedSecurityInfo / SetEntriesInAcl

#include <memory>
#include <vector>

#include "common/logger.h"
#include "common/win_error.h"

#pragma comment(lib, "advapi32.lib")

namespace sandbox {

namespace {

// 取当前进程用户 SID，转字符串形式（S-1-5-21-...）。失败返回空串。
std::wstring CurrentUserSidString() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        return L"";
    DWORD len = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::wstring out;
    if (len != 0) {
        std::vector<uint8_t> buf(len);
        if (::GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
            LPWSTR s = nullptr;
            if (::ConvertSidToStringSidW(tu->User.Sid, &s)) {
                out = s;
                ::LocalFree(s);
            }
        }
    }
    ::CloseHandle(token);
    return out;
}

// RAII：ConvertStringSidToSidW 返回的 PSID 需 LocalFree。
struct LocalSid {
    PSID sid = nullptr;
    ~LocalSid() {
        if (sid)
            ::LocalFree(sid);
    }
};

// 追加/删除一条针对 sid 的 DENY-WRITE ACE。add=true 追加，add=false 删除。
std::error_code ApplyDenyWrite(const std::wstring& dir, PSID sid, bool add) {
    // ---- 读现有 DACL ----
    PACL old_dacl = nullptr;
    PSECURITY_DESCRIPTOR psd = nullptr;
    DWORD rc = ::GetNamedSecurityInfoW(dir.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, &old_dacl, nullptr, &psd);
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR << L"FileAcl: GetNamedSecurityInfo 失败: "
                  << DescribeError(MakeWinError(rc)).c_str();
        return MakeWinError(rc);
    }
    std::unique_ptr<void, decltype(&::LocalFree)> psd_guard(psd, &::LocalFree);

    // ---- 组一条 DENY-WRITE 授权项（含目录+文件继承）----
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = FILE_GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA |
                              FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | DELETE;
    ea.grfAccessMode = add ? DENY_ACCESS : REVOKE_ACCESS;
    ea.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid);

    // SetEntriesInAcl 把这条项合并进旧 DACL，生成新 DACL。
    //   * DENY_ACCESS：SetEntriesInAcl 会把 DENY ACE 规范化放到 ALLOW 之前
    //     （满足 Windows 的 canonical ACE 顺序，DENY 优先命中）。
    //   * REVOKE_ACCESS：删掉该 SID 上匹配的项（用于回滚）。
    PACL new_dacl = nullptr;
    rc = ::SetEntriesInAclW(1, &ea, old_dacl, &new_dacl);
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR << L"FileAcl: SetEntriesInAcl 失败: " << DescribeError(MakeWinError(rc)).c_str();
        return MakeWinError(rc);
    }
    std::unique_ptr<void, decltype(&::LocalFree)> new_guard(new_dacl, &::LocalFree);

    // ---- 写回目录的 DACL ----
    rc = ::SetNamedSecurityInfoW(const_cast<LPWSTR>(dir.c_str()), SE_FILE_OBJECT,
                                 DACL_SECURITY_INFORMATION, nullptr, nullptr, new_dacl, nullptr);
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR << L"FileAcl: SetNamedSecurityInfo 失败: "
                  << DescribeError(MakeWinError(rc)).c_str();
        return MakeWinError(rc);
    }
    return {};
}

}  // namespace

FileAcl::~FileAcl() {
    if (applied_)
        (void)RemoveDenyWrite();  // 尽力回滚，析构不抛异常
}

std::error_code FileAcl::AddDenyWrite(const std::wstring& dir, const std::wstring& sid_string) {
    if (applied_)
        return MakeWinError(ERROR_ALREADY_EXISTS);

    std::wstring sid_str = sid_string.empty() ? CurrentUserSidString() : sid_string;
    if (sid_str.empty()) {
        LOG_ERROR << L"FileAcl: 无法确定目标 SID";
        return MakeWinError(ERROR_INVALID_SID);
    }

    LocalSid sid;
    if (!::ConvertStringSidToSidW(sid_str.c_str(), &sid.sid)) {
        LOG_ERROR << L"FileAcl: SID 解析失败: " << DescribeError(LastError()).c_str();
        return LastError();
    }

    if (auto ec = ApplyDenyWrite(dir, sid.sid, /*add=*/true))
        return ec;

    applied_ = true;
    dir_ = dir;
    sid_string_ = sid_str;
    LOG_INFO << L"FileAcl: 已给 " << dir.c_str() << L" 追加 DENY-WRITE(继承) for SID "
             << sid_str.c_str();
    return {};
}

std::error_code FileAcl::RemoveDenyWrite() {
    if (!applied_)
        return {};

    LocalSid sid;
    if (!::ConvertStringSidToSidW(sid_string_.c_str(), &sid.sid))
        return LastError();

    auto ec = ApplyDenyWrite(dir_, sid.sid, /*add=*/false);
    applied_ = false;  // 无论成败都标记已回滚，避免析构里反复尝试
    if (!ec)
        LOG_INFO << L"FileAcl: 已移除 " << dir_.c_str() << L" 上的 DENY-WRITE";
    return ec;
}

}  // namespace sandbox
