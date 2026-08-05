// -----------------------------------------------------------------------------
// core/desktop_iso.cc
// -----------------------------------------------------------------------------
#include "core/desktop_iso.h"

#include <aclapi.h>
#include <sddl.h>
#include <winbase.h>

#include <random>

#include "common/logger.h"
#include "common/win_error.h"

#pragma comment(lib, "advapi32.lib")

namespace sandbox {

namespace {

// 名字要有随机后缀，避免多个 broker 实例撞名。
std::wstring RandomSuffix() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis;
    wchar_t buf[16] = {};
    ::swprintf_s(buf, L"%08x", dis(gen));
    return buf;
}

// RAII 包装 PSECURITY_DESCRIPTOR（用 LocalFree 释放）
struct LocalSD {
    PSECURITY_DESCRIPTOR sd = nullptr;
    ~LocalSD() {
        if (sd)
            ::LocalFree(sd);
    }
};

// 通过 SDDL 字符串构造 SECURITY_DESCRIPTOR。字符串语法：
//   "D:(A;;GA;;;WD)" 表示"DACL:允许 (A) Everyone (WD) 得到Generic All (GA)"
// 参考 MSDN "Security Descriptor Definition Language"。
//
// 用这个方法比调SetEntriesInAcl + SetSecurityInfo 简单得多，而且**没有
// WRITE_DAC 权限的坑**：SDDL 是在对象创建时通过 SECURITY_ATTRIBUTES 传入，
// 完全绕过事后修改 DACL 的授权检查。
std::error_code BuildSDFromSddl(const wchar_t* sddl, LocalSD& out) {
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &psd,
                                                                nullptr)) {
        return LastError();
    }
    out.sd = psd;
    return {};
}

}  // namespace

DesktopIsolation::~DesktopIsolation() {
    Cleanup();
}

void DesktopIsolation::Cleanup() {
    if (desktop_) {
        ::CloseDesktop(desktop_);
        desktop_ = nullptr;
    }
    if (winsta_) {
        ::CloseWindowStation(winsta_);
        winsta_ = nullptr;
    }
}

std::error_code DesktopIsolation::Create() {
    Cleanup();

    const std::wstring suffix = RandomSuffix();
    const std::wstring winsta_name = L"sandbox_winsta_" + suffix;
    const std::wstring desktop_name = L"sandbox_desk";

    // ---- 构造 winsta / desktop 的 SECURITY_DESCRIPTOR ----
    //
    // SDDL 字符串解释：
    //   "D:"                DACL 段开始
    //   "(A;;GA;;;WD)"      Access-Allowed ACE，Generic All 给Everyone (WD)
    //   "(A;;GA;;;BA)"      Access-Allowed ACE，Generic All 给 Built-in Admins (BA)
    //   "(A;;GA;;;SY)"      Access-Allowed ACE，Generic All 给 Local System (SY)
    //
    // 为什么必须一开始就带上 DACL：
    //   * Low IL target 用同一个用户 SID，但因mandatory label 层默认"Medium
    //     及以上才能访问"这条隐式规则被拒。给Everyone 加 ACE 后 attach 就
    //     能过（Low IL target 也匹配 Everyone）。
    //   * 如果不在 Create 时带DACL，事后想用SetSecurityInfo 改，我们的
    //     winsta 句柄需要WRITE_DAC 权限——而 CreateWindowStation 返回的
    //     句柄默认**不带**WRITE_DAC，需要重开一次或者干脆在 Create 时就带
    //     上DACL。后者更简单。
    //
    // 生产级实现应该只授权 target 的具体 logon SID，而不是 Everyone。M2 上
    // AppContainer 后 target 有独立 profile SID，那时候可以精确授权。
    //
    // 特别注意：DACL 只解决"按SID 允许访问"，还必须加**Mandatory Label**
    // 才能让 Low IL 进程进得来。默认从当前 winsta 继承的 label 通常是
    // High/System IL，Low IL target 一律被拒 → 报 0xC0000142。所以下面
    // SDDL 里同时给了 "S:(ML;;NW;;;LW)"，把完整性层的门槛降到 Low IL。
    //
    //   "S:"                SACL 段开始（承载 Mandatory Label ACE）
    //   "(ML;;;;;LW)"       ML=Mandatory Label；空 policy 位 = 不做任何
    //                       "写/执行/读"完整性检查；LW=Low Mandatory Level
    //                       (S-1-16-4096)。给desktop 设 Low IL 层门槛，允
    //                       许 Low IL target 无障碍访问。
    static constexpr const wchar_t* kOpenSddl =
        L"D:(A;;GA;;;WD)(A;;GA;;;BA)(A;;GA;;;SY)"
        L"S:(ML;;;;;LW)";
    LocalSD sd_holder;
    if (auto ec = BuildSDFromSddl(kOpenSddl, sd_holder)) {
        return ec;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd_holder.sd;
    sa.bInheritHandle = FALSE;

    // 步骤 1：记住 broker 当前 winsta。
    HWINSTA saved_winsta = ::GetProcessWindowStation();

    // 步骤 2：CreateWindowStationW，DACL 通过 lpsa 传入。
    HWINSTA new_winsta = ::CreateWindowStationW(winsta_name.c_str(),
                                                /*flags*/ 0, WINSTA_ALL_ACCESS,
                                                /*lpsa*/ &sa);
    if (!new_winsta) {
        return LastError();
    }

    // 步骤 3：切进新 winsta。
    if (!::SetProcessWindowStation(new_winsta)) {
        auto ec = LastError();
        ::CloseWindowStation(new_winsta);
        return ec;
    }

    // 步骤 4：CreateDesktopW，同样把 sa 传进去。
    constexpr DWORD kDesktopAllAccess =
        STANDARD_RIGHTS_REQUIRED | DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
        DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | DESKTOP_ENUMERATE |
        DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP;

    HDESK new_desktop = ::CreateDesktopW(desktop_name.c_str(),
                                         /*lpszDevice*/ nullptr,
                                         /*pDevmode*/ nullptr,
                                         /*flags*/ 0, kDesktopAllAccess,
                                         /*lpsa*/ &sa);

    // 无论CreateDesktop 成功与否，都要先切回原winsta。
    ::SetProcessWindowStation(saved_winsta);

    if (!new_desktop) {
        auto ec = LastError();
        ::CloseWindowStation(new_winsta);
        return ec;
    }

    winsta_ = new_winsta;
    desktop_ = new_desktop;
    desktop_path_ = winsta_name + L"\\" + desktop_name;

    LOG_INFO << L"DesktopIsolation: 隔离桌面已就绪 -> " << desktop_path_
             << L"（DACL 已允许 Everyone/Admins/SYSTEM 访问）";
    return {};
}

std::error_code DesktopIsolation::GrantAccessToLowIntegrity() {
    // 现在 Create() 已经在创建时通过 SECURITY_ATTRIBUTES 带上了开放的 DACL，
    // 本方法保留只是为了 API 向后兼容。什么都不做。
    return {};
}

}  // namespace sandbox
