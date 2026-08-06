// -----------------------------------------------------------------------------
// core/appcontainer.cc
// -----------------------------------------------------------------------------
#include "core/appcontainer.h"

#include <sddl.h>  // ConvertSidToStringSidW

#include <array>

#include "common/logger.h"
#include "common/win_error.h"

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

namespace sandbox {

namespace {

// 把 WellKnownCapability 枚举映射成SDDL 字符串形式的 SID。
// 参考: https://learn.microsoft.com/windows/win32/secauthz/app-capability-sids
const wchar_t* WellKnownCapSid(WellKnownCapability c) {
    switch (c) {
        case WellKnownCapability::kInternetClient:
            return L"S-1-15-3-1";
        case WellKnownCapability::kInternetClientServer:
            return L"S-1-15-3-2";
        case WellKnownCapability::kPrivateNetworkClientServer:
            return L"S-1-15-3-3";
        case WellKnownCapability::kPicturesLibrary:
            return L"S-1-15-3-4";
        case WellKnownCapability::kDocumentsLibrary:
            return L"S-1-15-3-6";
    }
    return nullptr;
}

// 由字符串 SID 构造 PSID。释放用 LocalFree（ConvertStringSid... 系列的规矩）。
std::error_code SidFromString(const wchar_t* s, PSID& out) {
    if (!::ConvertStringSidToSidW(s, &out)) {
        return LastError();
    }
    return {};
}

// 由 capability name 派生 capability SID。
//
// 注意：`DeriveCapabilitySidsFromName` 在 SDK 里有声明，但导入库分散在
// api-ms-win-security-base-l1-2-2/ KernelBase 里，链接不同版本 SDK 时不
// 一定能一次拿到。M2 演示只需要 well-known cap（如 internetClient），本
// 函数暂用占位实现——需要自定义 cap name 时再补进来。
std::error_code DeriveCapabilityFromName(const std::wstring& /*name*/, PSID& /*out_cap_sid*/) {
    return MakeWinError(ERROR_NOT_SUPPORTED);
}

}  // namespace

AppContainer::~AppContainer() {
    Cleanup();
}

void AppContainer::Cleanup() {
    for (PSID p : capability_sids_) {
        if (p)
            ::LocalFree(p);
    }
    capability_sids_.clear();
    cap_arr_.clear();

    if (package_sid_) {
        // CreateAppContainerProfile / DeriveAppContainerSidFromAppContainerName
        // 返回的 SID 要用 FreeSid 释放（不是 LocalFree）。这两个 API 的返回
        // SID 是 alloc 出来的，参考 MSDN。
        ::FreeSid(package_sid_);
        package_sid_ = nullptr;
    }
    profile_name_.clear();
}

std::error_code AppContainer::Create(const std::wstring& profile_name,
                                     const std::wstring& display_name) {
    Cleanup();

    profile_name_ = profile_name;
    const std::wstring dname = display_name.empty() ? profile_name : display_name;

    // Step 1: 尝试创建 profile。如果已存在会返回 HRESULT_FROM_WIN32(
    // ERROR_ALREADY_EXISTS)，那我们退回去Derive 拿到现有 SID。
    HRESULT hr = ::CreateAppContainerProfile(profile_name.c_str(), dname.c_str(),
                                             /*description*/ dname.c_str(),
                                             /*capabilities*/ nullptr,
                                             /*capabilityCount*/ 0, &package_sid_);
    if (FAILED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
            // 复用已存在的 profile。
            hr = ::DeriveAppContainerSidFromAppContainerName(profile_name.c_str(), &package_sid_);
            if (FAILED(hr)) {
                return MakeWinError(HRESULT_CODE(hr));
            }
            LOG_INFO << L"AppContainer: 复用已有 profile: " << profile_name;
        } else {
            return MakeWinError(HRESULT_CODE(hr));
        }
    } else {
        LOG_INFO << L"AppContainer: 新建 profile: " << profile_name;
    }

    LOG_INFO << L"AppContainer: package SID = " << PackageSidString();
    return {};
}

std::error_code AppContainer::AddCapability(WellKnownCapability cap) {
    const wchar_t* s = WellKnownCapSid(cap);
    if (!s) {
        return MakeWinError(ERROR_INVALID_PARAMETER);
    }
    PSID p = nullptr;
    if (auto ec = SidFromString(s, p)) {
        return ec;
    }
    capability_sids_.push_back(p);
    SID_AND_ATTRIBUTES saa{};
    saa.Sid = p;
    saa.Attributes = SE_GROUP_ENABLED;
    cap_arr_.push_back(saa);
    LOG_INFO << L"AppContainer: + capability " << s;
    return {};
}

std::error_code AppContainer::AddCapabilityByName(const std::wstring& cap_name) {
    PSID p = nullptr;
    if (auto ec = DeriveCapabilityFromName(cap_name, p)) {
        return ec;
    }
    capability_sids_.push_back(p);
    SID_AND_ATTRIBUTES saa{};
    saa.Sid = p;
    saa.Attributes = SE_GROUP_ENABLED;
    cap_arr_.push_back(saa);
    LOG_INFO << L"AppContainer: + capability(named) " << cap_name;
    return {};
}

AppContainer::SecurityCapabilitiesView AppContainer::View() const {
    SecurityCapabilitiesView v;
    v.app_container_sid = package_sid_;
    v.capabilities = cap_arr_.empty() ? nullptr : const_cast<SID_AND_ATTRIBUTES*>(cap_arr_.data());
    v.capability_count = static_cast<DWORD>(cap_arr_.size());
    return v;
}

std::wstring AppContainer::PackageSidString() const {
    if (!package_sid_)
        return L"<null>";
    LPWSTR s = nullptr;
    if (!::ConvertSidToStringSidW(package_sid_, &s)) {
        return L"<error>";
    }
    std::wstring out = s;
    ::LocalFree(s);
    return out;
}

std::error_code AppContainer::Delete() {
    if (profile_name_.empty()) {
        return MakeWinError(ERROR_INVALID_STATE);
    }
    HRESULT hr = ::DeleteAppContainerProfile(profile_name_.c_str());
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        return MakeWinError(HRESULT_CODE(hr));
    }
    LOG_INFO << L"AppContainer: profile deleted: " << profile_name_;
    Cleanup();
    return {};
}

}  // namespace sandbox
