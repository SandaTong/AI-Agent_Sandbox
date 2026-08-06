// -----------------------------------------------------------------------------
// core/firewall.cc
// -----------------------------------------------------------------------------
#include "core/firewall.h"

#include <netfw.h>  // INetFwPolicy2, INetFwRule, INetFwRules
#include <objbase.h>

#include "common/logger.h"
#include "common/win_error.h"

// COM 库自动链接（Windows SDK 提供）。
// netfw.h 里的 CLSID/IID 定义会自动带链接 ole32/oleaut32 需求，我们再链接
// firewallapi.lib —— 不过实际发现 CLSID_NetFwPolicy2 走 ole32 就够了，
// firewallapi.lib 只提供 undocumented API。CMake 里我们统一 target_link
// ole32/oleaut32。
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace sandbox {

namespace {

// 小工具：把 std::wstring 转 BSTR。BSTR 内部是 len-prefixed，用完 SysFreeString。
class ScopedBSTR {
 public:
    explicit ScopedBSTR(const std::wstring& s) { bstr_ = ::SysAllocString(s.c_str()); }
    ~ScopedBSTR() {
        if (bstr_)
            ::SysFreeString(bstr_);
    }
    ScopedBSTR(const ScopedBSTR&) = delete;
    ScopedBSTR& operator=(const ScopedBSTR&) = delete;
    BSTR get() const { return bstr_; }
    explicit operator bool() const { return bstr_ != nullptr; }

 private:
    BSTR bstr_ = nullptr;
};

// COM RAII：自动 Release。
template <typename T>
class ScopedComPtr {
 public:
    ScopedComPtr() = default;
    ~ScopedComPtr() { reset(); }
    ScopedComPtr(const ScopedComPtr&) = delete;
    ScopedComPtr& operator=(const ScopedComPtr&) = delete;

    T** receive() { return &ptr_; }
    T* get() const { return ptr_; }
    T* operator->() const { return ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }
    void reset() {
        if (ptr_) {
            ptr_->Release();
            ptr_ = nullptr;
        }
    }

 private:
    T* ptr_ = nullptr;
};

std::error_code HrToEc(HRESULT hr) {
    // HRESULT 里low word 通常就是 Win32 error code (facility=FACILITY_WIN32)。
    // 我们直接把 hr 值塞进system_category —— DescribeError 会用
    // FormatMessage 拿到 Windows 侧的描述文本。
    return {static_cast<int>(hr), std::system_category()};
}

}  // namespace

// -----------------------------------------------------------------------------
FirewallGuard::~FirewallGuard() {
    if (!added_rule_name_.empty()) {
        (void)RemoveRule(added_rule_name_);
    }
    if (com_initialized_) {
        ::CoUninitialize();
    }
}

std::error_code FirewallGuard::EnsureComInit() {
    if (com_initialized_)
        return {};
    HRESULT hr = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    // RPC_E_CHANGED_MODE 意味着当前线程已经用别的 mode 起过 COM，也算成功
    if (hr == S_OK || hr == S_FALSE || hr == RPC_E_CHANGED_MODE) {
        com_initialized_ = (hr != RPC_E_CHANGED_MODE);  // 别人起的别人负责 Uninit
        return {};
    }
    return HrToEc(hr);
}

// 内部通用：拿 INetFwPolicy2 + 它的 Rules 集合。
static std::error_code AcquirePolicyAndRules(ScopedComPtr<INetFwPolicy2>& policy,
                                             ScopedComPtr<INetFwRules>& rules) {
    HRESULT hr = ::CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                    __uuidof(INetFwPolicy2), (void**)policy.receive());
    if (FAILED(hr)) {
        LOG_ERROR << L"CoCreateInstance(NetFwPolicy2) 失败 hr=0x" << std::hex << hr;
        return HrToEc(hr);
    }
    hr = policy->get_Rules(rules.receive());
    if (FAILED(hr))
        return HrToEc(hr);
    return {};
}

// -----------------------------------------------------------------------------
std::error_code FirewallGuard::AddBlockAllOutboundForAppContainer(
    const std::wstring& package_sid_sddl, const std::wstring& rule_name) {
    if (auto ec = EnsureComInit())
        return ec;

    // 幂等：先删再加。删返回失败不当致命错——可能是本来就不存在。
    (void)RemoveRule(rule_name);

    ScopedComPtr<INetFwPolicy2> policy;
    ScopedComPtr<INetFwRules> rules;
    if (auto ec = AcquirePolicyAndRules(policy, rules))
        return ec;

    //---- 构造一条 outbound TCP block 规则 ----
    ScopedComPtr<INetFwRule> rule;
    HRESULT hr = ::CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                                    __uuidof(INetFwRule), (void**)rule.receive());
    if (FAILED(hr)) {
        LOG_ERROR << L"CoCreateInstance(NetFwRule) 失败 hr=0x" << std::hex << hr;
        return HrToEc(hr);
    }

    // 基础属性
    ScopedBSTR bstr_name(rule_name);
    ScopedBSTR bstr_desc(L"sandbox_demo M2: block AppContainer outbound TCP");
    if (!bstr_name || !bstr_desc)
        return HrToEc(E_OUTOFMEMORY);

    if (FAILED(hr = rule->put_Name(bstr_name.get())))
        return HrToEc(hr);
    if (FAILED(hr = rule->put_Description(bstr_desc.get())))
        return HrToEc(hr);
    if (FAILED(hr = rule->put_Direction(NET_FW_RULE_DIR_OUT)))
        return HrToEc(hr);
    if (FAILED(hr = rule->put_Action(NET_FW_ACTION_BLOCK)))
        return HrToEc(hr);
    // Protocol = 6 (TCP)。UDP 是 17；这里我们只演示 TCP，够jailbreak-7 用
    if (FAILED(hr = rule->put_Protocol(6)))
        return HrToEc(hr);
    // 应用到所有 profile（Domain / Private / Public）
    if (FAILED(hr = rule->put_Profiles(NET_FW_PROFILE2_ALL)))
        return HrToEc(hr);
    if (FAILED(hr = rule->put_Enabled(VARIANT_TRUE)))
        return HrToEc(hr);

    // ---- 关键一步：把规则绑到 AppContainer Package SID ----
    // INetFwRule 本身没有 LocalAppPackageId 属性，需要 QI 成 INetFwRule3
    // （Win8+，SDK 里 INetFwRule2 只加 EdgeTraversalOptions，Rule3 才加
    // AppContainer 相关的 LocalAppPackageId / RemoteMachineAuthorizedList
    // 等属性）。
    ScopedComPtr<INetFwRule3> rule3;
    hr = rule->QueryInterface(__uuidof(INetFwRule3), (void**)rule3.receive());
    if (FAILED(hr)) {
        LOG_ERROR << L"QI(INetFwRule3) 失败 hr=0x" << std::hex << hr
                  << L"（可能是 Win7 以下不支持 AppContainer 规则）";
        return HrToEc(hr);
    }
    ScopedBSTR bstr_pkg(package_sid_sddl);
    if (!bstr_pkg)
        return HrToEc(E_OUTOFMEMORY);
    hr = rule3->put_LocalAppPackageId(bstr_pkg.get());
    if (FAILED(hr)) {
        LOG_ERROR << L"put_LocalAppPackageId 失败 hr=0x" << std::hex << hr;
        return HrToEc(hr);
    }

    // ---- 塞进 rules 集合 ----
    hr = rules->Add(rule.get());
    if (FAILED(hr)) {
        // E_ACCESSDENIED (0x80070005) - 非管理员运行
        LOG_ERROR << L"INetFwRules.Add 失败 hr=0x" << std::hex << hr
                  << L"（若是 0x80070005 请以管理员运行 broker）";
        return HrToEc(hr);
    }

    added_rule_name_ = rule_name;
    LOG_INFO << L"Firewall: 已加规则 \"" << rule_name.c_str()
             << L"\" (outbound block TCP for Package SID)";
    return {};
}

// -----------------------------------------------------------------------------
std::error_code FirewallGuard::RemoveRule(const std::wstring& rule_name) {
    if (auto ec = EnsureComInit())
        return ec;

    ScopedComPtr<INetFwPolicy2> policy;
    ScopedComPtr<INetFwRules> rules;
    if (auto ec = AcquirePolicyAndRules(policy, rules))
        return ec;

    ScopedBSTR bstr_name(rule_name);
    if (!bstr_name)
        return HrToEc(E_OUTOFMEMORY);
    HRESULT hr = rules->Remove(bstr_name.get());
    if (FAILED(hr)) {
        // rule 不存在也返回失败，我们不当致命错
        return HrToEc(hr);
    }
    if (rule_name == added_rule_name_)
        added_rule_name_.clear();
    LOG_INFO << L"Firewall: 已清理规则 \"" << rule_name.c_str() << L"\"";
    return {};
}

}  // namespace sandbox
