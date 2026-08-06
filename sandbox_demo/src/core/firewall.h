// -----------------------------------------------------------------------------
// core/firewall.h
// -----------------------------------------------------------------------------
// Windows Firewall (INetFwPolicy2) 简易封装。
//
// 用途：给 AppContainer target 写一条 outbound "Block All" 规则，让它出方向
// 被 mpssvc 拦下。生产上（Chromium sandbox 等）broker 起 target 前必做这一步。
//
// ⚠️ 注意事项：
//   1. **需要管理员权限**才能修改 Windows Firewall 规则 (INetFwPolicy2 底层
//      走 RPC 到 mpssvc，写入 firewall rule 表要写权限)。非管理员运行会
//      得到 E_ACCESSDENIED (0x80070005) —— broker 里返回 error_code 用户
//      自己看。
//   2. 我们用 CoInitializeEx(APARTMENTTHREADED) 起 COM，然后
//      CoCreateInstance(CLSID_NetFwPolicy2) 拿 INetFwPolicy2 主接口。
//   3. 规则用 CoCreateInstance(CLSID_NetFwRule) 造，塞进 policy 的 Rules
//      集合。规则里最关键是：
//        - Direction = NET_FW_RULE_DIR_OUT
//        - Action = NET_FW_ACTION_BLOCK
//        - Protocol = 6 (TCP)  —— 我们只拦 TCP outbound
//        - LocalAppPackageId = "S-1-15-2-..." (Package SID)
//   4. Package SID 通过 IPropertyStore-like 的 Put_LocalAppPackageId 塞
//      进去 (INetFwRule2 接口)，是 Win8+ 才有的 property。
//   5. 类的实例析构时删除自己加过的规则，保证 broker 退出后不污染系统。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <system_error>

namespace sandbox {

class FirewallGuard {
 public:
    FirewallGuard() = default;
    ~FirewallGuard();

    FirewallGuard(const FirewallGuard&) = delete;
    FirewallGuard& operator=(const FirewallGuard&) = delete;

    // 加一条 outbound TCP block 规则，针对给定的 Package SID (SDDL字符串)。
    // rule_name 是自定义规则名字，方便调试 (在 wf.msc 里能看到)。
    //
    // 返回值：
    //   {} 成功
    //   0x80070005 (ACCESS_DENIED) - broker 没管理员权限
    //   其他 HRESULT - COM 调用失败，看 win_error.DescribeError 输出
    //
    // 幂等：同名规则已存在会先删再加。
    std::error_code AddBlockAllOutboundForAppContainer(const std::wstring& package_sid_sddl,
                                                       const std::wstring& rule_name);

    // 手动清理规则。析构会自动调，一般不用手动 Remove。
    std::error_code RemoveRule(const std::wstring& rule_name);

 private:
    // 记住我们加过的规则名字，析构里逐个清理。
    std::wstring added_rule_name_;
    bool com_initialized_ = false;

    // 内部：确保 COM 初始化 (APARTMENTTHREADED)。可重入调用。
    std::error_code EnsureComInit();
};

}  // namespace sandbox
