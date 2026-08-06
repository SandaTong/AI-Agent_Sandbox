// -----------------------------------------------------------------------------
// core/appcontainer.h
// -----------------------------------------------------------------------------
// AppContainer / LowBox Token —— Windows 用户态沙箱的顶配。
//
// 对应 JD：
//   W1 - "AppContainer" 明确点名
//   W2 - "对象命名空间及句柄访问控制"（AppContainer 独立命名空间）
//
// 三个核心概念：
//
//   1) AppContainer Profile —— 系统级注册的一个"沙箱身份"，产生一个独一
//      无二的 Package SID（形如 S-1-15-2-XXX-XXX-...20 位子权限）。同名
//      profile 系统只保留一份，跨进程/跨启动可复用。删除靠 DeleteAppContainer
//      ProfileW，不删的话 profile 会永久留在注册表 HKCU\Software\Classes
//      \Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer。
//
//   2) Capability SID —— 白名单式权限。每个 capability 对应一个 SID：
//        internetClient      -> S-1-15-3-1
//        internetClientServer-> S-1-15-3-2
//        privateNetworkClientServer -> S-1-15-3-3
//        documentsLibrary    -> S-1-15-3-6
//        picturesLibrary     -> S-1-15-3-4
//      target 想访问什么就必须显式声明。没声明的**内核层默认拒绝**。这
//      和 M1 的"降IL"完全不同——M1 是"能力削减"，M2 是"白名单授权"。
//
//   3) LowBox Token —— 用 profile SID + capability 列表打包出的一种特殊
//      token。CreateProcessAsUserW 时通过 PROC_THREAD_ATTRIBUTE_SECURITY_
//      CAPABILITIES 传给内核，内核识别后走 AppContainer 特殊访问检查路径。
//      注意"LowBox" 是内核里的术语，用户态API 叫SECURITY_CAPABILITIES。
//
// 与 M1 的区别（重要）：
//   * M1 Restricted Token 是"你原来是谁 - 去掉一些权限"
//   * M2 LowBox Token 是"你换成一个新身份（Package SID），完全不同的
//     access-check 路径"
//   * M2 target 默认几乎啥都访问不了，capability 列表决定它能干啥
//
// 使用姿势：
//
//     AppContainerac;
//     ac.Create(L"WemeetSandboxDemo.M2", L"Sandbox Demo M2 Profile");
//     ac.AddCapability(WellKnownCapability::kInternetClient);
//     // ... target 启动时 launcher.Launch(opts) 里opts.appcontainer = &ac
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>
#include <userenv.h>  // CreateAppContainerProfile / DeriveAppContainerSidFromAppContainerName

#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

namespace sandbox {

// Windows 内置的著名 capability。参考:
//   https://learn.microsoft.com/windows/win32/secauthz/app-capability-sids
// 我们只列几个演示用得上的。想加自定义 capability 可以用 name 版本。
enum class WellKnownCapability : uint32_t {
    kInternetClient = 0,          // S-1-15-3-1  出方向 HTTP/TCP
    kInternetClientServer = 1,    // S-1-15-3-2  出+入方向
    kPrivateNetworkClientServer,  // S-1-15-3-3  局域网
    kDocumentsLibrary,            // S-1-15-3-6  我的文档
    kPicturesLibrary,             // S-1-15-3-4  图片库
};

class AppContainer {
 public:
    AppContainer() = default;
    ~AppContainer();

    AppContainer(const AppContainer&) = delete;
    AppContainer& operator=(const AppContainer&) = delete;

    // 注册（或复用）一个AppContainer profile。profile_name 建议用反向域名
    // 风格 "com.company.product.role"（不能含空格 / 特殊字符）。display_name
    // 是给用户看的说明。返回后 package_sid() 可用。
    //
    // 幂等：同名 profile 系统只保留一份，第二次调用会拿到已存在的 SID。
    std::error_code Create(const std::wstring& profile_name,
                           const std::wstring& display_name = L"");

    // 追加一个 well-known capability。必须在 Launch 前全部加完，之后
    // AppContainer 的 SECURITY_CAPABILITIES 结构会一次性组装出来。
    std::error_code AddCapability(WellKnownCapability cap);

    // 追加一个自定义 capability（Windows 允许应用申请自己的 capability，
    // 比如为 broker/target 之间对私有 named object 授权。M3 会用到）。
    std::error_code AddCapabilityByName(const std::wstring& cap_name);

    // 组装 SECURITY_CAPABILITIES 结构。ProcessLauncher 会调它，把结果塞给
    // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES 属性槽位。
    // 返回值：out 里的 AppContainerSid、Capabilities、CapabilityCount 都填好
    // 了，指针指向本对象内部存储，本对象存活期间保持有效。
    struct SecurityCapabilitiesView {
        PSID app_container_sid = nullptr;
        SID_AND_ATTRIBUTES* capabilities = nullptr;
        DWORD capability_count = 0;
    };
    SecurityCapabilitiesView View() const;

    [[nodiscard]] PSID package_sid() const noexcept { return package_sid_; }
    [[nodiscard]] const std::wstring& profile_name() const noexcept { return profile_name_; }
    [[nodiscard]] bool valid() const noexcept { return package_sid_ != nullptr; }

    // 把 package SID 转成人类可读字符串 "S-1-15-2-..."
    [[nodiscard]] std::wstring PackageSidString() const;

    // 删除profile（可选）。不调delete 的话 profile 永久留在注册表；对
    // demo 无所谓，对生产可能想清理。
    std::error_code Delete();

 private:
    void Cleanup();

    std::wstring profile_name_;
    PSID package_sid_ = nullptr;               // 由 FreeSid 释放
    std::vector<PSID> capability_sids_;        // 每个由FreeSid 释放
    std::vector<SID_AND_ATTRIBUTES> cap_arr_;  // 供 SecurityCapabilities 用
};

}  // namespace sandbox
