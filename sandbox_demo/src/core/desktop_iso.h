// -----------------------------------------------------------------------------
// core/desktop_iso.h
// -----------------------------------------------------------------------------
// Alternate Winstation + Desktop 隔离：把 target 塞进一个我们自己新建的
// window station 和 desktop，让它看不到 broker/用户桌面上的窗口。
//
// 对应 JD:
//   W1 —"隔离边界与适用范围" / UI 侧收敛
//
// 三层 GUI 命名空间（读书对应：MS Docs "Window Stations"）：
//
//     Session（登录会话，包含用户所有 GUI 状态）
//       └── WindowStation（"WinSta0" 是可交互桌面，其他都是不可见的）
//            └── Desktop（"Default"、"Winlogon"、"ScreenSaver"……）
//                 └── HWND（窗口）
//
// 沙箱要做的：
//   - 新建一个 WinSta叫 "sandbox_winsta_<pid>_<random>"
//   - 在里面新建一个 Desktop "sandbox_desk"
//   - 把这个 WinSta+Desktop 的名字通过 STARTUPINFO::lpDesktop 传给 target
//   - Target 一启动就"住"在这个 winsta+desktop 里，EnumWindows 出来的
//     窗口列表基本是空的（除了它自己创建的），Send/PostMessage 也发不到
//     用户真正的窗口
//
// 注意事项：
//   1) WinSta 上必须**授予 target 的 SID 访问权**（我们目前跑在同一用户
//      下，SID 相同，默认 DACL 就允许；但 M2 上 AppContainer 后必须显式加
//      ACE，M2 那时再补）。
//   2) broker 自己**不需要**切进这个 winsta，只是持有handle 保证 winsta
//      不会被回收。target 进程启动时 Win32 子系统会按 lpDesktop 字符串
//      自动 attach。
//   3) UI 相关的 lockdown 和 Job UI 限制是**互补**的，不是替代关系：
//        Job UI 限制 =拦"target 用 USER 句柄操作系统对象"（比如剪贴板API）
//        Alt Desktop = 拦"target 通过窗口消息看到/影响别的进程窗口"
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>
#include <winuser.h>  // DESKTOP_ALL_ACCESS / WINSTA_ALL_ACCESS 常量

#include <string>
#include <system_error>

namespace sandbox {

class DesktopIsolation {
 public:
    DesktopIsolation() = default;
    ~DesktopIsolation();

    DesktopIsolation(const DesktopIsolation&) = delete;
    DesktopIsolation& operator=(const DesktopIsolation&) = delete;
    DesktopIsolation(DesktopIsolation&&) = delete;
    DesktopIsolation& operator=(DesktopIsolation&&) = delete;

    // 创建一对新的 WinSta+Desktop。名字里含随机数，方便同一 broker 起多
    // 个 target 时区分。broker 需要在整个 target 生命周期内保持本对象存
    // 活，否则 WinSta 会被系统回收，target 就跟着挂了。
    std::error_code Create();

    // 给隔离 winsta+desktop 的 DACL 授权 Low IL target 访问。
    //
    // 现在的实现：Create() 内部已经通过 SECURITY_ATTRIBUTES 一次到位地把
    // DACL 设成 "Everyone / Admins / SYSTEM 全权限"，所以本方法现在是空
    // 实现，保留只是为了 API 兼容。M2 上 AppContainer 后会重新用到，精
    // 确授权 AppContainer profile SID。
    //
    // 历史坑：早版本试图用 SetSecurityInfo 事后改 DACL，但
    // CreateWindowStation 返回的句柄默认不带 WRITE_DAC，SetSecurityInfo
    // 直接返回 ACCESS_DENIED。改成 Create 时通过 SDDL 传入 SD 一次到位。
    std::error_code GrantAccessToLowIntegrity();

    // 拿到 "WinStaName\DesktopName" 形式的完整路径，用于填STARTUPINFO::lpDesktop。
    // 注意 lpDesktop 需要**可写**指针（Win32 传统坑），这里返回一份可写副本。
    [[nodiscard]] std::wstring desktop_path() const { return desktop_path_; }

    [[nodiscard]] bool valid() const noexcept { return winsta_ != nullptr && desktop_ != nullptr; }

 private:
    void Cleanup();

    HWINSTA winsta_ = nullptr;
    HDESK desktop_ = nullptr;
    std::wstring desktop_path_;  // "sandbox_winsta_xxx\\sandbox_desk"
};

}  // namespace sandbox
