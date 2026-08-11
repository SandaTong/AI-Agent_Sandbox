// -----------------------------------------------------------------------------
// core/self_defense.h
// -----------------------------------------------------------------------------
// M5：target 侧运行时自检模块（用户态"反注入 / 反篡改"检测层）。
//
// 【为什么内核 mitigation 之外还要用户态检测】
//   M1/M5 给 target 装的反注入 mitigation（PROHIBIT_DYNAMIC_CODE /
//   BLOCK_NON_MICROSOFT_BINARIES / DISABLE_EXTENSION_POINTS）是"内核级护栏"
//   —— 从娘胎带出来、无法绕过，是第一道也是最强的一道防线。但它有两个盲区：
//     1. 它是"拦"，不是"报"——被拦下的攻击尝试，target 自己不一定知道发生过；
//        安全产品往往需要"感知到有人在打我"（上报 / 取证 / 熔断）。
//     2. 不是所有环境都能开满 mitigation（兼容性：target 可能依赖某个未签名
//        第三方 DLL，就不能开 BLOCK_NON_MICROSOFT_BINARIES）。开不满时，用户态
//        检测就是补位的第二道防线。
//   所以生产级沙箱（含 Chromium / 各类 EDR）都是"内核挡 + 用户态查"双层。
//   M5 这个模块就是那第二层。
//
// 【三个检测手段（本模块实现）】
//   ① DLL 加载通知（LdrRegisterDllNotification）
//        ntdll 半公开 API。注册一个回调，进程每次 LoadLibrary / 映射映像时
//        内核加载器都会回调我们，带上被加载模块的全路径。我们对照白名单，
//        发现"白名单外的 DLL 被加载"就告警——这正好能抓到 M4 那种
//        "远程线程 LoadLibraryW(sandbox_hook.dll)"式注入。
//        （比轮询遍历模块列表实时得多——加载瞬间就知道。）
//
//   ② 可疑远程线程扫描（CreateToolhelp32Snapshot + 线程起始地址）
//        M4 注入的本质是 CreateRemoteThread(入口=LoadLibraryW)。正常线程的
//        起始地址落在进程自有模块的代码段内；远程注入线程的起点往往是
//        kernel32!LoadLibraryW 或一块 VirtualAllocEx 出来的裸内存。枚举本
//        进程线程、取其起始地址，落在"非预期模块"里的就可疑。
//        （M5 精简：用线程起始地址 + 模块归属做启发式判断。）
//
//   ③ 关键 API inline-hook 篡改自检
//        M4 的 inline hook 会把 kernel32!CreateFileW 头几字节改成 jmp。
//        我们读这几个字节，看是不是被改成了跳转指令（0xE9 / 0xFF25 / 0x48B8
//        …+jmp 等常见 hook 形态）。被改了说明有人 inline-hook 了我们。
//        （这是"反篡改 / 完整性自检"的最小实现。）
//
// 【定位】
//   本模块跑在**被保护进程（target）自己内部**——这是它和 M0~M4 的根本区别：
//   前面都是 broker 从外部配置 target，M5 的检测天然是"我自己查我自己"。
//   它不依赖 broker，target 独立就能自检并把结果打印/上报。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace sandbox {

// 单条自检发现。
struct DefenseFinding {
    enum class Kind {
        kSuspiciousDll,     // 白名单外的 DLL 被加载
        kSuspiciousThread,  // 起始地址不在预期模块内的线程（疑似远程线程）
        kApiTampered,       // 关键 API 头字节被改（疑似 inline hook）
    };
    Kind kind;
    std::wstring detail;  // 人类可读的详情（路径 / 线程起点 / API 名等）
};

// target 侧运行时自检器。典型用法：
//   SelfDefense sd;
//   sd.StartDllLoadMonitor();     // 尽早装 DLL 加载通知（越早越能抓到注入）
//   ...
//   auto findings = sd.ScanOnce(); // 跑一次全量自检（线程 + API 完整性）
//   for (auto& f : findings) 上报 / 打印
class SelfDefense {
 public:
    SelfDefense() = default;
    ~SelfDefense();

    SelfDefense(const SelfDefense&) = delete;
    SelfDefense& operator=(const SelfDefense&) = delete;

    // 手段①：注册 DLL 加载通知。此后白名单外 DLL 被加载会记为 finding，
    // 并即时 OutputDebugStringW 告警。返回 false 表示 ntdll API 取不到
    // （极老系统），此时降级为只能靠 ScanOnce 的轮询。
    bool StartDllLoadMonitor();

    // 手段② + ③：跑一次全量自检——扫可疑远程线程 + 校验关键 API 完整性。
    // 返回本次发现的所有异常。可重复调用（定时自检）。
    std::vector<DefenseFinding> ScanOnce();

    // 取 DLL 加载通知累积到的告警（手段①的异步结果）。
    std::vector<DefenseFinding> DrainDllFindings();

 private:
    bool dll_monitor_on_ = false;
    void* cookie_ = nullptr;  // LdrRegisterDllNotification 返回的注销 cookie
};

}  // namespace sandbox
