// -----------------------------------------------------------------------------
// core/mitigation.h
// -----------------------------------------------------------------------------
// STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_LIST装配器：一次性给 target 装上
// 一整套进程级缓解策略（Process Mitigation Policy）。
//
// 对应 JD:
//   W1 — 沙箱加固 / 权限收敛
//   W4 — 反注入（我们在这里就把"只允许微软签名 DLL""禁动态代码"这些
//         反注入护栏装上了；M5 会做运行时的检测层）
//
// 概念对照（读书对应：Richter Ch4 进程 / MS Docs "Process Mitigation Policy"）：
//   1) STARTUPINFOEX 是 STARTUPINFOW 的扩展版，额外多一个 lpAttributeList
//      指针，指向一段属性列表。
//   2) 属性列表用 InitializeProcThreadAttributeList /
//      UpdateProcThreadAttribute / DeleteProcThreadAttributeList 三件套操作。
//   3) 我们塞进的属性叫 PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY，值是一个
//      DWORD64 位图（Win10 起变成 2×DWORD64），每一位对应一项策略。
//   4) CreateProcess* 时 flag 里加上 EXTENDED_STARTUPINFO_PRESENT，并把
//      STARTUPINFOEX 转成 STARTUPINFOW* 传进去，内核会在**加载器还没跑**
//      的时候就把这些策略绑到 EPROCESS 上。
//
// 相比 Job UI 限制 / Restricted Token 的优势：
// Job/Token 是"事后拦截"（API 调用时判断），Mitigation Policy 是"从娘胎
//   带出来"——ntdll 加载器 / syscall 分发器 / 内存分配器直接按策略工作，
//   无法绕过（除非绕内核）。这也是为什么 Chromium sandbox renderer 靠这
//   一层就能挡住绝大多数 exploit提权。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <system_error>
#include <vector>

namespace sandbox {

// 我们默认装配的策略位组合。字段名对应 MS Docs 中 PROCESS_CREATION_MITIGATION_POLICY_*
// 常量的语义。全部开启后 target 变得非常"洁癖"，注意：
//   * strict_signed_dll 会拦掉所有非微软签名的 DLL 加载，如果 target 依赖
//     第三方 DLL（比如 CRT 之外的库），会启动失败。M1 我们的 hello_target
//     是纯 CRT + kernel32/advapi32，都是微软签名的，能过。
//   * disable_win32k极其激进，非专门写的 renderer 起不来。默认关。
struct MitigationConfig {
    bool dep = true;                       // Data Execution Prevention
    bool aslr_bottom_up = true;            // 强制 bottom-up ASLR
    bool aslr_force_relocate = true;       // 强制映像重定位（拦"未启用 ASLR 的 DLL"）
    bool strict_signed_dll = true;         // 只允许微软签名 DLL 加载（反注入绝杀）
    bool prohibit_dynamic_code = true;     // 禁止 VirtualAlloc RWX /禁 JIT
    bool disable_extension_points = true;  // 禁 AppInit_DLLs / SetWindowsHook 全局钩子
    bool disable_child_process = true;     // 禁子进程（沙箱标配）
    bool image_load_no_remote = true;      // 禁从 UNC 路径加载映像
    bool image_load_no_low_label = true;   // 禁加载低完整性文件的映像
    bool disable_win32k = false;           // Win32k lockdown，只有专门的 target 才开
    bool cet_shadow_stack = false;         // CET Shadow Stack（Win10 2004+ CPU 需支持）
};

// 拥有 PROC_THREAD_ATTRIBUTE_LIST 生命周期的 RAII 封装。
// 构造后调用 Configure() 装配属性；ptr() 返回可直接塞进 STARTUPINFOEX 的裸指针。
class MitigationAttrList {
 public:
    MitigationAttrList() = default;
    ~MitigationAttrList();

    MitigationAttrList(const MitigationAttrList&) = delete;
    MitigationAttrList& operator=(const MitigationAttrList&) = delete;
    MitigationAttrList(MitigationAttrList&&) = delete;
    MitigationAttrList& operator=(MitigationAttrList&&) = delete;

    // 按 config 计算位图，一次性写进属性列表。可以重复调用（内部会重置）。
    // parent_process 传非 nullptr 时会额外插入 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    // 属性（M3 之后会用到，M1 传 nullptr 即可）。
    std::error_code Configure(const MitigationConfig& config, HANDLE parent_process = nullptr);

    [[nodiscard]] LPPROC_THREAD_ATTRIBUTE_LIST ptr() const noexcept {
        return reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(const_cast<BYTE*>(buffer_.data()));
    }
    [[nodiscard]] bool valid() const noexcept { return !buffer_.empty(); }

 private:
    void Reset();

    std::vector<BYTE> buffer_;             // 存PROC_THREAD_ATTRIBUTE_LIST 结构
    DWORD64 mitigation_bits_[2] = {0, 0};  // policy 位图（Win10+ 为 2 个 DWORD64）
    HANDLE parent_process_ = nullptr;
    bool initialized_ = false;
};

// 便捷函数：只把 MitigationConfig 编译成 policy 位图，不构建属性列表。
// 用于调试打印。
void ComposeMitigationBits(const MitigationConfig& cfg, DWORD64& out_policy, DWORD64& out_policy2);

}  // namespace sandbox
