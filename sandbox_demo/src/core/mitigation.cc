// -----------------------------------------------------------------------------
// core/mitigation.cc
// -----------------------------------------------------------------------------
#include "core/mitigation.h"

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

// -----------------------------------------------------------------------------
// ComposeMitigationBits
//
// 把布尔配置翻译成两个 DWORD64 位图。
// 每个常量都在 SDK 里定义（processthreadsapi.h），文档参见：
//   https://learn.microsoft.com/windows/win32/api/processthreadsapi/ne-processthreadsapi-process_mitigation_policy
//   https://learn.microsoft.com/windows/win32/procthread/updateprocthreadattribute
//
// 注意 Win10 起UpdateProcThreadAttribute 支持传入两个 DWORD64（大小 = 16）
// 来使用扩展位（比如 CET Shadow Stack、Redirection Trust）。M1 只用到低位。
// -----------------------------------------------------------------------------
void ComposeMitigationBits(const MitigationConfig& c, DWORD64& p, DWORD64& p2) {
    p = 0;
    p2 = 0;

    if (c.dep) {
        p |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
        p |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE;
    }
    if (c.aslr_bottom_up) {
        p |= PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON;
    }
    if (c.aslr_force_relocate) {
        p |= PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON;
    }
    if (c.strict_signed_dll) {
        // 只允许由微软签名的映像加载。也可以选 STORE 变体只允许 Store 签名，
        // 但对我们的场景（普通桌面 target）微软签名足够。
        p |= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    }
    if (c.prohibit_dynamic_code) {
        p |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    }
    if (c.disable_extension_points) {
        // 拦 AppInit_DLLs、SetWindowsHookEx 全局钩子、IME 注入等一票老式手法。
        p |= PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON;
    }
    if (c.disable_child_process) {
        // 沙箱标配：target 无法通过 CreateProcess 起任何子进程。
        // 注意这个 flag 名字很像但**不在** PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
        // 里，它是**独立**的属性（PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY），
        // 需要单独调 UpdateProcThreadAttribute 装。见 Configure() 里的处理。
        // 这里只是把标志位存进配置，真正装配在下面。
    }
    if (c.image_load_no_remote) {
        p |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON;
    }
    if (c.image_load_no_low_label) {
        p |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;
    }
    if (c.disable_win32k) {
        // Win32k lockdown：禁 target 调Win32k syscall（GUI 相关一整套）。
        // 只有专门写的 renderer 才能这么起，普通程序会因为 CRT 里带的
        // wcserr/GDI 引用而崩。默认关。
        p |= PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
    }
    if (c.cet_shadow_stack) {
#ifdef PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON
        p2 |= PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON;
#endif
    }
}

// -----------------------------------------------------------------------------
// MitigationAttrList
// -----------------------------------------------------------------------------
MitigationAttrList::~MitigationAttrList() {
    Reset();
}

void MitigationAttrList::Reset() {
    if (initialized_) {
        ::DeleteProcThreadAttributeList(
            reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer_.data()));
        initialized_ = false;
    }
    buffer_.clear();
    mitigation_bits_[0] = 0;
    mitigation_bits_[1] = 0;
    parent_process_ = nullptr;
}

std::error_code MitigationAttrList::Configure(const MitigationConfig& config,
                                              HANDLE parent_process) {
    Reset();

    // 计算这次要装几个属性槽位。
    // 槽位 1：PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY（一定装）
    // 槽位 2（可选）：PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY
    // 槽位 3（可选）：PROC_THREAD_ATTRIBUTE_PARENT_PROCESS（M3 会用）
    DWORD attr_count = 1;
    if (config.disable_child_process)
        ++attr_count;
    if (parent_process != nullptr)
        ++attr_count;

    // Step 1: 问系统这个属性列表需要多大buffer（两阶段调用）。
    SIZE_T needed = 0;
    ::InitializeProcThreadAttributeList(nullptr, attr_count, 0, &needed);
    if (needed == 0)
        return LastError();

    buffer_.resize(needed);
    auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer_.data());

    if (!::InitializeProcThreadAttributeList(list, attr_count, 0, &needed)) {
        buffer_.clear();
        return LastError();
    }
    initialized_ = true;

    // Step 2: 装 Mitigation Policy 位图。
    ComposeMitigationBits(config, mitigation_bits_[0], mitigation_bits_[1]);

    // Win10+ 用 2 个 DWORD64（16 字节），旧系统只支持 1 个（8 字节）。
    // 为了兼容，如果 mitigation_bits_[1] == 0 就只塞 8 字节。
    const SIZE_T mit_size = (mitigation_bits_[1] != 0) ? sizeof(mitigation_bits_) : sizeof(DWORD64);

    if (!::UpdateProcThreadAttribute(list, /*flags*/ 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                     mitigation_bits_, mit_size,
                                     /*prev*/ nullptr, /*ret size*/ nullptr)) {
        return LastError();
    }

    // Step 3（可选）：Child Process Policy。这个属性是"独立槽位"，跟
    // Mitigation Policy 位图不重合。
    // ALWAYS_ON 表示"子进程 == 立刻退出"，target 想CreateProcess 会被内核
    // 直接拒绝，错误码 5(ACCESS_DENIED)。
    static DWORD kChildPolicyDeny = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    if (config.disable_child_process) {
        if (!::UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                                         &kChildPolicyDeny, sizeof(kChildPolicyDeny), nullptr,
                                         nullptr)) {
            return LastError();
        }
    }

    // Step 4（可选）：Parent Process 绑定。M3 起我们用它来防"PPID 伪造"，
    // 并让 target 从指定进程继承 handle。M1 传nullptr，不进这个分支。
    if (parent_process != nullptr) {
        parent_process_ = parent_process;
        if (!::UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                         &parent_process_, sizeof(parent_process_), nullptr,
                                         nullptr)) {
            return LastError();
        }
    }

    LOG_INFO << L"MitigationAttrList: 已装配" << L" policy=0x" << std::hex << mitigation_bits_[0]
             << L" policy2=0x" << mitigation_bits_[1] << std::dec << L" child_process_disabled="
             << (config.disable_child_process ? 1 : 0);
    return {};
}

}  // namespace sandbox
