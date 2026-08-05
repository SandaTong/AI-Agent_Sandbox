// -----------------------------------------------------------------------------
// core/process_launcher.h
// -----------------------------------------------------------------------------
// 负责编排沙箱子进程的启动流水线，按正确顺序执行：
//
//     1. TokenManager.CreateRestricted()  已在 M0 完成
//     2. TokenManager.SetIntegrityLevel(Low)          【M1 新增】
//     3. MitigationAttrList.Configure(...)            【M1 新增，装入 STARTUPINFOEX】
//     4. DesktopIsolation.Create()【M1 新增，可选】
//     5. CreateProcessAsUserW（CREATE_SUSPENDED + EXTENDED_STARTUPINFO_PRESENT）
//     6. AssignProcessToJobObject
//     7. ResumeThread —— target 此刻才开始执行用户代码
//
// 对应 JD:
//   W1 — 进程管控 / 沙箱加固 / 权限收敛
//
// 关于 CREATE_SUSPENDED 三步舞的说明保留在 M0 版本，见 process_launcher.cc。
// M1 的关键升级点：从 STARTUPINFOW -> STARTUPINFOEX，用lpAttributeList 携带
// Mitigation Policy；同时用 lpDesktop 携带 "winsta\\desktop" 路径。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <chrono>
#include <string>
#include <system_error>

#include "common/scoped_handle.h"
#include "core/desktop_iso.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/token_manager.h"

namespace sandbox {

struct LaunchOptions {
    std::wstring exe_path;     // 可执行文件绝对路径
    std::wstring cmd_line;     // 完整命令行；为空时会自动拼一个
    std::wstring working_dir;  // 工作目录；为空表示继承 broker 的

    // 【M1】可选：如果给了 desktop_iso，target 会被绑到该隔离桌面。
    // nullptr 表示不做 UI 隔离，target 与 broker 共享 default desktop。
    const DesktopIsolation* desktop_iso = nullptr;

    // 【M1】可选：如果给了 attr_list，target 会走 STARTUPINFOEX 加载 Mitigation。
    // nullptr 表示不装 Mitigation Policy。
    const MitigationAttrList* attr_list = nullptr;
};

struct LaunchResult {
    ScopedHandle process;
    ScopedHandle main_thread;
    DWORD process_id = 0;
    DWORD thread_id = 0;
};

class ProcessLauncher {
 public:
    ProcessLauncher(JobManager& job, TokenManager& token) : job_(job), token_(token) {}

    // 完整的启动流水线。成功后 out 持有已经 Resume 过的 target 进程和
    // 主线程句柄（都是拥有型的 ScopedHandle）。
    std::error_code Launch(const LaunchOptions& opts, LaunchResult& out);

    // 便捷函数：阻塞等 process 退出，直到超时。
    // 特殊值：timeout == std::chrono::milliseconds::zero() 表示"永久等待"
    // （INFINITE）。其他值会被 clamp 到 WaitForSingleObject 可接受的 DWORD
    // 范围。
    // 返回:
    //   error_code{}      — 进程在超时内正常退出。
    //   WAIT_TIMEOUT      — 超时。
    //   其他   — WaitForSingleObject 调用本身失败。
    static std::error_code WaitForExit(HANDLE process, std::chrono::milliseconds timeout,
                                       DWORD& exit_code);

 private:
    JobManager& job_;
    TokenManager& token_;
};

}  // namespace sandbox
