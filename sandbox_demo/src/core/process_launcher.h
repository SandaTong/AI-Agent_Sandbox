// -----------------------------------------------------------------------------
// core/process_launcher.h
// -----------------------------------------------------------------------------
// 负责编排沙箱子进程的启动流水线，按正确顺序执行：
//
//     1. CreateProcessAsUserW（带 CREATE_SUSPENDED，主线程冻结）
//     2. AssignProcessToJobObject（进 Job）
//     3.（M1）SetTokenInformation 降 Integrity Level
// 4.（M1）STARTUPINFOEX 装 Mitigation Policy
//   5. ResumeThread —— target 此刻才开始执行用户代码
//
// 对应 JD:
//   W1 — 进程管控 / 沙箱加固 / 权限收敛
//
// 修复的硬伤（相比初版）:
//   原来是 CreateProcessAsUserW 不带 CREATE_SUSPENDED，进程一创建就开跑，
//   然后再 AssignProcessToJobObject。这样从"进程开始执行"到"Job 限制生效"
//   之间存在一个不确定长度的时间窗口，target 可以在这个窗口里为所欲为
//   （分配大内存 / 起线程 / 写剪贴板 / 甚至 fork 子进程逃出）。
//   CREATE_SUSPENDED 把这个窗口消掉：Job 装完 -> 才 Resume。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <chrono>
#include <string>
#include <system_error>

#include "common/scoped_handle.h"
#include "core/job_manager.h"
#include "core/token_manager.h"

namespace sandbox {

struct LaunchOptions {
    std::wstring exe_path;     // 可执行文件绝对路径
    std::wstring cmd_line;     // 完整命令行；为空时会自动拼一个
    std::wstring working_dir;  // 工作目录；为空表示继承 broker 的
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
