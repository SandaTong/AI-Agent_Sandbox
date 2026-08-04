// -----------------------------------------------------------------------------
// demo/m0_demo.cc
// -----------------------------------------------------------------------------
// M0 冒烟主程序入口。
//
// 用法:
//   m0_demo.exe <target_exe> [args...]
//
// 做的事:
//   1) 建一个 JobManager（含资源 + UI 限制）
//   2) 建一个受限 primary token
//   3) 通过 ProcessLauncher 启动 <target_exe>
//      —— 走"CREATE_SUSPENDED -> assign to job -> resume"三步舞
// 4) 打印 Job 里的活跃 PID
//   5) 永久等待 target 退出，最后打印退出码
//
// 这一版是"验证 M0 各积木能拼在一起"的最小闭环。后续 milestone 会新增
// 更完整的 broker 主程序（broker.exe），本文件仅作教学冒烟。
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/job_manager.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"

namespace {

void PrintUsage() {
    LOG_INFO << L"用法: m0_demo.exe <target_exe> [args...]";
    LOG_INFO << L"示例: m0_demo.exe C:\\Windows\\System32\\notepad.exe";
}

// 把 argv[1..] 重新拼成一条 Windows 命令行，简单粗暴地给每个参数加引号。
std::wstring BuildCmdLine(int argc, wchar_t** argv) {
    std::wstring out;
    for (int i = 1; i < argc; ++i) {
        if (!out.empty())
            out.push_back(L' ');
        out.push_back(L'"');
        out.append(argv[i]);
        out.push_back(L'"');
    }
    return out;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    using namespace sandbox;

    // ---------- Job ----------
    JobManager job;
    JobPolicy policy;
    // 用 JobPolicy 默认值：4 进程 / 单进程 256 MB / CPU 硬顶 20%。
    if (auto ec = job.Create(policy)) {
        LOG_ERROR << L"JobManager.Create 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- Token ----------
    TokenManager token;
    if (auto ec = token.CreateRestricted()) {
        LOG_ERROR << L"TokenManager.CreateRestricted 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- Launch ----------
    LaunchOptions opts;
    opts.exe_path = argv[1];
    opts.cmd_line = BuildCmdLine(argc, argv);

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- Query ----------
    DWORD active = 0;
    (void)job.GetActiveProcessCount(active);
    LOG_INFO << L"Job 内活跃进程数: " << active;

    for (DWORD pid : job.EnumerateProcessIds()) {
        LOG_INFO << L"  in-job PID = " << pid;
    }

    // ---------- Wait ----------
    // 永久等 target 退出。broker 存活期间 Job handle 一直被持有，Job 及其
    // 内成员进程都活着；一旦 m0_demo return，JobManager 析构关闭最后一个
    // Job handle，触发 KILL_ON_JOB_CLOSE 把 Job 里剩下的进程内核级带走。
    // 这就是"target 与 broker 共生"的沙箱生命周期语义。
    LOG_INFO << L"等待 target 退出中……（手动关闭 target 才会结束）";
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(), std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec) {
        LOG_WARN << L"WaitForExit 返回异常: " << DescribeError(ec).c_str();
    } else {
        LOG_INFO << L"Target 退出，exit_code=" << exit_code;
    }
    return 0;
}
