// -----------------------------------------------------------------------------
// demo/m0_demo.cc
// -----------------------------------------------------------------------------
// M0 demo entry point.
//
// Usage:
//   m0_demo.exe <target_exe> [args...]
//
// What this program does:
//   1) Builds a JobManager with resource + UI limits.
//   2) Builds a restricted primary Token.
//   3) Launches <target_exe> via ProcessLauncher (CREATE_SUSPENDED -> assign
//      to job -> resume).
//   4) Prints active PIDs inside the job.
//   5) Waits up to 30 s for the target to exit, prints exit code.
//
// This is intentionally simple; it exists to VALIDATE that the M0 building
// blocks compose end-to-end. Later milestones will replace / extend it.
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
    LOG_INFO << L"Usage: m0_demo.exe <target_exe> [args...]";
    LOG_INFO << L"Example: m0_demo.exe C:\\Windows\\System32\\notepad.exe";
}

// Rebuild a Windows command line from argv[1..], quoting each arg naively.
std::wstring BuildCmdLine(int argc, wchar_t** argv) {
    std::wstring out;
    for (int i = 1; i < argc; ++i) {
        if (!out.empty()) out.push_back(L' ');
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

    // ---------- Job----------
    JobManager job;
    JobPolicy policy;
    // We keep the defaults from JobPolicy — 4 procs, 256 MB each, 20% CPU cap.
    if (auto ec = job.Create(policy)) {
        LOG_ERROR << L"JobManager.Create failed: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- Token ----------
    TokenManager token;
    if (auto ec = token.CreateRestricted()) {
        LOG_ERROR << L"TokenManager.CreateRestricted failed: "
                  << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- Launch ----------
    LaunchOptions opts;
    opts.exe_path = argv[1];
    opts.cmd_line = BuildCmdLine(argc, argv);

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch failed: "
                  << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- Query ----------
    DWORD active = 0;
    (void)job.GetActiveProcessCount(active);
    LOG_INFO << L"Active processes in job: " << active;

    for (DWORD pid : job.EnumerateProcessIds()) {
        LOG_INFO << L"  in-job PID = " << pid;
    }

    // ---------- Wait ----------
    // We wait indefinitely for the target to exit (user closes it).
    // While m0_demo is alive, the Job kernel handle stays alive, so the
    // Job (and everything in it) also stays alive. When m0_demo finally
    // returns, JobManager's destructor closes the last Job handle, and
    // KILL_ON_JOB_CLOSE terminates every remaining process in the job.
    // That's the intended sandbox lifecycle: target dies with broker.
    LOG_INFO << L"Waiting for target to exit... (close it manually to end)";
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(),
                                           std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec) {
        LOG_WARN << L"WaitForExit returned: " << DescribeError(ec).c_str();
    } else {
        LOG_INFO << L"Target exited with code=" << exit_code;
    }
    return 0;
}
