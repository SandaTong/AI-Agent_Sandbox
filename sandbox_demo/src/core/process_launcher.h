// -----------------------------------------------------------------------------
// core/process_launcher.h
// -----------------------------------------------------------------------------
// Coordinates the correct startup dance for a sandboxed child process:
//
//     1. CreateProcessAsUserW  (with CREATE_SUSPENDED)
//     2. AssignProcessToJobObject
//     3. (M1) SetTokenInformation for Integrity Level (not yet in M0)
//     4. (M1) STARTUPINFOEX Mitigation Policy (not yet in M0)
//     5. ResumeThread — target starts executing user code AFTER all limits
//        are in place.
//
// JD mapping:
//   W1 - 进程管控/ 沙箱加固 / 权限收敛
//
// Bug fix (hard bug #3 vs old code):
//   The old code called CreateProcessAsUserW *without* CREATE_SUSPENDED,
//   then AssignProcessToJobObject. That leaves a window (arbitrarily long
//   under load) where the target ran without job limits. On Win7 it could
//   even fail entirely. CREATE_SUSPENDED closes that window.
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
    std::wstring exe_path;      // absolute path to executable
    std::wstring cmd_line;      // full command line; if empty, will be built
    std::wstring working_dir;   // empty = inherit
};

struct LaunchResult {
    ScopedHandle process;
    ScopedHandle main_thread;
    DWORD process_id = 0;
    DWORD thread_id  = 0;
};

class ProcessLauncher {
 public:
    ProcessLauncher(JobManager& job, TokenManager& token)
        : job_(job), token_(token) {}

    // Full startup dance. On success, `out` holds owning handles to the
    // (already resumed) target process and its main thread.
    std::error_code Launch(const LaunchOptions& opts, LaunchResult& out);

    // Convenience: block until the given process exits or timeout elapses.
    // Returns:
    //   error_code{}      — process exited within timeout.
    //   WAIT_TIMEOUT      — did not exit in time.
    //   Anything else     — WaitForSingleObject failure.
    static std::error_code WaitForExit(HANDLE process,
                                       std::chrono::milliseconds timeout,
                                       DWORD& exit_code);

 private:
    JobManager&   job_;
    TokenManager& token_;
};

}  // namespace sandbox
