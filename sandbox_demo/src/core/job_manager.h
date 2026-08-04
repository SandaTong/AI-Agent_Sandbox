// -----------------------------------------------------------------------------
// core/job_manager.h
// -----------------------------------------------------------------------------
// Wraps a Windows Job Object and applies resource / UI / process constraints.
//
// JD mapping (Windows W1 - 进程管控& 资源限制):
//   "熟悉Windows权限与安全边界机制，包括 ... Job Object ... 具备权限收敛、
//    进程约束与沙箱加固实践经验"
//
// Layers of protection expressed here (bottom -> top):
//   1. Process cap (JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
//   2. Memory cap per-process (JOB_OBJECT_LIMIT_PROCESS_MEMORY)
//   3. CPU hard cap (JobObjectCpuRateControlInformation, HARD_CAP)
//   4. UI lockdown (clipboard/desktop/exitwindows/globalatoms/handles)
//   5. Kill-on-close: when Broker dies, all targets die with it (safety net)
//
// Fixed bugs (compared to old sandbox.cpp):
//   - Removed JOB_OBJECT_LIMIT_BREAKAWAY_OK (which *allowed* jailbreak).
//     Now we ADD JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and
//     JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION.
//   - Merged two SetInformationJobObject(ExtendedLimit) calls into one, so the
//     second no longer overwrites the first's LimitFlags / ActiveProcessLimit.
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <cstdint>
#include <system_error>
#include <vector>

#include "common/scoped_handle.h"

namespace sandbox {

struct JobPolicy {
    // Hard cap on the number of processes that may live inside the job.
    DWORD active_process_limit = 4;

    // Per-process memory cap in bytes. 0 = no limit.
    SIZE_T process_memory_limit = 256ull * 1024 * 1024;   // 256 MB

    // CPU cap as a fraction of 10000 (i.e. 2000 = 20% of one CPU). 0 = no cap.
    DWORD cpu_rate_1_10000 = 2000;

    // UI restrictions bitmask (JOB_OBJECT_UILIMIT_*).
    DWORD ui_restrictions = JOB_OBJECT_UILIMIT_DESKTOP |
                            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                            JOB_OBJECT_UILIMIT_EXITWINDOWS |
                            JOB_OBJECT_UILIMIT_GLOBALATOMS |
                            JOB_OBJECT_UILIMIT_HANDLES |
                            JOB_OBJECT_UILIMIT_READCLIPBOARD |
                            JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
                            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
};

class JobManager {
 public:
    JobManager() = default;

    JobManager(const JobManager&) = delete;
    JobManager& operator=(const JobManager&) = delete;
    JobManager(JobManager&&) = default;
    JobManager& operator=(JobManager&&) = default;

    // Create the job kernel object and apply `policy`. Idempotent — calling
    // twice with the same instance replaces the old job.
    std::error_code Create(const JobPolicy& policy);

    // Attach `process_handle` to this job. The process must have been created
    // with CREATE_SUSPENDED so limits apply before it runs.
    std::error_code Assign(HANDLE process_handle);

    // Query how many processes are currently active inside the job.
    [[nodiscard]] std::error_code GetActiveProcessCount(DWORD& out) const;

    // Enumerate PIDs of all processes still in the job. Empty on failure.
    [[nodiscard]] std::vector<DWORD> EnumerateProcessIds() const;

    [[nodiscard]] HANDLE handle() const noexcept { return job_.get(); }
    [[nodiscard]] bool valid() const noexcept { return job_.valid(); }

 private:
    ScopedHandle job_;
};

}  // namespace sandbox
