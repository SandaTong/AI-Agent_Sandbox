// -----------------------------------------------------------------------------
// core/job_manager.h
// -----------------------------------------------------------------------------
// 封装 Windows Job Object，负责施加资源 / UI / 进程约束。
//
// 对应 JD Windows 方向 W1（进程管控 & 资源限制）:
//   "熟悉 Windows 权限与安全边界机制，包括 ... Job Object ...
//    具备权限收敛、进程约束与沙箱加固实践经验"
//
// 本类当前施加的多层护栏（自下而上）：
//   1. 进程数上限（JOB_OBJECT_LIMIT_ACTIVE_PROCESS）
//   2. 单进程内存上限（JOB_OBJECT_LIMIT_PROCESS_MEMORY）
//   3. CPU 硬上限（JobObjectCpuRateControlInformation + HARD_CAP）
//   4. UI 全锁（剪贴板/桌面/退出/全局 atom/USER 句柄……）
// 5. Kill-on-close：Broker 死 -> Job 里所有 target 一起死（安全保底）
//
// 相比初版 sandbox.cpp 修复的坑：
//   - 去掉 JOB_OBJECT_LIMIT_BREAKAWAY_OK（那个 flag 是"允许 target 逃出 job"，
// 语义正好相反）。改成加 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 和
//     JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION。
//   - 两次 SetInformationJobObject(ExtendedLimit) 合并成一次调用，避免
//     后一次全零结构体覆盖掉前一次的 LimitFlags / ActiveProcessLimit。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <cstdint>
#include <system_error>
#include <vector>

#include "common/scoped_handle.h"

namespace sandbox {

struct JobPolicy {
    // Job 内允许同时存活的进程数上限。
    DWORD active_process_limit = 4;

    // 单进程内存上限（字节）。0 = 不限制。
    SIZE_T process_memory_limit = 256ull * 1024 * 1024;  // 256 MB

    // CPU 上限，以万分之一为单位（2000 = 单核 20%）。0 = 不限制。
    DWORD cpu_rate_1_10000 = 2000;

    // UI 限制位图（JOB_OBJECT_UILIMIT_*）。
    DWORD ui_restrictions = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                            JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                            JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
                            JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
};

class JobManager {
 public:
    JobManager() = default;

    JobManager(const JobManager&) = delete;
    JobManager& operator=(const JobManager&) = delete;
    JobManager(JobManager&&) = default;
    JobManager& operator=(JobManager&&) = default;

    // 创建 Job 内核对象并施加 policy。幂等：同一实例第二次调用会替换掉旧 Job。
    std::error_code Create(const JobPolicy& policy);

    // 把 process_handle 塞进当前 Job。该进程必须以 CREATE_SUSPENDED 方式
    // 创建，这样 target 在执行第一行代码之前 Job 限制就已经生效。
    std::error_code Assign(HANDLE process_handle);

    // 查询 Job 内当前活跃进程数。
    [[nodiscard]] std::error_code GetActiveProcessCount(DWORD& out) const;

    // 枚举 Job 内所有存活进程的 PID；失败返回空 vector。
    [[nodiscard]] std::vector<DWORD> EnumerateProcessIds() const;

    [[nodiscard]] HANDLE handle() const noexcept { return job_.get(); }
    [[nodiscard]] bool valid() const noexcept { return job_.valid(); }

 private:
    ScopedHandle job_;
};

}  // namespace sandbox
