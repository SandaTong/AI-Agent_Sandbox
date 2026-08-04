// -----------------------------------------------------------------------------
// core/job_manager.cc
// -----------------------------------------------------------------------------
#include "core/job_manager.h"

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

std::error_code JobManager::Create(const JobPolicy& policy) {
    // 1) CreateJobObjectW：创建 Job 内核对象。第二个参数传 NULL 表示无名
    //    Job（只能通过 handle 引用，不能通过对象名 OpenJobObject 打开）。
    ScopedHandle job(::CreateJobObjectW(nullptr, nullptr));
    if (!job) {
        return LastError();
    }

    // 2) JobObjectExtendedLimitInformation 这个 info-class 是"整块覆盖"语义，
    //    所以我们把所有相关 flag / limit 合成一个结构体一次性写下去。
    //    早期版本分两次调用会导致第二次的零值结构体覆盖第一次的设置。
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
    DWORD flags = 0;

    // 硬 kill：Job 的最后一个 handle 被关闭时（比如 broker 崩溃），
    // Job 里所有还活着的进程都会被内核终结。这是防止"沙箱失控 target
    // 变成孤儿进程"的兜底保护。
    flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    // Job 内进程发生未处理异常时静默终结，不弹 WER 对话框。
    flags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    // 活跃进程数上限。
    if (policy.active_process_limit > 0) {
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        eli.BasicLimitInformation.ActiveProcessLimit = policy.active_process_limit;
    }

    // 单进程 working set / commit 上限。
    if (policy.process_memory_limit > 0) {
        flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        eli.ProcessMemoryLimit = policy.process_memory_limit;
    }

    // 注意：这里刻意不设 JOB_OBJECT_LIMIT_BREAKAWAY_OK 或 SILENT_BREAKAWAY_OK。
    // 一旦设了，子进程就可以通过 CREATE_BREAKAWAY_FROM_JOB 逃出 Job。
    // 不设这两个 flag 意味着：Job 内任何进程 CreateProcess 出来的子进程
    // 自动继承 Job，谁也逃不掉。

    eli.BasicLimitInformation.LimitFlags = flags;

    if (!::SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &eli,
                                   sizeof(eli))) {
        return LastError();
    }

    // 3) CPU 硬上限（JobObjectCpuRateControlInformation）。
    //    HARD_CAP 表示"超额直接扣时间片"，而不是只降优先级，是真正的硬顶。
    if (policy.cpu_rate_1_10000 > 0) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cri{};
        cri.ControlFlags =
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cri.CpuRate = policy.cpu_rate_1_10000;
        if (!::SetInformationJobObject(job.get(), JobObjectCpuRateControlInformation, &cri,
                                       sizeof(cri))) {
            return LastError();
        }
    }

    // 4) UI 限制。
    if (policy.ui_restrictions != 0) {
        JOBOBJECT_BASIC_UI_RESTRICTIONS uir{};
        uir.UIRestrictionsClass = policy.ui_restrictions;
        if (!::SetInformationJobObject(job.get(), JobObjectBasicUIRestrictions, &uir,
                                       sizeof(uir))) {
            return LastError();
        }
    }

    job_ = std::move(job);
    LOG_INFO << L"JobManager: job created. process_limit=" << policy.active_process_limit
             << L" mem_limit_mb=" << (policy.process_memory_limit >> 20) << L" cpu_rate="
             << (policy.cpu_rate_1_10000 / 100.0) << L"%";
    return {};
}

std::error_code JobManager::Assign(HANDLE process_handle) {
    if (!valid()) {
        return MakeWinError(ERROR_INVALID_STATE);
    }
    if (!::AssignProcessToJobObject(job_.get(), process_handle)) {
        return LastError();
    }
    return {};
}

std::error_code JobManager::GetActiveProcessCount(DWORD& out) const {
    out = 0;
    if (!valid())
        return MakeWinError(ERROR_INVALID_STATE);

    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acc{};
    if (!::QueryInformationJobObject(job_.get(), JobObjectBasicAccountingInformation, &acc,
                                     sizeof(acc), nullptr)) {
        return LastError();
    }
    out = acc.ActiveProcesses;
    return {};
}

std::vector<DWORD> JobManager::EnumerateProcessIds() const {
    if (!valid())
        return {};

    // Win32 常见的"两阶段 query"模式：
    //   1) 先用一个大致够用的 buffer 调用；
    //   2) 如果返回 ERROR_MORE_DATA，API 会把实际需要的字节数写进 returned，
    //    按这个大小 resize 后重试一次。
    std::vector<BYTE> buf(sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * 64);
    DWORD returned = 0;

    for (int attempt = 0; attempt < 2; ++attempt) {
        auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(buf.data());
        if (::QueryInformationJobObject(job_.get(), JobObjectBasicProcessIdList, list,
                                        static_cast<DWORD>(buf.size()), &returned)) {
            std::vector<DWORD> pids;
            pids.reserve(list->NumberOfProcessIdsInList);
            for (DWORD i = 0; i < list->NumberOfProcessIdsInList; ++i) {
                pids.push_back(static_cast<DWORD>(list->ProcessIdList[i]));
            }
            return pids;
        }

        const DWORD err = ::GetLastError();
        // ERROR_MORE_DATA 表示 buffer 不够，returned 是实际需要的字节数。
        if (err == ERROR_MORE_DATA && returned > buf.size()) {
            buf.resize(returned);
            continue;
        }
        LOG_ERROR << L"EnumerateProcessIds failed: gle=" << err;
        break;
    }
    return {};
}

}  // namespace sandbox
