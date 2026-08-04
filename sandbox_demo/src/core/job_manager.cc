// -----------------------------------------------------------------------------
// core/job_manager.cc
// -----------------------------------------------------------------------------
#include "core/job_manager.h"

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

std::error_code JobManager::Create(const JobPolicy& policy) {
    // 1) CreateJobObjectW: kernel object that groups processes.
    //    Second arg NULL => unnamed job (only referenceable by handle).
    ScopedHandle job(::CreateJobObjectW(nullptr, nullptr));
    if (!job) {
        return LastError();
    }

    // 2) Merge ALL flags for JobObjectExtendedLimitInformation into one struct
    //    and call SetInformationJobObject ONCE. Two prior calls with zero-init
    //    structs each was a bug (later call wiped earlier LimitFlags).
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
    DWORD flags = 0;

    // Hard kill: when the last handle to the job closes (e.g. broker crashes),
    // every process still in the job is terminated. This is the safety net
    // against orphaned sandboxed processes.
    flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    // If a process in the job takes an unhandled exception, terminate it
    // silently instead of showing the WER dialog.
    flags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    // Cap number of live processes.
    if (policy.active_process_limit > 0) {
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        eli.BasicLimitInformation.ActiveProcessLimit = policy.active_process_limit;
    }

    // Cap per-process working set / commit.
    if (policy.process_memory_limit > 0) {
        flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        eli.ProcessMemoryLimit = policy.process_memory_limit;
    }

    // NOTE: we deliberately do NOT set JOB_OBJECT_LIMIT_BREAKAWAY_OK or
    // JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK. Setting either would let a child
    // process escape the job via CREATE_BREAKAWAY_FROM_JOB. Absence of the
    // flag => any child process launched by anyone inside the job is
    // automatically part of the job too.

    eli.BasicLimitInformation.LimitFlags = flags;

    if (!::SetInformationJobObject(job.get(),
                                   JobObjectExtendedLimitInformation,
                                   &eli, sizeof(eli))) {
        return LastError();
    }

    // 3) CPU rate hard cap (JobObjectCpuRateControlInformation).
    //    HARD_CAP means the scheduler will actually withhold CPU once the
    //    quota is exceeded — not just weight down the priority.
    if (policy.cpu_rate_1_10000 > 0) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cri{};
        cri.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                           JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cri.CpuRate = policy.cpu_rate_1_10000;
        if (!::SetInformationJobObject(job.get(),
                                       JobObjectCpuRateControlInformation,
                                       &cri, sizeof(cri))) {
            return LastError();
        }
    }

    // 4) UI restrictions.
    if (policy.ui_restrictions != 0) {
        JOBOBJECT_BASIC_UI_RESTRICTIONS uir{};
        uir.UIRestrictionsClass = policy.ui_restrictions;
        if (!::SetInformationJobObject(job.get(),
                                       JobObjectBasicUIRestrictions,
                                       &uir, sizeof(uir))) {
            return LastError();
        }
    }

    job_ = std::move(job);
    LOG_INFO << L"JobManager: job created. process_limit="
             << policy.active_process_limit
             << L" mem_limit_mb=" << (policy.process_memory_limit >> 20)
             << L" cpu_rate=" << (policy.cpu_rate_1_10000 / 100.0) << L"%";
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
    if (!valid()) return MakeWinError(ERROR_INVALID_STATE);

    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acc{};
    if (!::QueryInformationJobObject(job_.get(),
                                     JobObjectBasicAccountingInformation,
                                     &acc, sizeof(acc), nullptr)) {
        return LastError();
    }
    out = acc.ActiveProcesses;
    return {};
}

std::vector<DWORD> JobManager::EnumerateProcessIds() const {
    if (!valid()) return {};

    // Two-phase query pattern:
    //   1) Call with a moderately sized buffer.
    //   2) If ERROR_MORE_DATA, the API writes the *required* size into
    //      returned_bytes; resize and retry.
    std::vector<BYTE> buf(sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) +
                          sizeof(ULONG_PTR) * 64);
    DWORD returned = 0;

    for (int attempt = 0; attempt < 2; ++attempt) {
        auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(buf.data());
        if (::QueryInformationJobObject(job_.get(),
                                        JobObjectBasicProcessIdList,
                                        list, static_cast<DWORD>(buf.size()),
                                        &returned)) {
            std::vector<DWORD> pids;
            pids.reserve(list->NumberOfProcessIdsInList);
            for (DWORD i = 0; i < list->NumberOfProcessIdsInList; ++i) {
                pids.push_back(static_cast<DWORD>(list->ProcessIdList[i]));
            }
            return pids;
        }

        const DWORD err = ::GetLastError();
        // "MORE_DATA" is signalled here as ERROR_MORE_DATA, and `returned` is
        // the number of bytes actually required. Resize and retry once.
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
