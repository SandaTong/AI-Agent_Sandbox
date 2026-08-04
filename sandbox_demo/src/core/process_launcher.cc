// -----------------------------------------------------------------------------
// core/process_launcher.cc
// -----------------------------------------------------------------------------
#include "core/process_launcher.h"

#include <vector>

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

namespace {

// CreateProcessAsUserW requires the command-line buffer to be writable
// (documented; the API may write a NUL to break out argv[0]). std::wstring
// data() is writable since C++17.
std::wstring BuildMutableCmdLine(const LaunchOptions& opts) {
    if (!opts.cmd_line.empty()) return opts.cmd_line;
    // Wrap exe_path in quotes to keep spaces safe.
    std::wstring out;
    out.reserve(opts.exe_path.size() + 2);
    out.push_back(L'"');
    out.append(opts.exe_path);
    out.push_back(L'"');
    return out;
}

}  // namespace

std::error_code ProcessLauncher::Launch(const LaunchOptions& opts,
                                        LaunchResult& out) {
    if (!job_.valid()) return MakeWinError(ERROR_INVALID_STATE);
    if (!token_.valid()) return MakeWinError(ERROR_INVALID_STATE);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring cmdline = BuildMutableCmdLine(opts);

    // ---- Step 1: CreateProcessAsUserW with CREATE_SUSPENDED ----
    // Flags of interest:
    //   CREATE_SUSPENDED — thread starts frozen; nothing runs yet.
    //   CREATE_UNICODE_ENVIRONMENT — always pair this with W-suffix APIs.
    //   EXTENDED_STARTUPINFO_PRESENT — placeholder for M1 when we upgrade to
    //     STARTUPINFOEX + Mitigation Policy. Not set here yet.
    //
    // NOTE: We pass FALSE for bInheritHandles. In M3 (Broker/Target) we will
    // switch to TRUE + PROC_THREAD_ATTRIBUTE_HANDLE_LIST (explicit whitelist)
    // to safely pass pipes across without leaking anything else.
    constexpr DWORD kFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;

    LPCWSTR working_dir = opts.working_dir.empty()
                              ? nullptr
                              : opts.working_dir.c_str();

    if (!::CreateProcessAsUserW(token_.handle(),
                                opts.exe_path.c_str(),
                                cmdline.data(),
                                /*proc sec  */ nullptr,
                                /*thread sec*/ nullptr,
                                /*inherit   */ FALSE,
                                kFlags,
                                /*env       */ nullptr,
                                working_dir,
                                &si, &pi)) {
        return LastError();
    }

    // Take ownership immediately so any early return still cleans up.
    ScopedHandle proc(pi.hProcess);
    ScopedHandle thread(pi.hThread);

    // ---- Step 2: Attach to Job BEFORE the process runs ----
    if (auto ec = job_.Assign(proc.get())) {
        LOG_ERROR << L"AssignProcessToJobObject failed: " << ec.value();
        ::TerminateProcess(proc.get(), 1);
        return ec;
    }

    // ---- (M1 will insert IL/mitigation setup here) ----

    // ---- Step 3: Resume the main thread; target starts executing now ----
    if (::ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
        auto ec = LastError();
        ::TerminateProcess(proc.get(), 1);
        return ec;
    }

    LOG_INFO << L"ProcessLauncher: pid=" << pi.dwProcessId
             << L" tid=" << pi.dwThreadId
             << L" image=" << opts.exe_path;

    out.process= std::move(proc);
    out.main_thread = std::move(thread);
    out.process_id  = pi.dwProcessId;
    out.thread_id   = pi.dwThreadId;
    return {};
}

std::error_code ProcessLauncher::WaitForExit(HANDLE process,
                                             std::chrono::milliseconds timeout,
                                             DWORD& exit_code) {
    exit_code = 0;
    const DWORD ms = timeout.count() > 0xFFFFFFFELL
                         ? INFINITE
                         : static_cast<DWORD>(timeout.count());
    DWORD r = ::WaitForSingleObject(process, ms);
    if (r == WAIT_OBJECT_0) {
        if (!::GetExitCodeProcess(process, &exit_code)) return LastError();
        return {};
    }
    if (r == WAIT_TIMEOUT) return MakeWinError(WAIT_TIMEOUT);
    return LastError();
}

}  // namespace sandbox
