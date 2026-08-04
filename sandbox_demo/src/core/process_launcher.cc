// -----------------------------------------------------------------------------
// core/process_launcher.cc
// -----------------------------------------------------------------------------
#include "core/process_launcher.h"

#include <vector>

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

namespace {

// CreateProcessAsUserW 要求命令行 buffer 是可写的（文档明确说 API 可能会
// 往里写一个 '\0' 分割 argv[0]）。std::wstring::data() 从 C++17 起就是可写
// 指针。
std::wstring BuildMutableCmdLine(const LaunchOptions& opts) {
    if (!opts.cmd_line.empty())
        return opts.cmd_line;
    // 用引号把 exe 路径包起来，避免路径含空格时被 argv 拆开。
    std::wstring out;
    out.reserve(opts.exe_path.size() + 2);
    out.push_back(L'"');
    out.append(opts.exe_path);
    out.push_back(L'"');
    return out;
}

}  // namespace

std::error_code ProcessLauncher::Launch(const LaunchOptions& opts, LaunchResult& out) {
    if (!job_.valid())
        return MakeWinError(ERROR_INVALID_STATE);
    if (!token_.valid())
        return MakeWinError(ERROR_INVALID_STATE);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring cmdline = BuildMutableCmdLine(opts);

    // ---- 第 1 步：CreateProcessAsUserW，带 CREATE_SUSPENDED ----
    // 关键 flag：
    //   CREATE_SUSPENDED    — 主线程冻结，target 一行代码都没跑。
    //   CREATE_UNICODE_ENVIRONMENT — 用宽字符 API 必须搭配这个 flag。
    //   EXTENDED_STARTUPINFO_PRESENT — M1 升级 STARTUPINFOEX 时会加上，
    //     用来携带 Mitigation Policy。M0 还没到这一步。
    //
    // 这里 bInheritHandles 传 FALSE：target 不继承 broker 的任何 handle。
    // M3（Broker/Target IPC）时会改成 TRUE + PROC_THREAD_ATTRIBUTE_HANDLE_LIST
    // 白名单模式，只放通信管道那一根 handle，其他一律不给。
    constexpr DWORD kFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;

    LPCWSTR working_dir = opts.working_dir.empty() ? nullptr : opts.working_dir.c_str();

    if (!::CreateProcessAsUserW(token_.handle(), opts.exe_path.c_str(), cmdline.data(),
                                /*proc sec  */ nullptr,
                                /*thread sec*/ nullptr,
                                /*inherit   */ FALSE, kFlags,
                                /*env       */ nullptr, working_dir, &si, &pi)) {
        return LastError();
    }

    // 立即把返回的 raw HANDLE 装进 ScopedHandle。这样即便下面某一步失败
    // 走 early return，析构函数也会自动 CloseHandle。
    ScopedHandle proc(pi.hProcess);
    ScopedHandle thread(pi.hThread);

    // ---- 第 2 步：在 target 开始跑之前挂到 Job 上 ----
    if (auto ec = job_.Assign(proc.get())) {
        LOG_ERROR << L"AssignProcessToJobObject failed: " << ec.value();
        ::TerminateProcess(proc.get(), 1);
        return ec;
    }

    // ---- （M1 会在此插入：设 IL / 装 mitigation） ----

    // ---- 第 3 步：Resume 主线程；target 此刻真正开始执行 ----
    if (::ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
        auto ec = LastError();
        ::TerminateProcess(proc.get(), 1);
        return ec;
    }

    LOG_INFO << L"ProcessLauncher: pid=" << pi.dwProcessId << L" tid=" << pi.dwThreadId
             << L" image=" << opts.exe_path;

    out.process = std::move(proc);
    out.main_thread = std::move(thread);
    out.process_id = pi.dwProcessId;
    out.thread_id = pi.dwThreadId;
    return {};
}

std::error_code ProcessLauncher::WaitForExit(HANDLE process, std::chrono::milliseconds timeout,
                                             DWORD& exit_code) {
    exit_code = 0;

    // 便捷语义：零超时表示"永久等待"，供 broker 长期挂管 target 用。
    DWORD ms;
    if (timeout == std::chrono::milliseconds::zero()) {
        ms = INFINITE;
    } else if (timeout.count() >= INFINITE) {
        // WaitForSingleObject 用 0xFFFFFFFF (INFINITE) 作为哨兵值，任何合法
        // 的有限 timeout 必须严格小于它。这里 clamp 到最大可用有限值。
        ms = INFINITE - 1;
    } else {
        ms = static_cast<DWORD>(timeout.count());
    }

    DWORD r = ::WaitForSingleObject(process, ms);
    if (r == WAIT_OBJECT_0) {
        if (!::GetExitCodeProcess(process, &exit_code))
            return LastError();
        return {};
    }
    if (r == WAIT_TIMEOUT)
        return MakeWinError(WAIT_TIMEOUT);
    return LastError();
}

}  // namespace sandbox
