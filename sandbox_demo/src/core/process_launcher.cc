// -----------------------------------------------------------------------------
// core/process_launcher.cc
// -----------------------------------------------------------------------------
#include "core/process_launcher.h"

#include <vector>

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

namespace {

// CreateProcessAsUserW要求命令行 buffer 是可写的（文档明确说 API 可能会
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

    // 【M1】统一走 STARTUPINFOEX。即使不装 Mitigation / Desktop，用 EX
    // 版本也不会有副作用（内核直接读StartupInfo 部分，AttributeList 为
    // NULL 时按无扩展处理）。
    STARTUPINFOEXW six{};
    six.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    // 【M1】UI 隔离：如果提供了 DesktopIsolation，就把它的完整路径塞进
    // lpDesktop。字符串必须**可写**（Win32 传统坑），我们保留一份 std::wstring。
    std::wstring mutable_desktop;
    if (opts.desktop_iso && opts.desktop_iso->valid()) {
        mutable_desktop = opts.desktop_iso->desktop_path();
        six.StartupInfo.lpDesktop = mutable_desktop.data();
    }

    // 【M1】Mitigation Policy：塞 attribute list。
    if (opts.attr_list && opts.attr_list->valid()) {
        six.lpAttributeList = opts.attr_list->ptr();
    }

    PROCESS_INFORMATION pi{};
    std::wstring cmdline = BuildMutableCmdLine(opts);

    // ----第 1 步：CreateProcessAsUserW，带 CREATE_SUSPENDED ----
    // 关键 flag：
    //   CREATE_SUSPENDED       — 主线程冻结，target 一行代码都没跑。
    //   CREATE_UNICODE_ENVIRONMENT — 用宽字符 API 必须搭配这个 flag。
    //   EXTENDED_STARTUPINFO_PRESENT — 【M1】告诉内核lpStartupInfo 是
    //   STARTUPINFOEX，需要额外读 lpAttributeList。
    //
    // bInheritHandles = FALSE：target 不继承 broker 的任何 handle。M3 时
    // 会改成 TRUE + PROC_THREAD_ATTRIBUTE_HANDLE_LIST 白名单模式。
    constexpr DWORD kFlags =
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;

    LPCWSTR working_dir = opts.working_dir.empty() ? nullptr : opts.working_dir.c_str();

    // 注意：STARTUPINFOEX 通过 reinterpret_cast 传成 STARTUPINFOW*。
    // 这是 Win32 API 规定的写法，内核会根据 kFlags 里的
    // EXTENDED_STARTUPINFO_PRESENT 决定按扩展结构解析。
    if (!::CreateProcessAsUserW(token_.handle(), opts.exe_path.c_str(), cmdline.data(),
                                /*proc sec   */ nullptr,
                                /*thread sec */ nullptr,
                                /*inherit    */ FALSE, kFlags,
                                /*env        */ nullptr, working_dir,
                                reinterpret_cast<LPSTARTUPINFOW>(&six), &pi)) {
        return LastError();
    }

    // 立即把返回的 raw HANDLE 装进 ScopedHandle。这样即便下面某一步失败
    // 走 early return，析构函数也会自动 CloseHandle。
    ScopedHandle proc(pi.hProcess);
    ScopedHandle thread(pi.hThread);

    // ---- 第 2 步：在 target 开始跑之前挂到Job 上 ----
    if (auto ec = job_.Assign(proc.get())) {
        LOG_ERROR << L"AssignProcessToJobObject failed: " << ec.value();
        ::TerminateProcess(proc.get(), 1);
        return ec;
    }

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
        // 的有限 timeout 必须严格小于它。这里clamp 到最大可用有限值。
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
