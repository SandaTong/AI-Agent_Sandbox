#include "sandbox.h"
#include <sddl.h>
#include <userenv.h>
#include <iostream>

#pragma comment(lib, "userenv.lib")

Sandbox::Sandbox() = default;
Sandbox::~Sandbox() = default;

std::error_code Sandbox::create_job() {
    // Create Job Object
    HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
    if (!hJob) {
        return {static_cast<int>(GetLastError()), std::system_category()};
    }
    job_ = ScopedHandle(hJob);

    // Configure limits
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags =
      JOB_OBJECT_LIMIT_BREAKAWAY_OK |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 5;

    if (!SetInformationJobObject(job_.get(),
         JobObjectExtendedLimitInformation,
  &limits, sizeof(limits))) {
        return {static_cast<int>(GetLastError()), std::system_category()};
    }

    // UI restrictions: forbid clipboard write, desktop switch, etc.
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui_limits{};
    ui_limits.UIRestrictionsClass =
        JOB_OBJECT_UILIMIT_DESKTOP |
  JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
        JOB_OBJECT_UILIMIT_EXITWINDOWS |
      JOB_OBJECT_UILIMIT_HANDLES |
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

    if (!SetInformationJobObject(job_.get(),
       JobObjectBasicUIRestrictions,
 &ui_limits, sizeof(ui_limits))) {
        return {static_cast<int>(GetLastError()), std::system_category()};
    }

    std::wcout << L"[+] Job Object created with process limit=5, UI restricted\n";
 return {}; // success
}

std::error_code Sandbox::create_restricted_token() {
    HANDLE hToken = nullptr;

// Open current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        return {static_cast<int>(GetLastError()), std::system_category()};
    }
    ScopedHandle current_token(hToken);

    // Create restricted token: drop all privileges
    HANDLE hRestricted = nullptr;
    if (!CreateRestrictedToken(current_token.get(),
      DISABLE_MAX_PRIVILEGE,
  0, nullptr,
         0, nullptr,
               0, nullptr,
     &hRestricted)) {
        return {static_cast<int>(GetLastError()), std::system_category()};
    }
    restricted_token_ = ScopedHandle(hRestricted);

    std::wcout << L"[+] Restricted token created (all privileges disabled)\n";
    return {};
}

std::error_code Sandbox::launch_process(const std::wstring& exe_path,
          const std::wstring& cmdline) {
    // Launch process with restricted token
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    // CreateProcessAsUser requires a mutable cmdline buffer
    std::wstring cmdline_mut = cmdline.empty() ? exe_path : cmdline;

    if (!CreateProcessAsUserW(restricted_token_.get(),
            exe_path.c_str(),
        cmdline_mut.empty() ? nullptr : cmdline_mut.data(),
          nullptr, nullptr,
           FALSE,
         0,
      nullptr, nullptr,
            &si, &pi)) {
    return {static_cast<int>(GetLastError()), std::system_category()};
    }

    ScopedHandle proc(pi.hProcess);
    ScopedHandle thread(pi.hThread);

    // Assign process to the Job
    if (!AssignProcessToJobObject(job_.get(), proc.get())) {
  TerminateProcess(proc.get(), 1);
        return {static_cast<int>(GetLastError()), std::system_category()};
    }

    std::wcout << L"[+] Process launched, PID=" << pi.dwProcessId << L"\n";

    // Wait for process to exit (demo)
    WaitForSingleObject(proc.get(), INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(proc.get(), &exit_code);
    std::wcout << L"[+] Process exited with code=" << exit_code << L"\n";

    return {};
}

std::error_code Sandbox::launch(const std::wstring& exe_path,
         const std::wstring& cmdline) {
    if (auto ec = create_job(); ec) return ec;
    if (auto ec = create_restricted_token(); ec) return ec;
    return launch_process(exe_path, cmdline);
}
