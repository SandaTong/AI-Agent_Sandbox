// -----------------------------------------------------------------------------
// demo/hello_target.cc
// -----------------------------------------------------------------------------
// A trivial target program used to smoke-test the sandbox.
//
// It:
//   - Prints its PID, image path, and integrity level (approximate).
//   - Enters a message loop with a heartbeat every 2 seconds.
//   - Exits cleanly on Ctrl+C or when its window is closed.
//
// We deliberately keep it self-contained (no dependency on sandbox_core) so
// it can be launched either directly (baseline behavior) or via m0_demo
// (sandboxed behavior). The output difference is the whole point.
// -----------------------------------------------------------------------------
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>

namespace {

// Query own integrity level as a human string. Returns empty on failure.
// Docs: https://learn.microsoft.com/windows/win32/secauthz/mandatory-integrity-control
const wchar_t* GetOwnIntegrityLevel() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return L"?";
    }

    DWORD size = 0;
    ::GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
    if (size == 0) {
        ::CloseHandle(token);
        return L"?";
    }

    auto* buf = static_cast<TOKEN_MANDATORY_LABEL*>(std::malloc(size));
    if (!buf) {
        ::CloseHandle(token);
        return L"?";
    }

    const wchar_t* result = L"?";
    if (::GetTokenInformation(token, TokenIntegrityLevel, buf, size, &size)) {
        // RID at the *last* sub-authority of the label SID identifies the IL.
        DWORD rid = *::GetSidSubAuthority(
            buf->Label.Sid,
            static_cast<DWORD>(*::GetSidSubAuthorityCount(buf->Label.Sid) - 1));
        if (rid < 0x1000)result = L"Untrusted";
        else if (rid < 0x2000)  result = L"Low";
        else if (rid < 0x3000)  result = L"Medium";
        else if (rid < 0x4000)  result = L"High";
        else                    result = L"System";
    }
    std::free(buf);
    ::CloseHandle(token);
    return result;
}

BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT) {
        std::wprintf(L"[target] caught ctrl signal, exiting\n");
        std::exit(0);
    }
    return FALSE;
}

}  // namespace

int wmain() {
    ::SetConsoleCtrlHandler(CtrlHandler, TRUE);

    wchar_t exe_path[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    std::wprintf(L"[target] hello!\n");
    std::wprintf(L"[target] pid=%lu\n", ::GetCurrentProcessId());
    std::wprintf(L"[target] image=%ls\n", exe_path);
    std::wprintf(L"[target] integrity_level=%ls\n", GetOwnIntegrityLevel());
    std::wprintf(L"[target] I will heartbeat every 2s. Press Ctrl+C or close"
                 L" this window to exit.\n");
    std::fflush(stdout);

    int i = 0;
    for (;;) {
        ::Sleep(2000);
        std::wprintf(L"[target] tick %d\n", ++i);
        std::fflush(stdout);
    }
    // Unreachable — infinite loop above only exits via CtrlHandler -> exit(0).
}
