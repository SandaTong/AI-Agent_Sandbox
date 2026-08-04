// -----------------------------------------------------------------------------
// demo/hello_target.cc
// -----------------------------------------------------------------------------
// 一个极简的"被沙箱化"目标程序，用于冒烟对比。
//
// 它做的事：
//   - 打印自身 PID、映像路径、完整性等级（Integrity Level 近似值）
//   - 进入心跳循环，每 2 秒打印一个 tick
//   - Ctrl+C 或关闭窗口时干净退出
//
// 特意做成自包含（不依赖 sandbox_core），既可以直接双击运行（基线组），
// 也可以通过 m0_demo 拉起（沙箱组）。输出差异就是沙箱效果的直观证据。
// -----------------------------------------------------------------------------
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>

namespace {

// 查询自身进程的 Integrity Level，返回一个人类可读字符串。失败返回 "?"
// 参考: https://learn.microsoft.com/windows/win32/secauthz/mandatory-integrity-control
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
        // Integrity Level 编码在 SID 最后一个 sub-authority 里。取出对应
        // RID 后按 SECURITY_MANDATORY_*_RID 的范围划一下就能得到等级。
        DWORD rid = *::GetSidSubAuthority(
            buf->Label.Sid, static_cast<DWORD>(*::GetSidSubAuthorityCount(buf->Label.Sid) - 1));
        if (rid < 0x1000)
            result = L"Untrusted";
        else if (rid < 0x2000)
            result = L"Low";
        else if (rid < 0x3000)
            result = L"Medium";
        else if (rid < 0x4000)
            result = L"High";
        else
            result = L"System";
    }
    std::free(buf);
    ::CloseHandle(token);
    return result;
}

BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        std::wprintf(L"[target] 收到 Ctrl 信号，退出\n");
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
    std::wprintf(L"[target] 每 2 秒发一次心跳。按 Ctrl+C 或关闭窗口即可退出。\n");
    std::fflush(stdout);

    int i = 0;
    for (;;) {
        ::Sleep(2000);
        std::wprintf(L"[target] tick %d\n", ++i);
        std::fflush(stdout);
    }
    // 上面是死循环，只能通过 CtrlHandler -> exit(0) 退出，这里不可达。
}
