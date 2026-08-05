// -----------------------------------------------------------------------------
// demo/hello_target.cc
// -----------------------------------------------------------------------------
// 一个"被沙箱化"的目标程序，用来对比基线 vs 沙箱下的行为差异。
//
// 启动时先做**5 个越狱测试**，每一项都对应一层 M0/M1 的护栏。基线运行（直
// 接双击）时几乎全成功；M1 沙箱运行时应该全部被拦下。之后进入心跳循环。
//
//   测试 1：写用户桌面文件   → 拦的层：Low IL 的 NTFS mandatory label
//   测试 2：起子进程 cmd.exe  → 拦的层：Mitigation Policy CHILD_PROCESS_RESTRICTED
//   测试 3：申请 RWX 内存     → 拦的层：Mitigation Policy PROHIBIT_DYNAMIC_CODE
//   测试 4：加载非签名 DLL     → 拦的层：Mitigation Policy BLOCK_NON_MICROSOFT
//   测试 5：读剪贴板→ 拦的层：Job UI 限制 READCLIPBOARD
// -----------------------------------------------------------------------------
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <fcntl.h>  // _O_U16TEXT
#include <io.h>     // _setmode / _fileno
#include <string>   // std::wstring（jailbreak-4 拼 DLL 路径用）

namespace {

// -----------------------------------------------------------------------------
// 查询自身进程的 Integrity Level，返回一个人类可读字符串。
// 参考: https://learn.microsoft.com/windows/win32/secauthz/mandatory-integrity-control
// -----------------------------------------------------------------------------
const wchar_t* GetOwnIntegrityLevel() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        return L"?";

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

// -----------------------------------------------------------------------------
// 越狱测试：统一走一个 lambda，成功/失败都打印，方便对比。
// -----------------------------------------------------------------------------
void Test1_WriteDesktopFile() {
    wchar_t path[MAX_PATH] = {};
    ::ExpandEnvironmentStringsW(L"%USERPROFILE%\\Desktop\\sandbox_jailbreak.txt", path, MAX_PATH);
    HANDLE h = ::CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                             nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        ::CloseHandle(h);
        ::DeleteFileW(path);
        std::wprintf(L"  [jailbreak-1] 写用户桌面文件 : SUCCESS (沙箱漏了!)\n");
    } else {
        std::wprintf(L"  [jailbreak-1] 写用户桌面文件 : BLOCKED  (gle=%lu)\n", ::GetLastError());
    }
}

void Test2_SpawnChildProcess() {
    wchar_t cmd[] = L"cmd.exe /c exit 0";  // 命令行 buffer 必须可写
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (::CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                         &si, &pi)) {
        ::TerminateProcess(pi.hProcess, 0);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
        std::wprintf(L"  [jailbreak-2] 起子进程 cmd.exe : SUCCESS (沙箱漏了!)\n");
    } else {
        std::wprintf(L"  [jailbreak-2] 起子进程 cmd.exe : BLOCKED  (gle=%lu)\n", ::GetLastError());
    }
}

void Test3_AllocRWXMemory() {
    // PROHIBIT_DYNAMIC_CODE 会拒绝 W+X 组合的 VirtualAlloc。
    void* p = ::VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (p) {
        ::VirtualFree(p, 0, MEM_RELEASE);
        std::wprintf(L"  [jailbreak-3] 分配 RWX 内存: SUCCESS (沙箱漏了!)\n");
    } else {
        std::wprintf(L"  [jailbreak-3] 分配 RWX 内存: BLOCKED  (gle=%lu)\n", ::GetLastError());
    }
}

void Test4_LoadUnsignedDll() {
    // 加载我们同目录下自编译的 unsigned_probe.dll —— 未签名 DLL。
    //
    // 之所以不用 LoadLibraryW(self_exe_path)：加载"自己的主映像"时Windows
    // 会走快速路径（因为 CreateProcess 时已经把它映射进了地址空间），绕过
    // 部分完整性校验，导致基线组也会显示 SUCCESS，无法凸显 M1 拦截点。
    //
    // 用一个独立编译的真 DLL 才能干净观察差异：
    //   基线 / M0：加载成功，LoadLibraryW 返回非空 HMODULE
    //   M1（BLOCK_NON_MICROSOFT_BINARIES）：返回 nullptr，
    //     GetLastError() == 577 (ERROR_INVALID_IMAGE_HASH)
    //     —— 内核在做微软根证书校验那一步把它拒了

    // 拼出 exe 同目录下的 unsigned_probe.dll 全路径
    wchar_t exe_path[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    wchar_t* last_slash = ::wcsrchr(exe_path, L'\\');
    if (last_slash) {
        *(last_slash + 1) = L'\0';
    }
    std::wstring dll_path = std::wstring(exe_path) + L"unsigned_probe.dll";

    HMODULE h = ::LoadLibraryW(dll_path.c_str());
    if (h) {
        ::FreeLibrary(h);
        std::wprintf(L"  [jailbreak-4] 加载非签名 DLL   : SUCCESS (沙箱漏了!)\n");
    } else {
        DWORD gle = ::GetLastError();
        const wchar_t* hint = (gle == 577)   ? L" (INVALID_IMAGE_HASH，M1 生效)"
                              : (gle == 126) ? L" (MODULE_NOT_FOUND，unsigned_probe.dll 缺失)"
                                             : L"";
        std::wprintf(L"  [jailbreak-4] 加载非签名 DLL   : BLOCKED  (gle=%lu)%ls\n", gle, hint);
    }
}

void Test5_ReadClipboard() {
    // Job UI Limit 里 JOB_OBJECT_UILIMIT_READCLIPBOARD 拦的是 GetClipboardData，
    // 不是 OpenClipboard。所以完整测试要走"打开 -> 尝试读 -> 关闭"三步，看
    // 读操作那一步是否被拦。
    if (!::OpenClipboard(nullptr)) {
        // 有些沙箱直接连 OpenClipboard 都拦（AppContainer 会这样），这里
        // 视作"更严"级别的 BLOCKED。
        std::wprintf(L"  [jailbreak-5] 读剪贴板         : BLOCKED  (gle=%lu, open 失败)\n",
                     ::GetLastError());
        return;
    }
    HANDLE h = ::GetClipboardData(CF_UNICODETEXT);
    DWORD gle = ::GetLastError();
    ::CloseClipboard();
    if (h != nullptr) {
        std::wprintf(L"  [jailbreak-5] 读剪贴板         : SUCCESS (沙箱漏了!)\n");
    } else {
        // 剪贴板可能只是没数据，也可能被 UILIMIT_READCLIPBOARD 拦。
        // ERROR_ACCESS_DENIED (5) 或 ERROR_CLIPBOARD_NOT_OPEN 之类才是真拦；
        // gle==0 通常表示"没数据"不算拦。区分一下。
        const wchar_t* hint = (gle == ERROR_ACCESS_DENIED) ? L" (真被Job UI Limit 拦下)"
                              : (gle == 0)                 ? L" (剪贴板可能就是空的，非拦截)"
                                                           : L"";
        std::wprintf(L"  [jailbreak-5] 读剪贴板         : BLOCKED  (gle=%lu)%ls\n", gle, hint);
    }
}

// -----------------------------------------------------------------------------
BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        std::wprintf(L"[target] 收到 Ctrl 信号，退出\n");
        std::exit(0);
    }
    return FALSE;
}

}  // namespace

int wmain() {
    // ---- stdio初始化 ----
    // 只有当 stdout 真的是"控制台屏幕缓冲区"（file type == FILE_TYPE_CHAR
    // 且 GetConsoleMode 成功）时，才把它切到 _O_U16TEXT。否则跳过：
    //   * M1 target 住在 alternate winstation里，broker 传下来的 console
    //     句柄可能已经不在同一个 winsta 里，_setmode 尝试查询/校验时会失败
    //     甚至导致进程立刻挂（现象：0xC0000142 STATUS_DLL_INIT_FAILED，
    //     实际是 CRT 初始化 wprintf 通道时崩）。
    //   * 后台/无 console 启动时 stdout 是无效句柄，切模式没意义。
    //
    // 安全策略：只在真console 场景切；不是console 就让 wprintf 走默认
    // narrow 路径，这时中文会打不出但至少 target 能跑（M1 时我们更关注
    // "target 存活+执行越狱测试"而不是"输出好看"）。
    auto try_widen = [](FILE* stream) {
        int fd = _fileno(stream);
        HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
        if (h == INVALID_HANDLE_VALUE || h == nullptr)
            return;
        DWORD mode = 0;
        if (::GetConsoleMode(h, &mode)) {
            (void)_setmode(fd, _O_U16TEXT);
        }
    };
    try_widen(stdout);
    try_widen(stderr);

    ::SetConsoleCtrlHandler(CtrlHandler, TRUE);

    wchar_t exe_path[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    std::wprintf(L"[target] hello!\n");
    std::wprintf(L"[target] pid=%lu\n", ::GetCurrentProcessId());
    std::wprintf(L"[target] image=%ls\n", exe_path);
    std::wprintf(L"[target] integrity_level=%ls\n", GetOwnIntegrityLevel());

    std::wprintf(L"\n[target] === 开始越狱测试 ===\n");
    Test1_WriteDesktopFile();
    Test2_SpawnChildProcess();
    Test3_AllocRWXMemory();
    Test4_LoadUnsignedDll();
    Test5_ReadClipboard();
    std::wprintf(L"[target] === 越狱测试结束 ===\n\n");

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
