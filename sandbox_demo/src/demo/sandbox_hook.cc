// -----------------------------------------------------------------------------
// demo/sandbox_hook.cc  ->  编译产物sandbox_hook.dll
// -----------------------------------------------------------------------------
// M4：被 broker 注入进 target 的"拦截垫片"DLL。
//
// 职责：进程加载本 DLL 时（DllMain 的 DLL_PROCESS_ATTACH），用 MinHook 把
// kernel32!CreateFileW 钩住。之后 target 每次调 CreateFileW，都会先进我们的
// HookedCreateFileW —— 打印/记录被访问的路径，再调用原函数放行（M4 精简版
// 只观察不拦截；后续可在这里接M3 IPC 做策略检查 / broker 代劳）。
//
// 【为什么钩子里的日志走 OutputDebugStringW + 写文件，而不是 wprintf】
//   本 DLL 运行在 **target 进程上下文**里。target 的 stdout 可能被切到
//   _O_U16TEXT、可能在 alt desktop、也可能根本没console。在 hook 回调里直接
//   wprintf 既不可靠也可能重入。所以用两条稳的输出通道：
//     1. OutputDebugStringW —— 用 Sysinternals DebugView 实时看
//     2. 追加写C:\sandbox_share\hook_log.txt —— 落盘，跑完回看
//   （C:\sandbox_share 是 M3 已经建好的白名单目录，复用它。）
//
// 【DllMain 里做 MinHook 安全吗】
//   DllMain 的 loader lock 下**禁止**再 LoadLibrary / 起线程做重活。MinHook
//   的 MH_Initialize/MH_CreateHook/MH_EnableHook 只做内存分配 + 改目标函数
//   头几字节 + VirtualProtect，不触发 LoadLibrary，实践中在 attach 里直接调
//   是安全的（大量注入型工具都这么用）。若要更保险可另起线程延迟 hook，M4
//   精简版直接在 attach 里做。
// -----------------------------------------------------------------------------
#include <windows.h>

#include <cstdio>
#include <cstdlib>

#include "MinHook.h"

#pragma comment(lib, "user32.lib")

namespace {

// 原始 CreateFileW 的函数指针类型。
using CreateFileW_t = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                      HANDLE);

// MinHook 回填的"跳过 hook 直接调原函数"的 trampoline 指针。
CreateFileW_t g_orig_CreateFileW = nullptr;

// 日志文件路径（DllMain 里解析一次）。默认放%TEMP%——因为注入的 target 可能
// 是 Low IL 进程，它对 C:\sandbox_share 这类 Medium IL 目录没有写权限（会被
// 文件系统 mandatory label 拒，这正是 M1 Low IL 的效果）。而每个进程对自己的
// %TEMP% 一定有写权限（Low IL 进程的 TEMP 会指向 ...\AppData\Local\Temp\Low）。
// ⭐ 教学点：注入的 hook 垫片**继承 target 的权限，不会提权**——钩子逻辑在
// target 内存里不受 IL 限制，但钩子里做的 IO 仍受 target 自身沙箱权限约束。
wchar_t g_log_path[MAX_PATH] = {};

void ResolveLogPath() {
    wchar_t tmp[MAX_PATH] = {};
    DWORD n = ::GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n > MAX_PATH) {
        // 兜底：拿不到 TEMP 就用当前目录。
        lstrcpynW(g_log_path, L"sandbox_hook_log.txt", MAX_PATH);
        return;
    }
    _snwprintf_s(g_log_path, MAX_PATH, _TRUNCATE, L"%ssandbox_hook_log.txt", tmp);
}

// 简单的日志：OutputDebugStringW + 追加写文件。两条通道都不依赖 target 的
// stdout 状态，在 hook 回调里最稳。
void HookLog(const wchar_t* fmt, const wchar_t* arg) {
    wchar_t line[1200];
    _snwprintf_s(line, _countof(line), _TRUNCATE, fmt, arg);

    // 通道 1：调试器 / DebugView
    ::OutputDebugStringW(line);

    // 通道 2：追加写日志文件（注意：这里必须用**原始** CreateFileW，否则会
    // 递归触发自己的 hook 造成无限递归！所以走 g_orig_CreateFileW。）
    if (g_orig_CreateFileW && g_log_path[0]) {
        HANDLE h =
            g_orig_CreateFileW(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            // 转成 UTF-8 写盘，避免宽字节BOM 麻烦。
            char utf8[1600];
            int n =
                ::WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, sizeof(utf8), nullptr, nullptr);
            if (n > 1) {
                DWORD wrote = 0;
                ::SetFilePointer(h, 0, nullptr, FILE_END);
                ::WriteFile(h, utf8, static_cast<DWORD>(n - 1), &wrote, nullptr);
            }
            ::CloseHandle(h);
        }
    }
}

// 我们的钩子：target 调 CreateFileW 会先进这里。
HANDLE WINAPI HookedCreateFileW(LPCWSTR file_name, DWORD access, DWORD share,
                                LPSECURITY_ATTRIBUTES sa, DWORD disposition, DWORD flags,
                                HANDLE tmpl) {
    // 记录被访问的路径。M4 精简版只观察不拦截。
    HookLog(L"[hook] CreateFileW 拦截到: %s\n", file_name ? file_name : L"(null)");

    // 放行：调用原始函数，行为对 target 完全透明。
    return g_orig_CreateFileW(file_name, access, share, sa, disposition, flags, tmpl);
}

// 在 attach 时装 hook。
bool InstallHooks() {
    ResolveLogPath();  // 先确定日志文件路径（%TEMP%\sandbox_hook_log.txt）
    ::OutputDebugStringW(L"[hook] DllMain attach，开始装 hook\n");

    MH_STATUS s_init = MH_Initialize();
    if (s_init != MH_OK && s_init != MH_ERROR_ALREADY_INITIALIZED) {
        ::OutputDebugStringW(L"[hook] MH_Initialize 失败\n");
        return false;
    }

    // 直接对 kernel32!CreateFileW 下钩；MH_CreateHookApi 按模块名+函数名定位。
    if (MH_CreateHookApi(L"kernel32", "CreateFileW", &HookedCreateFileW,
                         reinterpret_cast<LPVOID*>(&g_orig_CreateFileW)) != MH_OK) {
        ::OutputDebugStringW(L"[hook] MH_CreateHookApi(CreateFileW) 失败\n");
        return false;
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        ::OutputDebugStringW(L"[hook] MH_EnableHook 失败\n");
        return false;
    }

    // 第一条日志：宣告 hook 装好了（同时会创建/打开日志文件）。
    HookLog(L"[hook] sandbox_hook.dll 已注入并 Hook 住 CreateFileW（日志: %s）\n", g_log_path);
    return true;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            ::DisableThreadLibraryCalls(module);  // 不关心线程 attach/detach
            InstallHooks();
            break;
        case DLL_PROCESS_DETACH:
            // 卸载时清理 hook（进程退出时其实无所谓，但规范起见）。
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            break;
        default:
            break;
    }
    return TRUE;
}
