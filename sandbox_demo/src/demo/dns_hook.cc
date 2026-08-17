// -----------------------------------------------------------------------------
// demo/dns_hook.cc  ->  编译产物 dns_hook.dll
// -----------------------------------------------------------------------------
// M7【形态 A：DNS 域名白名单 Hook】被 broker 注入进 target 的"域名管控垫片"DLL。
//
// 【M7 要解决什么——网络管控从 IP 维度升到域名维度】
//   M6 的 WFP 只能按 IP 拦（内核网络栈看不到域名——域名早在 DNS 解析阶段就变
//   成 IP 了）。但 agent 场景我们想说的是"只准连 api.openai.com，别的域名一律
//   拒"。域名管控必须在 **DNS 解析这一环** 动手。
//
// 【为什么用 API Hook 而不是 WFP 拦 :53】
//   getaddrinfo/GetAddrInfoW 这类解析 API 在进程内是薄壳，真正解析甩给进程外的
//   DNS Client 服务(dnscache/svchost)。所以 WFP 在 :53 报文上看到的源进程是
//   svchost 而非 target，按进程根本区分不出"是哪个 agent 要解析"。而在 target
//   进程内 hook 解析 API，能**直接拿到明文域名**、天然区分进程、还挡得住 DoH
//   （DoH 也要先调 GetAddrInfoW 拿 hostname）。这是域名管控的正确抽象层。
//   （完整三方案对比见 docs/notes/M7.md）
//
// 【复用 M4 骨架】注入机制（远程线程 + LoadLibraryW）、日志双通道
//   （OutputDebugStringW + %TEMP% 落盘）、DllMain 里 MinHook 装钩，全部沿用
//   M4 sandbox_hook.dll 的做法，M7 只是把 hook 目标从 kernel32!CreateFileW
//   换成 ws2_32!GetAddrInfoW（域名解析），逻辑同源。
//
// 【白名单怎么传进来】通过环境变量 M7_DNS_ALLOWLIST（分号分隔，支持 *. 通配），
//   broker 起 target 前设好，子进程继承，DLL 在 DllMain 里读一次。命中白名单
//   放行（调原函数），未命中返回 WSAHOST_NOT_FOUND（相当于"该域名不存在"）。
// -----------------------------------------------------------------------------
#include <winsock2.h>  // 必须在 windows.h 之前
#include <ws2tcpip.h>

#include <windows.h>

#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#include "MinHook.h"

#pragma comment(lib, "user32.lib")

namespace {

// ---- 原函数指针类型（GetAddrInfoW：现代域名解析主入口）----
using GetAddrInfoW_t = INT(WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
GetAddrInfoW_t g_orig_GetAddrInfoW = nullptr;

// 域名白名单（小写，DllMain 里从环境变量解析一次）。
std::vector<std::wstring> g_allowlist;

wchar_t g_log_path[MAX_PATH] = {};

// ---- 日志：OutputDebugStringW + %TEMP% 落盘（复用 M4 模式，钩子内最稳）----
void ResolveLogPath() {
    wchar_t tmp[MAX_PATH] = {};
    DWORD n = ::GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n > MAX_PATH) {
        lstrcpynW(g_log_path, L"dns_hook_log.txt", MAX_PATH);
        return;
    }
    _snwprintf_s(g_log_path, MAX_PATH, _TRUNCATE, L"%sdns_hook_log.txt", tmp);
}

void HookLog(const wchar_t* line) {
    ::OutputDebugStringW(line);
    // 落盘走原始 CreateFileW（这里不 hook CreateFileW，直接用系统的即可）。
    HANDLE h = ::CreateFileW(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char utf8[1600];
        int n = ::WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, sizeof(utf8), nullptr, nullptr);
        if (n > 1) {
            DWORD wrote = 0;
            ::SetFilePointer(h, 0, nullptr, FILE_END);
            ::WriteFile(h, utf8, static_cast<DWORD>(n - 1), &wrote, nullptr);
        }
        ::CloseHandle(h);
    }
}

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(::towlower(c));
    return s;
}

// 解析环境变量 M7_DNS_ALLOWLIST（分号分隔）成小写域名列表。
void LoadAllowlist() {
    wchar_t buf[2048] = {};
    DWORD n = ::GetEnvironmentVariableW(L"M7_DNS_ALLOWLIST", buf, _countof(buf));
    if (n == 0 || n >= _countof(buf))
        return;
    std::wstring s(buf);
    size_t start = 0;
    while (start < s.size()) {
        size_t sep = s.find(L';', start);
        if (sep == std::wstring::npos)
            sep = s.size();
        std::wstring item = s.substr(start, sep - start);
        // 去首尾空白
        while (!item.empty() && (item.front() == L' ' || item.front() == L'\t'))
            item.erase(item.begin());
        while (!item.empty() && (item.back() == L' ' || item.back() == L'\t'))
            item.pop_back();
        if (!item.empty())
            g_allowlist.push_back(ToLower(item));
        start = sep + 1;
    }
}

// host 是否匹配白名单里的某一项。支持三种：
//   · 完全相等：api.openai.com == api.openai.com
//   · 通配 *.example.com：匹配 a.example.com / a.b.example.com，也匹配 example.com 本身
//   · 裸域 example.com：同时匹配其子域（等价隐式 *.example.com + 自身）
bool IsAllowed(const std::wstring& host_in) {
    std::wstring host = ToLower(host_in);
    for (const auto& rule : g_allowlist) {
        std::wstring base = rule;
        if (base.rfind(L"*.", 0) == 0)  // 以 "*." 开头 → 取后半
            base = base.substr(2);
        if (host == base)
            return true;
        // host 以 ".base" 结尾 → 是 base 的子域
        if (host.size() > base.size() + 1 &&
            host.compare(host.size() - base.size() - 1, base.size() + 1, L"." + base) == 0)
            return true;
    }
    return false;
}

// ---- 钩子：target 每次域名解析先进这里 ----
INT WSAAPI HookedGetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints,
                              PADDRINFOW* result) {
    if (node && node[0]) {
        std::wstring host(node);
        if (IsAllowed(host)) {
            wchar_t l[512];
            _snwprintf_s(l, _countof(l), _TRUNCATE, L"[dns] 放行(白名单内): %s\n", node);
            HookLog(l);
            return g_orig_GetAddrInfoW(node, service, hints, result);
        }
        // 白名单外：拒绝解析，返回"域名不存在"。target 拿不到 IP → 连不上。
        wchar_t l[512];
        _snwprintf_s(l, _countof(l), _TRUNCATE, L"[dns] 拦截(白名单外): %s -> WSAHOST_NOT_FOUND\n",
                     node);
        HookLog(l);
        if (result)
            *result = nullptr;
        ::WSASetLastError(WSAHOST_NOT_FOUND);
        return WSAHOST_NOT_FOUND;  // EAI 错误码：11001
    }
    // 无 node（如仅按 service 查）——放行。
    return g_orig_GetAddrInfoW(node, service, hints, result);
}

bool InstallHooks() {
    ResolveLogPath();
    LoadAllowlist();
    ::OutputDebugStringW(L"[dns] DllMain attach，开始装 DNS hook\n");

    {
        wchar_t l[1024];
        std::wstring names;
        for (const auto& d : g_allowlist) {
            if (!names.empty())
                names += L", ";
            names += d;
        }
        _snwprintf_s(l, _countof(l), _TRUNCATE,
                     L"[dns] dns_hook.dll 已注入。白名单[%zu]: %s（日志: %s）\n", g_allowlist.size(),
                     names.empty() ? L"(空=全部拦截)" : names.c_str(), g_log_path);
        HookLog(l);
    }

    MH_STATUS s_init = MH_Initialize();
    if (s_init != MH_OK && s_init != MH_ERROR_ALREADY_INITIALIZED) {
        ::OutputDebugStringW(L"[dns] MH_Initialize 失败\n");
        return false;
    }
    // hook ws2_32!GetAddrInfoW —— getaddrinfo / Python socket / Node dns 最终都
    // 落到它。ws2_32.dll 在进程里已加载（target 用 winsock）。
    if (MH_CreateHookApi(L"ws2_32", "GetAddrInfoW", &HookedGetAddrInfoW,
                         reinterpret_cast<LPVOID*>(&g_orig_GetAddrInfoW)) != MH_OK) {
        ::OutputDebugStringW(L"[dns] MH_CreateHookApi(GetAddrInfoW) 失败\n");
        return false;
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        ::OutputDebugStringW(L"[dns] MH_EnableHook 失败\n");
        return false;
    }
    return true;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID /*reserved*/) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            ::DisableThreadLibraryCalls(module);
            InstallHooks();
            break;
        case DLL_PROCESS_DETACH:
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            break;
        default:
            break;
    }
    return TRUE;
}
