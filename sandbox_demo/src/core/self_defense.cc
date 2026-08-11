// -----------------------------------------------------------------------------
// core/self_defense.cc
// -----------------------------------------------------------------------------
#include "core/self_defense.h"

#include <tlhelp32.h>  // CreateToolhelp32Snapshot / Thread32First
#include <winternl.h>  // 一些 NT 结构（部分自定义补齐）

#include <mutex>

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

namespace {

// ---- LdrRegisterDllNotification 相关声明（ntdll 半公开 API，自己补齐原型）----
// 这些结构/原型在公开 SDK 里没有，按微软文档与社区逆向补齐。
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_LOADED_NOTIFICATION_DATA Unloaded;  // 布局相同
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason, const LDR_DLL_NOTIFICATION_DATA* NotificationData, PVOID Context);

typedef NTSTATUS(NTAPI* LdrRegisterDllNotification_t)(ULONG Flags,
                                                      PLDR_DLL_NOTIFICATION_FUNCTION Function,
                                                      PVOID Context, PVOID* Cookie);
typedef NTSTATUS(NTAPI* LdrUnregisterDllNotification_t)(PVOID Cookie);

// ---- 手段① 的共享状态（回调是 C 风格，用文件级静态桥接到实例）----
std::mutex g_dll_mtx;
std::vector<DefenseFinding> g_dll_findings;
LdrUnregisterDllNotification_t g_unregister = nullptr;

// 判断一个模块路径是否在"可信白名单"里。M5 精简策略：系统目录下的 DLL
// （System32/WinSxS）+ 我们自己的 exe 目录视为可信；其余（尤其临时目录、
// 用户目录、UNC）视为可疑。生产上应做签名校验 + 精确清单。
bool IsTrustedModulePath(const std::wstring& path_lower) {
    static const wchar_t* kTrusted[] = {
        L"\\windows\\system32\\",
        L"\\windows\\syswow64\\",
        L"\\windows\\winsxs\\",
        L"\\windows\\systemapps\\",
    };
    for (auto* t : kTrusted) {
        if (path_lower.find(t) != std::wstring::npos)
            return true;
    }
    return false;
}

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(::towlower(c));
    return s;
}

// 手段① 的加载回调：每次有模块被映射进来时被内核加载器调用。
VOID CALLBACK DllNotificationCallback(ULONG reason, const LDR_DLL_NOTIFICATION_DATA* data,
                                      PVOID /*ctx*/) {
    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED || !data)
        return;
    const auto& info = data->Loaded;
    if (!info.FullDllName || !info.FullDllName->Buffer)
        return;

    std::wstring full(info.FullDllName->Buffer, info.FullDllName->Length / sizeof(wchar_t));
    std::wstring lower = ToLower(full);
    if (IsTrustedModulePath(lower))
        return;  // 可信路径，放过

    // 白名单外的模块被加载——记为可疑（这正是 M4 注入 sandbox_hook.dll 的现场）。
    DefenseFinding f{DefenseFinding::Kind::kSuspiciousDll, L"白名单外 DLL 被加载: " + full};
    {
        std::lock_guard<std::mutex> lk(g_dll_mtx);
        g_dll_findings.push_back(f);
    }
    ::OutputDebugStringW((L"[selfcheck][ALERT] " + f.detail + L"\n").c_str());
}

// 枚举本进程所有已加载模块的 [基址, 基址+大小) 区间，用于判断"某地址落在哪个
// 模块里"。返回 true 表示 addr 落在任一已加载模块内（即"有归属"）。
bool AddressInAnyModule(BYTE* addr) {
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                             ::GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE)
        return true;  // 拿不到快照时保守判定"有归属"，避免误报
    bool found = false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (::Module32FirstW(snap, &me)) {
        do {
            BYTE* base = me.modBaseAddr;
            if (addr >= base && addr < base + me.modBaseSize) {
                found = true;
                break;
            }
        } while (::Module32NextW(snap, &me));
    }
    ::CloseHandle(snap);
    return found;
}

}  // namespace

SelfDefense::~SelfDefense() {
    if (dll_monitor_on_ && g_unregister && cookie_) {
        g_unregister(cookie_);
    }
}

bool SelfDefense::StartDllLoadMonitor() {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;
    auto reg = reinterpret_cast<LdrRegisterDllNotification_t>(
        ::GetProcAddress(ntdll, "LdrRegisterDllNotification"));
    g_unregister = reinterpret_cast<LdrUnregisterDllNotification_t>(
        ::GetProcAddress(ntdll, "LdrUnregisterDllNotification"));
    if (!reg) {
        LOG_WARN << L"SelfDefense: 本系统无 LdrRegisterDllNotification，降级为轮询";
        return false;
    }
    NTSTATUS st = reg(0, &DllNotificationCallback, nullptr, &cookie_);
    if (st != 0) {
        LOG_WARN << L"SelfDefense: LdrRegisterDllNotification 失败 status=0x" << std::hex << st;
        return false;
    }
    dll_monitor_on_ = true;
    LOG_INFO << L"SelfDefense: DLL 加载通知已装（白名单外 DLL 加载即告警）";
    return true;
}

std::vector<DefenseFinding> SelfDefense::DrainDllFindings() {
    std::lock_guard<std::mutex> lk(g_dll_mtx);
    std::vector<DefenseFinding> out;
    out.swap(g_dll_findings);
    return out;
}

std::vector<DefenseFinding> SelfDefense::ScanOnce() {
    std::vector<DefenseFinding> findings;

    // ---- 手段②：扫可疑远程线程 ----
    // 枚举本进程线程，取每个线程的起始地址，判断它是否落在某个已加载模块内。
    // 落在模块外（比如 VirtualAllocEx 出来的裸内存）的线程高度可疑。
    // 注：线程起点的入口若是 kernel32!LoadLibraryW，会落在 kernel32 模块内，
    // 单看"是否有归属"抓不到；所以额外把"起点正好等于 LoadLibraryW/LoadLibraryA"
    // 也判为可疑（这正是 M4 CreateRemoteThread 的入口特征）。
    HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
    BYTE* load_library_w =
        k32 ? reinterpret_cast<BYTE*>(::GetProcAddress(k32, "LoadLibraryW")) : nullptr;
    BYTE* load_library_a =
        k32 ? reinterpret_cast<BYTE*>(::GetProcAddress(k32, "LoadLibraryA")) : nullptr;

    HANDLE tsnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (tsnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        DWORD self_pid = ::GetCurrentProcessId();
        if (::Thread32First(tsnap, &te)) {
            do {
                if (te.th32OwnerProcessID != self_pid)
                    continue;
                HANDLE th = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!th)
                    continue;
                // 用 NtQueryInformationThread(ThreadQuerySetWin32StartAddress=9) 取起点。
                using NtQIT_t = NTSTATUS(NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
                static NtQIT_t NtQIT = reinterpret_cast<NtQIT_t>(
                    ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
                BYTE* start = nullptr;
                if (NtQIT) {
                    NtQIT(th, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start),
                          nullptr);
                }
                ::CloseHandle(th);
                if (!start)
                    continue;

                bool suspicious = false;
                std::wstring why;
                if (start == load_library_w || start == load_library_a) {
                    suspicious = true;
                    why = L"起点正好是 LoadLibraryW/A（典型远程线程注入入口）";
                } else if (!AddressInAnyModule(start)) {
                    suspicious = true;
                    why = L"起点不在任何已加载模块内（疑似裸内存 shellcode）";
                }
                if (suspicious) {
                    wchar_t buf[128];
                    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"可疑线程 tid=%lu 起点=0x%p —— %s",
                                 te.th32ThreadID, static_cast<void*>(start), why.c_str());
                    findings.push_back({DefenseFinding::Kind::kSuspiciousThread, buf});
                }
            } while (::Thread32Next(tsnap, &te));
        }
        ::CloseHandle(tsnap);
    }

    // ---- 手段③：关键 API inline-hook 篡改自检 ----
    // 读 kernel32!CreateFileW 头几字节，看是否被改成跳转（inline hook 特征）。
    // 正常的 CreateFileW 开头不会是 jmp；被 M4 那种 hook 改过就会。
    auto check_api = [&](const char* name) {
        if (!k32)
            return;
        BYTE* fn = reinterpret_cast<BYTE*>(::GetProcAddress(k32, name));
        if (!fn)
            return;
        // 常见 inline hook 头字节形态：
        //   E9 xx xx xx xx           → jmp rel32
        //   FF 25 xx xx xx xx        → jmp [rip+disp32]（间接跳）
        //   48 B8 .. (mov rax,imm64) + FF E0 (jmp rax) → 少见但也有
        //   68 xx.. (push+ret) 等
        bool hooked = false;
        std::wstring form;
        if (fn[0] == 0xE9) {
            hooked = true;
            form = L"E9 jmp rel32";
        } else if (fn[0] == 0xFF && fn[1] == 0x25) {
            hooked = true;
            form = L"FF25 jmp [rip+disp]";
        } else if (fn[0] == 0x48 && fn[1] == 0xB8) {
            hooked = true;
            form = L"48B8 mov rax,imm64 (+jmp rax)";
        } else if (fn[0] == 0x68) {
            hooked = true;
            form = L"68 push+ret";
        }
        if (hooked) {
            wchar_t buf[160];
            _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                         L"kernel32!%hs 头字节被改 (%s) —— 疑似被 inline hook", name, form.c_str());
            findings.push_back({DefenseFinding::Kind::kApiTampered, buf});
        }
    };
    check_api("CreateFileW");
    check_api("CreateFileA");

    return findings;
}

}  // namespace sandbox
