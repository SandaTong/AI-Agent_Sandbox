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
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <fcntl.h>  // _O_U16TEXT
#include <io.h>     // _setmode / _fileno
#include <string>   // std::wstring（jailbreak-4拼 DLL 路径用）

#include "core/pipe_client.h"   // 【M3】target 侧 IPC client
#include "core/self_defense.h"  // 【M5】target 侧运行时自检（反注入检测）

#pragma comment(lib, "ws2_32.lib")

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
        std::wprintf(L"  [jailbreak-5] 读剪贴板         : BLOCKED(gle=%lu, open 失败)\n",
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

// ---- M2 新增两个越狱测试：AppContainer 命名空间/网络---------------------

void Test6_OpenGlobalNamedObject() {
    // AppContainer 有独立的对象命名空间：
    //   \Sessions\<n>\AppContainerNamedObjects\<pkg_sid>\
    // target 尝试打开 global BaseNamedObjects 下的对象会被 LowBox 访问检
    // 查拦下（也可能是 FILE_NOT_FOUND —— 因为它看的是自己私有的一份根本
    // 没这个对象）。M0/ M1 走共享 BaseNamedObjects，理论上能开成功。
    //
    // 但**必须选一个稳定存在的global对象**才有意义。第一版用了
    // "Global\\ShimCacheMutex"——在裸奔进程都返回 FILE_NOT_FOUND，因为
    // Win10/11 上这个名字已经不稳定存在了，测试变成假阳性。
    //
    // 换成 broker 约定：**broker 起 target 前必须先在自己进程里 CreateMutexW
    // 一个名叫 "Global\\WEMEET_SANDBOX_PROBE_MUTEX" 的 mutex 并持有 HANDLE**。
    // 于是：
    //   * baseline / M0 / M1 target：能在共享 \BaseNamedObjects\ 下看到
    //     broker 建的这个 mutex → OpenMutexW SUCCESS
    //   * M2 AppContainer target：走私有 \Sessions\<n>\AppContainer-
    //     NamedObjects\<pkg_sid>\，看不到 broker 的对象 → FILE_NOT_FOUND
    //
    // ⚠️ 如果你直接双击 hello_target.exe（没有 broker）跑，这项会
    // FILE_NOT_FOUND，属于**正常**——因为没人建过那个 mutex。
    static constexpr const wchar_t* kProbeMutex = L"Global\\WEMEET_SANDBOX_PROBE_MUTEX";
    HANDLE h = ::OpenMutexW(SYNCHRONIZE, FALSE, kProbeMutex);
    if (h) {
        ::CloseHandle(h);
        std::wprintf(L"  [jailbreak-6] 打开 global mutex : SUCCESS (沙箱漏了!)\n");
    } else {
        DWORD gle = ::GetLastError();
        const wchar_t* hint = (gle == ERROR_ACCESS_DENIED)    ? L" (AppContainer 命名空间拦下)"
                              : (gle == ERROR_FILE_NOT_FOUND) ? L" (私有命名空间/无 broker 造)"
                                                              : L"";
        std::wprintf(L"  [jailbreak-6] 打开 global mutex : BLOCKED  (gle=%lu)%ls\n", gle, hint);
    }
}

void Test7_TryNetworkConnect() {
    // AppContainer 网络策略【实测校准结论】完全依赖 Windows Firewall 用户
    // 态规则引擎（M2 加餐补丁前 target 网络出方向一路漏，见 docs/notes/
    // M2.md § 九、十一）。加餐补丁后 broker 通过 INetFwPolicy2 COM API 加了
    // 一条针对 Package SID 的 outbound TCP block 规则，此时**公网出方向**
    // 才会真被拦。
    //
    // ⚠️ 关键陷阱：**Windows Firewall 对 loopback (127.0.0.1 / ::1) 流量
    //    有 bypass**——mpssvc 判定引擎不对回环走规则匹配路径。所以我们必
    //    须打**公网 IP** 才能观察到firewall 规则的效果。这里选 8.8.8.8:80
    //    （Google DNS 永远可达的服务器），SYN 会在规则表判定阶段被拒。
    //
    // 判定：
    //   * baseline / M0 / M1：路径通到公网，SYN 出去了，可能连上 (r=0) 或
    //     等超时 (WSAETIMEDOUT)—— 无论哪种都算 SUCCESS
    //   * M2 无 firewall 规则（broker 非管理员或没加）：同上SUCCESS
    //   * M2 有 firewall 规则（管理员+ 加餐补丁生效）：WSAEACCES (10013) BLOCKED ⭐
    //   * M2 --net：broker 跳过加规则，SUCCESS
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::wprintf(L"  [jailbreak-7] TCP 8.8.8.8:80    : BLOCKED  (WSAStartup 失败)\n");
        return;
    }
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        std::wprintf(L"  [jailbreak-7] TCP 8.8.8.8:80    : BLOCKED  (socket() gle=%d)\n",
                     ::WSAGetLastError());
        ::WSACleanup();
        return;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = ::htons(80);
    ::inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    DWORD timeout_ms = 1500;
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                 sizeof(timeout_ms));

    int r = ::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int err = ::WSAGetLastError();
    ::closesocket(s);
    ::WSACleanup();

    // WSAEACCES (10013)     -> firewall 规则拦下(M2 加餐补丁生效)
    // r == 0 / WSAETIMEDOUT -> SYN 发出去了，沙箱没拦
    if (err == WSAEACCES) {
        std::wprintf(
            L"  [jailbreak-7] TCP 8.8.8.8:80    : BLOCKED  (WSAErr=%d, Firewall 规则拦下)\n", err);
    } else if (r == 0 || err == WSAETIMEDOUT) {
        std::wprintf(
            L"  [jailbreak-7] TCP 8.8.8.8:80    : SUCCESS (SYN 出去了，沙箱没拦，WSAErr=%d)\n",
            err);
    } else {
        std::wprintf(L"  [jailbreak-7] TCP 8.8.8.8:80    : ??  (WSAErr=%d 请对照 winerror.h)\n",
                     err);
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

// -----------------------------------------------------------------------------
// 【M3】IPC 客户端演示：target 在沙箱里几乎什么都干不了，通过 IPC 委托 broker
// 代劳。这里演示三步：
//   1. Ping —— 连通性冒烟
//   2. 请 broker 打开白名单目录里的文件 —— 应成功拿到句柄并能读
//   3. 请 broker 打开白名单外的文件 —— 应被 broker 策略拒绝 (kDenied)
//
// 关键看点：即便 target 自己 CreateFileW 打不开的文件（Low IL / AppContainer
// 无权限），只要 broker 有权且策略允许，target 就能通过 IPC + DuplicateHandle
// 拿到一个可用的文件句柄——这就是"broker 代劳"的核心价值。
// -----------------------------------------------------------------------------
void RunIpcClientDemo() {
    using namespace sandbox;
    std::wprintf(L"\n[target] === IPC 客户端演示（M3）===\n");

    PipeClient client;
    if (auto ec = client.Connect(5000)) {
        std::wprintf(L"  [ipc] 连接 broker 失败: gle=%d（若为 5=ACCESS_DENIED 说明未授权本 SID）\n",
                     ec.value());
        std::wprintf(L"[target] === IPC 演示结束（未连上）===\n\n");
        return;
    }
    std::wprintf(L"  [ipc] 已连上 broker 管道\n");

    // 1) Ping
    if (auto ec = client.Ping()) {
        std::wprintf(L"  [ipc] Ping 失败: gle=%d\n", ec.value());
    } else {
        std::wprintf(L"  [ipc] Ping -> Pong OK\n");
    }

    // 2) 请 broker 打开白名单内的文件
    auto try_open = [&client](const wchar_t* path) {
        HANDLE h = nullptr;
        ipc::ResultCode rc = ipc::ResultCode::kInternalError;
        auto ec = client.RequestOpenFile(path, h, rc);
        if (ec) {
            std::wprintf(L"  [ipc] 请求打开 %ls 传输失败: gle=%d\n", path, ec.value());
            return;
        }
        if (rc == ipc::ResultCode::kOk && h) {
            // 拿到 broker DuplicateHandle 过来的句柄，直接读前几个字节验证可用。
            char peek[64] = {};
            DWORD got = 0;
            BOOL ok = ::ReadFile(h, peek, sizeof(peek) - 1, &got, nullptr);
            std::wprintf(L"  [ipc] 打开 %ls -> OK (broker 代劳)，ReadFile %ls，读到 %lu 字节\n",
                         path, ok ? L"成功" : L"失败", got);
            ::CloseHandle(h);
        } else if (rc == ipc::ResultCode::kDenied) {
            std::wprintf(L"  [ipc] 打开 %ls -> BLOCKED（broker 策略拒绝，越权路径）\n", path);
        } else {
            std::wprintf(L"  [ipc] 打开 %ls -> 失败 (result=%u)\n", path,
                         static_cast<unsigned>(rc));
        }
    };

    try_open(L"C:\\sandbox_share\\hello.txt");                // 白名单内：应 OK
    try_open(L"C:\\Windows\\System32\\drivers\\etc\\hosts");  // 白名单外：应 BLOCKED

    std::wprintf(L"[target] === IPC 演示结束 ===\n\n");
}

// -----------------------------------------------------------------------------
// 【M5】运行时自检报告：把 SelfDefense 的发现打印出来。target 是被保护方，
// 这里演示"我自己查我自己有没有被注入 / 被 inline hook"。
//   - 若 broker 开满了反注入 mitigation，M4 那种注入根本进不来 → 自检应"干净"
//   - 若 mitigation 关着（如 M4 场景），注入得手 → 自检应报出可疑 DLL/线程/API 篡改
// 这一对照正是 M5 的核心：内核挡（mitigation）+ 用户态查（本自检）双层。
// -----------------------------------------------------------------------------
void PrintFindings(const wchar_t* phase, const std::vector<sandbox::DefenseFinding>& fs) {
    if (fs.empty()) {
        std::wprintf(L"  [selfcheck] %ls: 干净，未发现异常\n", phase);
        return;
    }
    for (const auto& f : fs) {
        const wchar_t* tag = L"?";
        switch (f.kind) {
            case sandbox::DefenseFinding::Kind::kSuspiciousDll:
                tag = L"可疑DLL";
                break;
            case sandbox::DefenseFinding::Kind::kSuspiciousThread:
                tag = L"可疑线程";
                break;
            case sandbox::DefenseFinding::Kind::kApiTampered:
                tag = L"API被篡改";
                break;
        }
        std::wprintf(L"  [selfcheck][ALERT][%ls] %ls\n", tag, f.detail.c_str());
    }
}

void RunSelfCheckDemo(sandbox::SelfDefense& sd) {
    std::wprintf(L"\n[target] === 运行时自检（M5 反注入检测）===\n");
    // 手段①的异步结果：启动以来 DLL 加载通知累积的告警。
    PrintFindings(L"DLL加载监控", sd.DrainDllFindings());
    // 手段②③：跑一次全量自检（可疑远程线程 + 关键 API 完整性）。
    PrintFindings(L"全量扫描", sd.ScanOnce());
    std::wprintf(L"[target] === 自检结束 ===\n\n");
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    // 解析参数：--ipc 跑 M3 IPC 演示；--selfcheck 跑 M5 运行时自检。
    bool run_ipc = false;
    bool run_selfcheck = false;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--ipc") == 0)
            run_ipc = true;
        else if (wcscmp(argv[i], L"--selfcheck") == 0)
            run_selfcheck = true;
    }

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

    // 【M5】尽早装 DLL 加载监控——越早越能抓到启动后被注入的模块。
    // 放在越狱测试之前，这样若有人在此期间注入 DLL，加载通知能第一时间记下。
    sandbox::SelfDefense self_defense;
    if (run_selfcheck) {
        self_defense.StartDllLoadMonitor();
    }

    std::wprintf(L"\n[target] === 开始越狱测试 ===\n");
    Test1_WriteDesktopFile();
    Test2_SpawnChildProcess();
    Test3_AllocRWXMemory();
    Test4_LoadUnsignedDll();
    Test5_ReadClipboard();
    Test6_OpenGlobalNamedObject();
    Test7_TryNetworkConnect();
    std::wprintf(L"[target] === 越狱测试结束 ===\n\n");

    // 【M3】可选：跑 IPC 客户端演示（委托 broker 代劳打开文件）。
    if (run_ipc) {
        RunIpcClientDemo();
    }

    // 【M5】可选：跑运行时自检（检测启动以来有没有被注入 / 被 inline hook）。
    if (run_selfcheck) {
        RunSelfCheckDemo(self_defense);
    }

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
