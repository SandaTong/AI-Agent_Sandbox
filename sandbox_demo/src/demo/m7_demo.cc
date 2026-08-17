// -----------------------------------------------------------------------------
// demo/m7_demo.cc
// -----------------------------------------------------------------------------
// M7【形态 A：DNS 域名白名单 Hook】演示。
//
// broker 往 target 注入 dns_hook.dll（复用 M4 注入骨架：挂起→注入→resume），
// dns_hook.dll 在 target 内 hook ws2_32!GetAddrInfoW，按域名白名单放行/拦截：
//   · 白名单内域名 → 正常解析（放行）
//   · 白名单外域名 → 返回 WSAHOST_NOT_FOUND（target 拿不到 IP，连不上）
//
// 白名单通过环境变量 M7_DNS_ALLOWLIST 传给 target（分号分隔，支持 *. 通配）。
// broker 用 SetEnvironmentVariableW 设好，CreateProcessAsUser(lpEnvironment=null)
// 让 target 继承 broker 环境块，注入的 dns_hook.dll 在 target 里读到它。
//
// 【为什么 hook 而非 WFP 拦 :53】域名解析走进程外 dnscache 服务，WFP 在 :53
// 看到的源是 svchost 不是 target，区分不了进程；进程内 hook 才能拿到明文域名 +
// 天然区分进程 + 挡 DoH。详见 docs/notes/M7.md。
//
// 预期（target 的 jailbreak-8 两行）：
//   [8a] 解析 example.com   (白名单内) : SUCCESS（放行）
//   [8b] 解析 www.bing.com  (白名单外) : BLOCKED（WSAHOST_NOT_FOUND）⭐
//
// 用法（Low IL；注入需 broker 对 target 有 VM/线程权限，不叠加 AppContainer）:
//   m7_demo.exe [--allow <domain>]... [--no-il] <target_exe> [args...]
//   不带 --allow 时默认白名单 = {example.com}。
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>
#include <vector>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/injector.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"

namespace {

struct CliArgs {
    std::vector<std::wstring> allow;
    bool use_il = true;
    int target_start = -1;
};

CliArgs ParseArgs(int argc, wchar_t** argv) {
    CliArgs r;
    int i = 1;
    while (i < argc) {
        if (wcscmp(argv[i], L"--allow") == 0 && i + 1 < argc) {
            r.allow.emplace_back(argv[i + 1]);
            i += 2;
        } else if (wcscmp(argv[i], L"--no-il") == 0) {
            r.use_il = false;
            ++i;
        } else {
            r.target_start = i;
            break;
        }
    }
    if (r.allow.empty())
        r.allow.emplace_back(L"example.com");  // 默认白名单
    return r;
}

std::wstring BuildCmdLine(int argc, wchar_t** argv, int target_start) {
    std::wstring out;
    for (int i = target_start; i < argc; ++i) {
        if (!out.empty())
            out.push_back(L' ');
        out.push_back(L'"');
        out.append(argv[i]);
        out.push_back(L'"');
    }
    return out;
}

// dns_hook.dll 和各 demo exe 在同一输出目录。
std::wstring HookDllPath() {
    wchar_t self[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring p(self);
    size_t slash = p.find_last_of(L'\\');
    std::wstring dir = (slash == std::wstring::npos) ? L"" : p.substr(0, slash + 1);
    return dir + L"dns_hook.dll";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        LOG_INFO << L"用法: m7_demo.exe [--allow <domain>]... [--no-il] <target_exe> [args...]";
        return 1;
    }

    using namespace sandbox;

    // 白名单拼成分号分隔串，通过环境变量传给 target（子进程继承 broker 环境块）。
    std::wstring allowlist;
    for (const auto& d : a.allow) {
        if (!allowlist.empty())
            allowlist += L";";
        allowlist += d;
    }
    ::SetEnvironmentVariableW(L"M7_DNS_ALLOWLIST", allowlist.c_str());

    LOG_INFO << L"M7【DNS 域名白名单】配置：IL=" << (a.use_il ? L"Low" : L"off");
    LOG_INFO << L"  域名白名单（放行）: " << allowlist.c_str();

    // ---------- 1) Job ----------
    JobManager job;
    JobPolicy job_policy{};
    if (auto ec = job.Create(job_policy)) {
        LOG_ERROR << L"JobManager.Create 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 2) Token ----------
    TokenManager token;
    if (auto ec = token.CreateRestricted()) {
        LOG_ERROR << L"TokenManager.CreateRestricted 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }
    if (a.use_il) {
        if (auto ec = token.SetIntegrityLevel(IntegrityLevel::kLow)) {
            LOG_ERROR << L"TokenManager.SetIntegrityLevel 失败: " << DescribeError(ec).c_str();
            return ec.value();
        }
    }

    // ---------- 3) Mitigation（注入场景：关掉会拦注入的两位，同 M4）----------
    MitigationConfig mit_cfg{};
    mit_cfg.strict_signed_dll = false;      // 否则拦掉未签名的 dns_hook.dll
    mit_cfg.prohibit_dynamic_code = false;  // 否则拦掉 MinHook 改可执行内存
    MitigationAttrList attr_list;
    if (auto ec = attr_list.Configure(mit_cfg, nullptr, nullptr)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 4) Launch（挂起，注入完再 resume）----------
    LaunchOptions opts;
    opts.exe_path = argv[a.target_start];
    opts.cmd_line = BuildCmdLine(argc, argv, a.target_start);
    opts.attr_list = &attr_list;
    opts.start_suspended = true;  // ⭐ 挂起，保证 hook 在 target 解析域名之前装好

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }
    LOG_INFO << L"ProcessLauncher: pid=" << res.process_id << L"（挂起中，准备注入 dns_hook.dll）";

    // ---------- 5) 注入 dns_hook.dll ----------
    std::wstring dll = HookDllPath();
    if (auto ec = Injector::InjectDll(res.process.get(), dll)) {
        LOG_WARN << L"Injector.InjectDll 失败: " << DescribeError(ec).c_str()
                 << L"（target 仍会运行，只是没装上 DNS hook）";
    } else {
        LOG_INFO << L"Injector: dns_hook.dll 注入成功";
    }

    // ---------- 6) Resume ----------
    if (::ResumeThread(res.main_thread.get()) == static_cast<DWORD>(-1)) {
        LOG_ERROR << L"ResumeThread 失败: " << DescribeError(LastError()).c_str();
        return 1;
    }
    LOG_INFO << L"target 已 Resume；观察 jailbreak-8 两行 + DebugView/%TEMP%\\dns_hook_log.txt";

    // ---------- 7) 等 target 退出 ----------
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(), std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec)
        LOG_WARN << L"WaitForExit 返回异常: " << DescribeError(ec).c_str();
    else
        LOG_INFO << L"Target 退出，exit_code=0x" << std::hex << exit_code << std::dec;
    return 0;
}
