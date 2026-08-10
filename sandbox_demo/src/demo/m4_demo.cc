// -----------------------------------------------------------------------------
// demo/m4_demo.cc
// -----------------------------------------------------------------------------
// M4 DLL 注入 + API Hook 骨架演示。
//
// 流程：
//   1. launch target（start_suspended=true，target挂起不执行）
//   2. Injector::InjectDll 把 sandbox_hook.dll 注入 target（远程线程 + LoadLibraryW）
//      —— sandbox_hook.dll 在 DllMain 里用 MinHook 钩住 CreateFileW
//   3. ResumeThread —— target 开始执行，此后它调CreateFileW 都会先进我们的钩子
//   4. 等 target 退出
//
// 为什么先挂起再注入再resume：
//   保证 hook 在 target 执行任何用户代码（包括越狱测试的 CreateFileW）之前
//   就装好，这样 jailbreak-1（写桌面文件，内部走 CreateFileW）能被钩子拦到。
//
// 使用:
//   m4_demo.exe [--strict N] [--no-il] <target_exe> [args...]
//   （M4 精简版不叠加 AppContainer——见injector.h 说明：AppContainer +
//    强 mitigation 会拦注入，精简版用普通 Low IL target 演示注入骨架。）
//
// 观察hook 生效的两个通道（sandbox_hook.dll 的日志）：
//   * Sysinternals DebugView：实时看 [hook] CreateFileW 拦截到: <path>
//   * C:\sandbox_share\hook_log.txt：落盘，跑完回看
//
// 期望现象：
//   [+] Injector: 远程线程已起 ... 入口=LoadLibraryW
//   [+] Injector: DLL 注入成功 ...
//   然后 target 正常跑越狱测试；hook_log.txt 里会出现它调CreateFileW 的记录
//   （比如 jailbreak-1 写桌面文件那次的路径）。
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/injector.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"

namespace {

struct CliArgs {
    int strict_level = 4;
    bool use_il = true;
    int target_start = -1;
};

CliArgs ParseArgs(int argc, wchar_t** argv) {
    CliArgs r;
    int i = 1;
    while (i < argc) {
        if (wcscmp(argv[i], L"--strict") == 0 && i + 1 < argc) {
            r.strict_level = _wtoi(argv[i + 1]);
            if (r.strict_level < 0)
                r.strict_level = 0;
            if (r.strict_level > 8)
                r.strict_level = 8;
            i += 2;
        } else if (wcscmp(argv[i], L"--no-il") == 0) {
            r.use_il = false;
            ++i;
        } else {
            r.target_start = i;
            break;
        }
    }
    return r;
}

sandbox::MitigationConfig BuildMitigation(int level) {
    sandbox::MitigationConfig c{};
    c.dep = level >= 1;
    c.aslr_bottom_up = level >= 2;
    c.aslr_force_relocate = level >= 2;
    // ⚠️ M4 注入演示：prohibit_dynamic_code / strict_signed_dll 会拦住我们
    // 注入的 sandbox_hook.dll（它不带微软签名，且 hook 要改可执行内存）。
    // 精简版把这两项关掉，让注入骨架能跑通。这本身是个教学点：**强 mitigation
    // 和"自己注入 hook"是冲突的**——生产上要么 hook dll 签名，要么用别的
    // 预置 hook 机制。
    c.prohibit_dynamic_code = false;
    c.disable_child_process = level >= 4;
    c.image_load_no_remote = false;  // 注入的 DLL 从磁盘加载，别开这个
    c.image_load_no_low_label = false;
    c.strict_signed_dll = false;
    c.disable_extension_points = level >= 8;
    c.disable_win32k = false;
    return c;
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

// 拿到 broker 自己exe 所在目录，用来拼 sandbox_hook.dll 的绝对路径
// （它和各 demo exe 在同一个输出目录）。
std::wstring HookDllPath() {
    wchar_t self[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring p(self);
    size_t slash = p.find_last_of(L'\\');
    std::wstring dir = (slash == std::wstring::npos) ? L"" : p.substr(0, slash + 1);
    return dir + L"sandbox_hook.dll";
}

void PrintUsage() {
    LOG_INFO << L"用法: m4_demo.exe [--strict N] [--no-il] <target_exe> [args...]";
    LOG_INFO << L"      观察 hook: DebugView 或 C:\\sandbox_share\\hook_log.txt";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        PrintUsage();
        return 1;
    }

    using namespace sandbox;

    LOG_INFO << L"M4 配置：strict=" << a.strict_level << L" IL=" << (a.use_il ? L"Low" : L"off");

    // ----------1) Job ----------
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

    // ---------- 3) Mitigation ----------
    MitigationConfig mit_cfg = BuildMitigation(a.strict_level);
    MitigationAttrList attr_list;
    if (auto ec = attr_list.Configure(mit_cfg, /*parent_process*/ nullptr, nullptr)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 4) Launch（挂起，先不resume）----------
    LaunchOptions opts;
    opts.exe_path = argv[a.target_start];
    opts.cmd_line = BuildCmdLine(argc, argv, a.target_start);
    opts.attr_list = &attr_list;
    opts.start_suspended = true;  // ⭐ M4 关键：挂起，注入完再resume

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }
    LOG_INFO << L"ProcessLauncher: pid=" << res.process_id << L"（挂起中，准备注入）";

    // ---------- 5) 注入 sandbox_hook.dll ----------
    std::wstring dll = HookDllPath();
    if (auto ec = Injector::InjectDll(res.process.get(), dll)) {
        LOG_WARN << L"Injector.InjectDll 失败: " << DescribeError(ec).c_str()
                 << L"（target仍会正常运行，只是没装上 hook）";
    }

    // ---------- 6) Resume：target 开始执行，此后 CreateFileW 走我们的钩子 ----------
    if (::ResumeThread(res.main_thread.get()) == static_cast<DWORD>(-1)) {
        LOG_ERROR << L"ResumeThread 失败: " << DescribeError(LastError()).c_str();
        return 1;
    }
    LOG_INFO << L"target 已 Resume；观察 hook 日志: DebugView 或 C:\\sandbox_share\\hook_log.txt";

    // ---------- 7) 等 target 退出 ----------
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(), std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec) {
        LOG_WARN << L"WaitForExit 返回异常: " << DescribeError(ec).c_str();
    } else {
        LOG_INFO << L"Target 退出，exit_code=0x" << std::hex << exit_code << std::dec;
    }
    return 0;
}
