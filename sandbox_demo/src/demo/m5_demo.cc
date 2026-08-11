// -----------------------------------------------------------------------------
// demo/m5_demo.cc
// -----------------------------------------------------------------------------
// M5 反注入 + 运行时检测演示（M4 的攻防翻转版）。
//
// M4：broker 关掉反注入 mitigation，主动注入 target 得手（演示"攻"）。
// M5：broker 开满反注入 mitigation，再用同一套 injector 去打，观察注入
//     被内核挡在哪一步（演示"守"）；同时 target 自己跑运行时自检（--selfcheck）
//     确认"没被注入 / 没被 inline hook"。两层防御：内核挡 + 用户态查。
//
// 三种运行模式（对照实验）：
//   1) 纯防御（默认）：开满反注入 mitigation，不主动注入。
//      target --selfcheck 自检应"干净"。看基线。
//   2) 防御 + 攻击（--attack）：开满 mitigation，然后用 injector 尝试注入
//      sandbox_hook.dll。⭐ 预期注入失败——被 mitigation 挡下（观察日志里
//      Injector 在哪一步失败：LoadLibraryW 返回 NULL = BLOCK_NON_MICROSOFT
//      拦了加载；或改内存被 PROHIBIT_DYNAMIC_CODE 拦）。target 自检仍干净。
//   3) 关防御 + 攻击（--defense-off --attack）：复现 M4 —— mitigation 关掉，
//      注入得手，⭐ 这时 target 自检应报警（可疑 DLL / 可疑线程 / API 被篡改），
//      证明"内核没挡住时，用户态检测层能兜底发现"。
//
// 用法:
//   m5_demo.exe [--defense-off] [--attack] [--no-il] <target_exe> [args...]
//   （建议 target 带 --selfcheck 让它自检并打印结果。）
//
// 观察点：
//   * broker 侧 Injector 日志：注入成功 vs 被挡（哪一步失败）
//   * target 侧 [selfcheck] 行：干净 vs 报警
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
    bool defense_off = false;  // 关掉反注入 mitigation（复现 M4 场景做对照）
    bool attack = false;       // 是否用 injector 主动注入 target
    bool use_il = true;
    int target_start = -1;
};

CliArgs ParseArgs(int argc, wchar_t** argv) {
    CliArgs r;
    int i = 1;
    while (i < argc) {
        if (wcscmp(argv[i], L"--defense-off") == 0) {
            r.defense_off = true;
            ++i;
        } else if (wcscmp(argv[i], L"--attack") == 0) {
            r.attack = true;
            ++i;
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

// M5 的 mitigation 配置：默认**开满反注入三件套**（这是与 M4 的核心区别）。
//   prohibit_dynamic_code   —— 禁改可执行内存：拦 inline hook 改 API 头字节
//   strict_signed_dll       —— 只许微软签名 DLL：拦加载未签名的注入 dll
//   disable_extension_points—— 禁 AppInit/全局钩子：拦老式 SetWindowsHookEx 注入
// defense_off=true 时全关，复现 M4"注入得手"的对照组。
sandbox::MitigationConfig BuildMitigation(bool defense_off) {
    sandbox::MitigationConfig c{};
    c.dep = true;
    c.aslr_bottom_up = true;
    c.aslr_force_relocate = true;
    c.disable_child_process = true;
    c.image_load_no_remote = false;  // 注入的 dll 从本地磁盘加载，别开这个免误伤
    c.image_load_no_low_label = false;
    c.disable_win32k = false;

    if (defense_off) {
        // 对照组：关掉反注入护栏（等价 M4 场景）。
        c.prohibit_dynamic_code = false;
        c.strict_signed_dll = false;
        c.disable_extension_points = false;
    } else {
        // ⭐ M5 主场景：开满反注入三件套。
        c.prohibit_dynamic_code = true;
        c.strict_signed_dll = true;
        c.disable_extension_points = true;
    }
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

std::wstring HookDllPath() {
    wchar_t self[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring p(self);
    size_t slash = p.find_last_of(L'\\');
    std::wstring dir = (slash == std::wstring::npos) ? L"" : p.substr(0, slash + 1);
    return dir + L"sandbox_hook.dll";
}

void PrintUsage() {
    LOG_INFO << L"用法: m5_demo.exe [--defense-off] [--attack] [--no-il] <target_exe> [args...]";
    LOG_INFO << L"      建议 target 带 --selfcheck。--attack 用 injector 打 target。";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        PrintUsage();
        return 1;
    }

    using namespace sandbox;

    LOG_INFO << L"M5 配置：反注入防御=" << (a.defense_off ? L"OFF(对照/复现M4)" : L"ON(全开)")
             << L" 主动攻击=" << (a.attack ? L"是" : L"否") << L" IL="
             << (a.use_il ? L"Low" : L"off");

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

    // ---------- 3) Mitigation（M5 核心：默认开满反注入）----------
    MitigationConfig mit_cfg = BuildMitigation(a.defense_off);
    MitigationAttrList attr_list;
    if (auto ec = attr_list.Configure(mit_cfg, /*parent_process*/ nullptr, nullptr)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }
    LOG_INFO << L"反注入护栏: prohibit_dynamic_code=" << mit_cfg.prohibit_dynamic_code
             << L" strict_signed_dll=" << mit_cfg.strict_signed_dll << L" disable_extension_points="
             << mit_cfg.disable_extension_points;

    // ---------- 4) Launch（挂起，以便攻击场景在 resume 前注入）----------
    LaunchOptions opts;
    opts.exe_path = argv[a.target_start];
    opts.cmd_line = BuildCmdLine(argc, argv, a.target_start);
    opts.attr_list = &attr_list;
    opts.start_suspended = true;

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }
    LOG_INFO << L"ProcessLauncher: pid=" << res.process_id << L"（挂起中）";

    // ---------- 5) 攻击（可选）：用 M4 的 injector 尝试注入 ----------
    if (a.attack) {
        std::wstring dll = HookDllPath();
        LOG_INFO << L"【攻击】用 injector 尝试注入 " << dll.c_str() << L" ……";
        if (auto ec = Injector::InjectDll(res.process.get(), dll)) {
            // ⭐ M5 主场景预期走到这里：注入被反注入 mitigation 挡下。
            LOG_INFO << L"【攻击被挡】注入失败: " << DescribeError(ec).c_str()
                     << L" —— 反注入 mitigation 生效（若 defense=ON）。这是预期结果。";
        } else {
            // 只有 defense-off（复现 M4）才应走到这里。
            LOG_WARN << L"【攻击得手】注入成功！target 已被植入 hook dll——"
                        L"这只应在 --defense-off 时发生。target 自检应能报警。";
        }
    }

    // ---------- 6) Resume ----------
    if (::ResumeThread(res.main_thread.get()) == static_cast<DWORD>(-1)) {
        LOG_ERROR << L"ResumeThread 失败: " << DescribeError(LastError()).c_str();
        return 1;
    }
    LOG_INFO << L"target 已 Resume；观察 target 的 [selfcheck] 自检结果。";

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
