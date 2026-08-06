// -----------------------------------------------------------------------------
// demo/m1_demo.cc
// -----------------------------------------------------------------------------
// M1 沙箱综合演示：在 M0 基础上叠加
//   * Low Integrity Level
//   * 8 项 Process Mitigation Policy
//   * Alternate WindowStation + Desktop
//
// 使用:
//   m1_demo.exe [--strict N] [--no-il] [--no-desk] <target_exe> [args...]
//
//   --strict N (0..8)逐项 bisect mitigation policy
//     0 = 全关（等价 M0）
//     1 = + DEP
//     2 = + ASLR (bottom_up + force_relocate)
//     3 = + PROHIBIT_DYNAMIC_CODE
//     4 = + CHILD_PROCESS_RESTRICTED
//     5 = + IMAGE_LOAD_NO_REMOTE
//     6 = + IMAGE_LOAD_NO_LOW_LABEL
//     7 = + BLOCK_NON_MICROSOFT_BINARIES
//     8 = + EXTENSION_POINT_DISABLE
//   --no-il            关闭 Low IL 降级（bisect IL 是否影响启动）
//   --no-desk          关闭 alternate winsta+desktop（bisect UI 隔离）
//
//   不传时默认：strict=8, IL=Low, desk=on。
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/desktop_iso.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"

namespace {

struct CliArgs {
    int strict_level = 8;
    bool use_il = true;
    bool use_desk = true;
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
        } else if (wcscmp(argv[i], L"--no-desk") == 0) {
            r.use_desk = false;
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
    c.prohibit_dynamic_code = level >= 3;
    c.disable_child_process = level >= 4;
    c.image_load_no_remote = level >= 5;
    c.image_load_no_low_label = level >= 6;
    c.strict_signed_dll = level >= 7;
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

void PrintUsage() {
    LOG_INFO << L"用法: m1_demo.exe [--strict N] [--no-il] [--no-desk] <target_exe> [args...]";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        PrintUsage();
        return 1;
    }

    using namespace sandbox;

    LOG_INFO << L"M1 配置：strict=" << a.strict_level << L" IL=" << (a.use_il ? L"Low" : L"off")
             << L" desk=" << (a.use_desk ? L"iso" : L"off");

    // ---- broker 提前建probe mutex（见 hello_target.cc::Test6 注释） ----
    HANDLE probe_mutex = ::CreateMutexW(nullptr, FALSE, L"Global\\WEMEET_SANDBOX_PROBE_MUTEX");
    if (!probe_mutex) {
        LOG_WARN << L"probe mutex 创建失败(gle=" << ::GetLastError()
                 << L")，jailbreak-6 结果可能失真";
    }

    // ---------- 1) Job ----------
    JobManager job;
    JobPolicy job_policy{};
    if (a.use_desk) {
        // Alt Desktop 隔离和 Job UILIMIT_DESKTOP / UILIMIT_HANDLES 是**互斥的**：
        //   * target 一起来就要 attach 到我们新建的 desktop（user32.dll DllMain
        //     里做的），这个 attach 走的是 NtUserOpenDesktop —— 恰好被 Job 的
        //     UILIMIT_DESKTOP + UILIMIT_HANDLES 拦下，target CRT 初始化失败，
        //     报 0xC0000142。
        //   * 既然我们已经用独立 winsta/desktop 做 UI 隔离，Job UI 限制里的
        //     DESKTOP 和 HANDLES 已经没必要——那两位主要用来防"target 在共
        //     享桌面上乱操作"。所以清掉。
        //   * 其余 UI 限制（EXITWINDOWS / SYSTEMPARAMETERS / CLIPBOARD 等）
        //     保留，它们和 alt desktop 不冲突。
        job_policy.ui_restrictions &= ~JOB_OBJECT_UILIMIT_DESKTOP;
        job_policy.ui_restrictions &= ~JOB_OBJECT_UILIMIT_HANDLES;
    }
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
    if (auto ec = attr_list.Configure(mit_cfg, /*parent_process*/ nullptr)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 4) Desktop ----------
    DesktopIsolation desk;
    if (a.use_desk) {
        if (auto ec = desk.Create()) {
            LOG_ERROR << L"DesktopIsolation.Create 失败: " << DescribeError(ec).c_str();
            return ec.value();
        }
        // 必须给 desktop 授权，否则 Low IL target attach 时会被拒（默认 DACL
        // 只包含 broker 自己），导致 0xC0000142 STATUS_DLL_INIT_FAILED。
        if (auto ec = desk.GrantAccessToLowIntegrity()) {
            LOG_ERROR << L"DesktopIsolation.Grant 失败: " << DescribeError(ec).c_str();
            return ec.value();
        }
    }

    // ---------- 5) Launch ----------
    LaunchOptions opts;
    opts.exe_path = argv[a.target_start];
    opts.cmd_line = BuildCmdLine(argc, argv, a.target_start);
    opts.desktop_iso = a.use_desk ? &desk : nullptr;
    opts.attr_list = &attr_list;

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    DWORD active = 0;
    (void)job.GetActiveProcessCount(active);
    LOG_INFO << L"Job 内活跃进程数: " << active;

    LOG_INFO << L"等待 target 退出中……（手动关闭 target 才会结束）";
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
