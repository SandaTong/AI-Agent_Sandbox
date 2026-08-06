// -----------------------------------------------------------------------------
// demo/m2_demo.cc
// -----------------------------------------------------------------------------
// M2 沙箱综合演示：在 M1 之上加 AppContainer + Capability 白名单。
//
// 使用:
//   m2_demo.exe [--net] [--strict N] [--no-il] [--no-desk] <target_exe> [args...]
//
//   --net       给target 加 internetClient capability（jailbreak-7 会SUCCESS）
//               不加则target 出方向被内核拒（WSAEACCES）
//   --strict N  见 M1 doc；默认 8
//   --no-il     关掉 Low IL 降级
//   --desk      **反向开关**：显式打开 alt winsta+desktop（默认关）
//
// ⚠️ 为什么默认关掉 alt desktop（M2 亲踩的坑）
//   AppContainer 自带独立的 winsta / desktop 命名空间——它把 target 塞
//   进 \Sessions\<n>\AppContainerNamedObjects\<pkg_sid>\ 下自己的 winsta。
//   此时再往上叠加我们手工建的 alt winsta+desktop 会因命名空间冲突让
//   target 报 0xC0000142 STATUS_DLL_INIT_FAILED。Chromium sandbox 里
//   AppContainer 分支也不做 alt desktop，就这个道理。
//
// 期望现象（用 hello_target 冒烟）：
//   * broker 日志显示 AppContainer 已创建，package SID = S-1-15-2-...
//   * jailbreak-6 (打开global mutex): BLOCKED
//   * jailbreak-7 (TCP connect):
//         不带 --net: BLOCKED WSAEACCES
//         带 --net:   SUCCESS 或 TIMEOUT（能连通）
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/appcontainer.h"
#include "core/desktop_iso.h"
#include "core/firewall.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"

namespace {

struct CliArgs {
    int strict_level = 8;
    bool use_il = true;
    bool use_desk = false;  // M2 默认关：AppContainer 自带命名空间隔离
    bool allow_net = false;
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
        } else if (wcscmp(argv[i], L"--desk") == 0) {
            // M2 反向开关：显式打开 alt desktop（不推荐，会和 AppContainer
            // 冲突挂 target；保留只为让你可以复现坑）
            r.use_desk = true;
            ++i;
        } else if (wcscmp(argv[i], L"--net") == 0) {
            r.allow_net = true;
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
    LOG_INFO << L"用法: m2_demo.exe [--net] [--strict N] [--no-il] [--desk] <target_exe> [args...]";
    LOG_INFO << L"       --desk 是反向开关：显式启用 alt desktop（会挂，仅复现坑）";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        PrintUsage();
        return 1;
    }

    using namespace sandbox;

    LOG_INFO << L"M2 配置：strict=" << a.strict_level << L" IL=" << (a.use_il ? L"Low" : L"off")
             << L" desk=" << (a.use_desk ? L"iso" : L"off") << L" net="
             << (a.allow_net ? L"on" : L"off");

    // ---- broker 提前建 probe mutex（见 hello_target.cc::Test6 注释） ----
    // M2 里这个mutex 建在 broker 进程的 \BaseNamedObjects\ 下；AppContainer
    // target 走的是私有命名空间根本看不见它，正好演示 namespace isolation。
    HANDLE probe_mutex = ::CreateMutexW(nullptr, FALSE, L"Global\\WEMEET_SANDBOX_PROBE_MUTEX");
    if (!probe_mutex) {
        LOG_WARN << L"probe mutex 创建失败(gle=" << ::GetLastError()
                 << L")，jailbreak-6 结果可能失真";
    }

    // ---------- 1) AppContainer ----------
    // 先建 AppContainer，因为 profile SID 后面很多地方要用。
    // profile 名字用反向域名风格，同名profile 系统只保留一份。
    AppContainer ac;
    if (auto ec = ac.Create(L"com.wemeet.sandbox.demo.m2", L"Wemeet Sandbox M2 Demo")) {
        LOG_ERROR << L"AppContainer.Create 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    if (a.allow_net) {
        if (auto ec = ac.AddCapability(WellKnownCapability::kInternetClient)) {
            LOG_ERROR << L"AppContainer.AddCapability(internetClient)失败: "
                      << DescribeError(ec).c_str();
            return ec.value();
        }
    }

    // ---------- 1.5) Windows Firewall 规则（M2 加餐补丁）----------
    // 见 docs/notes/M2.md § 九 & § 十一：AppContainer 单靠自身不禁网，broker
    // 必须主动往 Windows Firewall 写规则。这里默认加一条 outbound TCP block
    // 规则；如果用户带了 --net，就跳过这一步（等价 UWP 里 internetClient
    // capability 允许出方向的效果）。
    //
    // ⚠️ 需要管理员权限。非管理员运行会 E_ACCESSDENIED，只警告不fail。
    FirewallGuard fw;
    if (!a.allow_net) {
        std::wstring pkg = ac.PackageSidString();
        static constexpr const wchar_t* kRuleName = L"sandbox_demo_m2_block_outbound";
        auto ec = fw.AddBlockAllOutboundForAppContainer(pkg, kRuleName);
        if (ec) {
            LOG_WARN << L"Firewall 规则未加成功 (" << DescribeError(ec).c_str()
                     << L")，jailbreak-7 可能仍 SUCCESS。请以管理员运行 broker。";
        }
    } else {
        LOG_INFO << L"Firewall:跳过outbound block 规则 (--net 显式允许出方向)";
    }

    // ---------- 2) Job ----------
    JobManager job;
    JobPolicy job_policy{};
    if (a.use_desk) {
        // 见 M1 § 七坑 #3：Alt Desktop 时清掉 DESKTOP/HANDLES 位
        job_policy.ui_restrictions &= ~JOB_OBJECT_UILIMIT_DESKTOP;
        job_policy.ui_restrictions &= ~JOB_OBJECT_UILIMIT_HANDLES;
    }
    if (auto ec = job.Create(job_policy)) {
        LOG_ERROR << L"JobManager.Create 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 3) Token ----------
    // M2 里 LowBox Token 是通过 STARTUPINFOEX + SECURITY_CAPABILITIES 内核
    // 侧生成的，所以这里的 restricted token 只是"起点"，不用调CreateRestrictedToken。
    // 我们让 launcher 用当前用户的 primary token 作起点（token 参数传 nullptr
    // 会走 CreateProcessW 而不是 CreateProcessAsUserW，但我们仍然把 IL 和
    // restricted 加上，代码结构和 M1 保持一致）。
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

    // ---------- 4) Mitigation + SECURITY_CAPABILITIES ----------
    MitigationConfig mit_cfg = BuildMitigation(a.strict_level);
    // AppContainer 已经"堵掉了非签名 DLL 加载 + 网络 + 命名空间"，很多
    // mitigation 有 AppContainer 就冗余了。但一起开也没坏处，只要target
    // 能起来。M2 里我们关掉 strict_signed_dll 是因为 AppContainer runtime
    // 需要加载一些非 Microsoft-only 签名的 DLL（比如 winsock helper），
    // 强开会挂。这个坑记进 docs/notes/M2.md。
    mit_cfg.strict_signed_dll = false;

    AppContainer::SecurityCapabilitiesView view = ac.View();
    SECURITY_CAPABILITIES sec_caps{};
    sec_caps.AppContainerSid = view.app_container_sid;
    sec_caps.Capabilities = view.capabilities;
    sec_caps.CapabilityCount = view.capability_count;

    MitigationAttrList attr_list;
    if (auto ec = attr_list.Configure(mit_cfg, /*parent_process*/ nullptr, &sec_caps)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 5) Desktop ----------
    DesktopIsolation desk;
    if (a.use_desk) {
        if (auto ec = desk.Create()) {
            LOG_ERROR << L"DesktopIsolation.Create 失败: " << DescribeError(ec).c_str();
            return ec.value();
        }
    }

    // ---------- 6) Launch ----------
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
