// -----------------------------------------------------------------------------
// demo/m6_demo.cc
// -----------------------------------------------------------------------------
// M6 WFP 网络管控演示【形态 A：IP 黑名单】。
//
// broker 用 WFP 用户态 filter 给 target 装网络策略：
//   对黑名单里的每个目标 IP（默认 8.8.8.8）加一条 BLOCK，其余目标默认放行。
// 规则通过 FWPM_CONDITION_ALE_APP_ID 限定到只对 target 进程生效，不动全机网络。
//
// 【为什么是黑名单而非白名单】白名单（默认拦 + 白名单放行）需要 PERMIT 确定性
// 压过兜底 BLOCK，涉及 WFP 仲裁深水区（CLEAR_ACTION_RIGHT / 独立 sublayer 权重，
// 实测 PERMIT 压不住 BLOCK）。黑名单只加 BLOCK filter，命中即拦、不命中即放行，
// 行为确定，同样能演示"WFP 按远程 IP 精确匹配"这一核心能力。
//
// 预期（target 的 jailbreak-7 三行）：
//   [7a] 8.8.8.8   (黑名单内) : BLOCKED  ⭐ 从 M0~M5 一直 SUCCESS，M6 终于按 IP 拦下
//   [7b] 1.1.1.1   (黑名单外) : SUCCESS  （放行）
//   [7c] 127.0.0.1 (loopback) : SUCCESS  （不在黑名单里，放行；要拦 loopback 见 AppID 形态）
//
// 用法（需管理员权限——改 WFP filter 要写权限）:
//   m6_demo.exe [--block <ipv4>]... [--no-il] <target_exe> [args...]
//   不带 --block 时默认黑名单 = {8.8.8.8}。
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>
#include <vector>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"
#include "core/wfp_filter.h"

namespace {

struct CliArgs {
    std::vector<std::wstring> block_ipv4;
    bool use_il = true;
    int target_start = -1;
};

CliArgs ParseArgs(int argc, wchar_t** argv) {
    CliArgs r;
    int i = 1;
    while (i < argc) {
        if (wcscmp(argv[i], L"--block") == 0 && i + 1 < argc) {
            r.block_ipv4.emplace_back(argv[i + 1]);
            i += 2;
        } else if (wcscmp(argv[i], L"--no-il") == 0) {
            r.use_il = false;
            ++i;
        } else {
            r.target_start = i;
            break;
        }
    }
    if (r.block_ipv4.empty())
        r.block_ipv4.emplace_back(L"8.8.8.8");  // 默认黑名单
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

// 把 target 相对路径转成绝对路径（WFP AppId 需要绝对路径）。
std::wstring ToAbsolutePath(const std::wstring& p) {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = ::GetFullPathNameW(p.c_str(), MAX_PATH, buf, nullptr);
    return (n > 0 && n < MAX_PATH) ? std::wstring(buf) : p;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        LOG_INFO << L"用法: m6_demo.exe [--block <ipv4>]... [--no-il] <target_exe> "
                    L"[args...]（需管理员）";
        return 1;
    }

    using namespace sandbox;

    std::wstring target_abs = ToAbsolutePath(argv[a.target_start]);
    LOG_INFO << L"M6【IP 黑名单】配置：IL=" << (a.use_il ? L"Low" : L"off") << L" target="
             << target_abs.c_str();
    for (const auto& ip : a.block_ipv4) LOG_INFO << L"  黑名单 IP（拦截）: " << ip.c_str();

    // ---------- 0) 先装 WFP 网络策略（限定到 target 进程）----------
    WfpFilter wfp;
    if (auto ec = wfp.Open()) {
        LOG_ERROR << L"WfpFilter.Open 失败（是否以管理员运行?）: " << DescribeError(ec).c_str();
        return ec.value();
    }
    WfpPolicy policy;
    policy.kind = WfpPolicyKind::kIpBlocklist;
    policy.block_ipv4 = a.block_ipv4;
    policy.scope_app_path = target_abs;  // 只对 target 生效，不动全机
    if (auto ec = wfp.Apply(policy)) {
        LOG_ERROR << L"WfpFilter.Apply 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

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

    // ---------- 3) Mitigation（沿用默认沙箱配置，反注入位可开可不开）----------
    MitigationConfig mit_cfg{};
    mit_cfg.strict_signed_dll = false;  // 避免拦到调试 CRT / target 依赖
    mit_cfg.prohibit_dynamic_code = false;
    MitigationAttrList attr_list;
    if (auto ec = attr_list.Configure(mit_cfg, nullptr, nullptr)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 4) Launch ----------
    LaunchOptions opts;
    opts.exe_path = argv[a.target_start];
    opts.cmd_line = BuildCmdLine(argc, argv, a.target_start);
    opts.attr_list = &attr_list;

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }
    LOG_INFO << L"ProcessLauncher: pid=" << res.process_id
             << L"；观察 target 的 jailbreak-7 三行网络判定";

    // ---------- 5) 等 target 退出 ----------
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(), std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec)
        LOG_WARN << L"WaitForExit 返回异常: " << DescribeError(ec).c_str();
    else
        LOG_INFO << L"Target 退出，exit_code=0x" << std::hex << exit_code << std::dec;

    // wfp 析构自动 Close，DYNAMIC 会话 filter 由 BFE 清理。
    return 0;
}
