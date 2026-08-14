// -----------------------------------------------------------------------------
// demo/m6_appid_demo.cc
// -----------------------------------------------------------------------------
// M6 WFP 网络管控演示【形态 C：AppID 精确匹配】。
//
// broker 用 WFP filter 按**exe 路径(AppId)**精确拦 target 的全部 outbound，
// 通过 FWPM_CONDITION_ALE_APP_ID 匹配。效果：只拦 hello_target.exe 这一个进程，
// 同机其他进程网络完全不受影响。
//
// 预期（target 的 jailbreak-7 三行全 BLOCKED）：
//   [7a] 8.8.8.8   (白名单外) : BLOCKED
//   [7b] 1.1.1.1   (白名单内) : BLOCKED  （AppID 形态无白名单，全拦）
//   [7c] 127.0.0.1 (loopback) : BLOCKED  ⭐ 连回环也拦——WFP 相对 Windows Firewall 的关键优势
//
// 与形态 A 的区别：形态 A 是"IP 白名单（放行部分）"，形态 C 是"针对某 exe 全拦"。
// 形态 C 最贴近"精确沙箱化某一个 target 进程的网络"，不需要知道它要连哪些 IP。
//
// 用法（需管理员权限）:
//   m6_appid_demo.exe [--no-il] <target_exe> [args...]
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"
#include "core/wfp_filter.h"

namespace {

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

std::wstring ToAbsolutePath(const std::wstring& p) {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = ::GetFullPathNameW(p.c_str(), MAX_PATH, buf, nullptr);
    return (n > 0 && n < MAX_PATH) ? std::wstring(buf) : p;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    bool use_il = true;
    int target_start = -1;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--no-il") == 0) {
            use_il = false;
        } else {
            target_start = i;
            break;
        }
    }
    if (target_start < 0) {
        LOG_INFO << L"用法: m6_appid_demo.exe [--no-il] <target_exe> [args...]（需管理员）";
        return 1;
    }

    using namespace sandbox;

    std::wstring target_abs = ToAbsolutePath(argv[target_start]);
    LOG_INFO << L"M6【AppID 精确拦截】配置：IL=" << (use_il ? L"Low" : L"off") << L" target="
             << target_abs.c_str();

    // ---------- 0) 装 WFP：按 AppID 拦 target 全部 outbound ----------
    WfpFilter wfp;
    if (auto ec = wfp.Open()) {
        LOG_ERROR << L"WfpFilter.Open 失败（是否以管理员运行?）: " << DescribeError(ec).c_str();
        return ec.value();
    }
    WfpPolicy policy;
    policy.kind = WfpPolicyKind::kBlockAppId;
    policy.block_app_path = target_abs;
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
    if (use_il) {
        if (auto ec = token.SetIntegrityLevel(IntegrityLevel::kLow)) {
            LOG_ERROR << L"TokenManager.SetIntegrityLevel 失败: " << DescribeError(ec).c_str();
            return ec.value();
        }
    }

    // ---------- 3) Mitigation ----------
    MitigationConfig mit_cfg{};
    mit_cfg.strict_signed_dll = false;
    mit_cfg.prohibit_dynamic_code = false;
    MitigationAttrList attr_list;
    if (auto ec = attr_list.Configure(mit_cfg, nullptr, nullptr)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 4) Launch ----------
    LaunchOptions opts;
    opts.exe_path = argv[target_start];
    opts.cmd_line = BuildCmdLine(argc, argv, target_start);
    opts.attr_list = &attr_list;

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }
    LOG_INFO << L"ProcessLauncher: pid=" << res.process_id
             << L"；观察 target 的 jailbreak-7 三行应全 BLOCKED（含 loopback）";

    // ---------- 5) 等 target 退出 ----------
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(), std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec)
        LOG_WARN << L"WaitForExit 返回异常: " << DescribeError(ec).c_str();
    else
        LOG_INFO << L"Target 退出，exit_code=0x" << std::hex << exit_code << std::dec;
    return 0;
}
