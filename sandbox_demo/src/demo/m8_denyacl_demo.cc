// -----------------------------------------------------------------------------
// demo/m8_denyacl_demo.cc
// -----------------------------------------------------------------------------
// M8 用户态文件 Broker 演示【形态 B：DENY-ACE 从外部剥夺写权限】。
//
// 和形态 A（IPC 文件 broker 主动代劳）互补的另一条路线：broker 起 target 之前，
// 直接给敏感目录 C:\sandbox_protected 的 NTFS DACL 追加一条针对 target 主体 SID
// 的 DENY-WRITE ACE（含目录+文件继承）。于是 target 自己 CreateFileW(GENERIC_
// WRITE) 那个目录时，内核访问检查里 DENY-ACE 优先命中，直接 ACCESS_DENIED。
//
// 这对应 target 里的 jailbreak-9（直接写 C:\sandbox_protected\jailbreak9.txt）：
//   * 不加 DENY-ACE（如直接双击 / 跑 M0）：SUCCESS（沙箱漏了）
//   * 本 demo 加了 DENY-ACE：BLOCKED (gle=5 ACCESS_DENIED) ⭐
//
// 要点：M0 的 restricted token 从当前进程 token 派生，用户 SID 不变，所以对
// "当前用户 SID"下 DENY 就能作用到 target。demo 结束自动回滚这条 ACE。
//
// 冒烟前置：
//   mkdir C:\sandbox_protected
//
// 用法（改 ACL 需对该目录有 WRITE_DAC 权限，一般当前用户对自己建的目录就有）:
//   m8_denyacl_demo.exe [--no-il] <target_exe> --once
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/file_acl.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"

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
        LOG_INFO << L"用法: m8_denyacl_demo.exe [--no-il] <target_exe> --once";
        LOG_INFO << L"      冒烟前置: mkdir C:\\sandbox_protected";
        return 1;
    }

    using namespace sandbox;
    constexpr const wchar_t* kProtectedDir = L"C:\\sandbox_protected";
    LOG_INFO << L"M8【DENY-ACE 剥夺写权限】配置：IL=" << (use_il ? L"Low" : L"off") << L" 受保护目录="
             << kProtectedDir;

    // ---------- 0) 给受保护目录追加针对当前用户 SID 的 DENY-WRITE ACE ----------
    // FileAcl 析构自动回滚（也可显式 RemoveDenyWrite）。这里用局部对象，作用域到
    // wmain 结束——demo 跑完 ACE 就被摘掉，不污染真实目录权限。
    FileAcl file_acl;
    if (auto ec = file_acl.AddDenyWrite(kProtectedDir)) {
        LOG_ERROR << L"FileAcl.AddDenyWrite 失败（目录是否存在? 是否有 WRITE_DAC?）: "
                  << DescribeError(ec).c_str();
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
    mit_cfg.dep = true;
    mit_cfg.aslr_bottom_up = true;
    mit_cfg.disable_child_process = true;
    mit_cfg.strict_signed_dll = false;
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
             << L"；观察 target 的 jailbreak-9 应 BLOCKED (gle=5 ACCESS_DENIED)";

    // ---------- 5) 等 target 退出 ----------
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(), std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec)
        LOG_WARN << L"WaitForExit 返回异常: " << DescribeError(ec).c_str();
    else
        LOG_INFO << L"Target 退出，exit_code=0x" << std::hex << exit_code << std::dec;

    // file_acl 析构在这里自动回滚 DENY-ACE。
    return 0;
}
