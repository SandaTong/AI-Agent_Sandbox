// -----------------------------------------------------------------------------
// demo/m8_demo.cc
// -----------------------------------------------------------------------------
// M8 用户态文件 Broker 演示【形态 A：策略引擎增强版】。
//
// 在 M3 的 Broker/Target Named-Pipe IPC 骨架之上，把文件 broker 从"单目录只读
// 白名单"升级成生产级策略引擎：
//   1. 多规则白名单：一个【只读】目录 + 一个【可写】目录，读写权限分离。
//   2. 读/写/创建多操作：协议加 access_mode / disposition，target 能请 broker
//      代劳写文件（CreateFileW + WriteFile 都在 broker 侧按最小权限做）。
//   3. 防 TOCTOU：broker 先开句柄，再用 GetFinalPathNameByHandle 拿"事后真身"
//      （已解 symlink/junction/短名/大小写）去比白名单，杜绝检查时机攻击。
//   4. 最小权限句柄回传：DuplicateHandle 时按本次策略允许的最小 access 复制，
//      不再 DUPLICATE_SAME_ACCESS 原样带权限。
//
// 冒烟前置（broker 侧策略目录）：
//   mkdir C:\sandbox_share     （只读目录，放 hello.txt）
//   echo hello-from-broker > C:\sandbox_share\hello.txt
//   mkdir C:\sandbox_write     （可写目录，target 请 broker 往这里写）
//
// 预期现象（target 带 --ipc 时）：
//   [ipc] Ping -> Pong OK
//   [ipc] 打开 C:\sandbox_share\hello.txt -> OK (读到内容)
//   [ipc] 打开 ...\etc\hosts -> BLOCKED（越权路径）
//   [ipc] 写 C:\sandbox_write\agent_out.txt -> OK (broker 代劳落盘)
//   [ipc] 写 C:\sandbox_share\should_fail.txt -> BLOCKED（命中只读规则，拒绝写）⭐
//
// 用法:
//   m8_demo.exe [--ac] [--no-il] <target_exe> --ipc --once
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>
#include <vector>

#include "common/logger.h"
#include "common/win_error.h"
#include "core/appcontainer.h"
#include "core/job_manager.h"
#include "core/mitigation.h"
#include "core/pipe_server.h"
#include "core/process_launcher.h"
#include "core/token_manager.h"

namespace {

struct CliArgs {
    bool use_ac = false;
    bool use_il = true;
    int target_start = -1;
};

CliArgs ParseArgs(int argc, wchar_t** argv) {
    CliArgs r;
    int i = 1;
    while (i < argc) {
        if (wcscmp(argv[i], L"--ac") == 0) {
            r.use_ac = true;
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
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        LOG_INFO << L"用法: m8_demo.exe [--ac] [--no-il] <target_exe> --ipc --once";
        LOG_INFO << L"      冒烟前置: mkdir C:\\sandbox_share 放 hello.txt; mkdir C:\\sandbox_write";
        return 1;
    }

    using namespace sandbox;
    LOG_INFO << L"M8【文件 Broker 策略引擎】配置：ac=" << (a.use_ac ? L"on" : L"off") << L" IL="
             << (a.use_il ? L"Low" : L"off");

    // ---------- 1) 可选 AppContainer ----------
    AppContainer ac;
    std::wstring pkg_sid_sddl;
    if (a.use_ac) {
        if (auto ec = ac.Create(L"com.wemeet.sandbox.demo.m8", L"Wemeet Sandbox M8 Demo")) {
            LOG_ERROR << L"AppContainer.Create 失败: " << DescribeError(ec).c_str();
            return ec.value();
        }
        pkg_sid_sddl = ac.PackageSidString();
    }

    // ---------- 2) 命名管道服务端 + M8 文件策略 ----------
    PipeServer server;
    if (auto ec = server.Create(pkg_sid_sddl)) {
        LOG_ERROR << L"PipeServer.Create 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }
    // 【M8 核心】多规则白名单：只读目录 + 可写目录。
    std::vector<FilePolicyRule> rules;
    rules.push_back({L"C:\\sandbox_share\\", /*allow_write=*/false});  // 只读
    rules.push_back({L"C:\\sandbox_write\\", /*allow_write=*/true});   // 可写
    server.SetFilePolicy(std::move(rules));

    // ---------- 3) Job ----------
    JobManager job;
    JobPolicy job_policy{};
    if (auto ec = job.Create(job_policy)) {
        LOG_ERROR << L"JobManager.Create 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 4) Token ----------
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

    // ---------- 5) Mitigation (+ 可选 SECURITY_CAPABILITIES) ----------
    MitigationConfig mit_cfg{};
    mit_cfg.dep = true;
    mit_cfg.aslr_bottom_up = true;
    mit_cfg.disable_child_process = true;
    mit_cfg.strict_signed_dll = false;

    SECURITY_CAPABILITIES sec_caps{};
    SECURITY_CAPABILITIES* sec_caps_ptr = nullptr;
    AppContainer::SecurityCapabilitiesView view{};
    if (a.use_ac) {
        view = ac.View();
        sec_caps.AppContainerSid = view.app_container_sid;
        sec_caps.Capabilities = view.capabilities;
        sec_caps.CapabilityCount = view.capability_count;
        sec_caps_ptr = &sec_caps;
    }

    MitigationAttrList attr_list;
    if (auto ec = attr_list.Configure(mit_cfg, nullptr, sec_caps_ptr)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

    // ---------- 6) Launch ----------
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
    LOG_INFO << L"ProcessLauncher: pid=" << res.process_id;

    // ---------- 7) IPC 服务循环 ----------
    LOG_INFO << L"PipeServer: 等待 target 连接……";
    if (auto wait_ec = server.WaitForClient()) {
        LOG_WARN << L"WaitForClient 失败: " << DescribeError(wait_ec).c_str();
    } else {
        for (;;) {
            auto serve_ec = server.ServeOneRequest(res.process.get());
            if (serve_ec) {
                if (serve_ec.value() == ERROR_BROKEN_PIPE ||
                    serve_ec.value() == ERROR_PIPE_NOT_CONNECTED)
                    LOG_INFO << L"PipeServer: target 已断开管道，服务循环结束";
                else
                    LOG_WARN << L"ServeOneRequest 结束: " << DescribeError(serve_ec).c_str();
                break;
            }
        }
    }

    // ---------- 8) 等 target 退出 ----------
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(), std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec)
        LOG_WARN << L"WaitForExit 返回异常: " << DescribeError(ec).c_str();
    else
        LOG_INFO << L"Target 退出，exit_code=0x" << std::hex << exit_code << std::dec;
    return 0;
}
