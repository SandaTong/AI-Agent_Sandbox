// -----------------------------------------------------------------------------
// demo/m3_demo.cc
// -----------------------------------------------------------------------------
// M3 Broker/Target IPC 骨架演示。
//
// 在 M0/M1（Job + Restricted Token + Low IL + Mitigation）基础上，broker 与
// 沙箱内 target 之间建立一条命名管道 IPC 通道：
//   * broker 起 target 前先建好命名管道（若 --ac 则把管道 SD 授权 target 的
//     Package SID，让 AppContainer target 也能连上）
//   * launch target（带 --ipc 参数，让 target 跑 IPC 客户端逻辑）
//   * broker WaitForClient 等 target 连上，然后循环 ServeOneRequest 服务请求
//   * target 断开（跑完 IPC demo 进入心跳）后 broker 结束服务循环，继续等
//     target 退出
//
// 使用:
//   m3_demo.exe [--ac] [--strict N] [--no-il] <target_exe> [args...]
//     --ac  叠加 AppContainer（M2 能力），并把管道 SD 授权 Package SID
//     --strict N  mitigation 强度，默认 4（够演示又不容易踩 M1 那些坑）
//     --no-il   关掉 Low IL 降级
//
// ⚠️ 冒烟前置：请先创建白名单目录和测试文件（broker 侧策略只放行这个目录）：
//     mkdir C:\sandbox_share
//     echo hello-from-broker > C:\sandbox_share\hello.txt
//
// 期望现象：
//   [+] PipeServer: 管道已就绪 ...
//   [+] PipeServer: target 已连接
//   [+] PipeServer: 收到 Ping，回 Pong
//   [+] PipeServer: 已代劳打开 C:\sandbox_share\hello.txt 并 DuplicateHandle ...
//   [!] PipeServer: 拒绝打开越权路径: C:\Windows\System32\drivers\etc\hosts
//   target 侧：hello.txt -> OK 能读到内容；hosts -> BLOCKED
// -----------------------------------------------------------------------------
#include <windows.h>

#include <chrono>
#include <string>

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
    int strict_level = 4;
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
        } else if (wcscmp(argv[i], L"--strict") == 0 && i + 1 < argc) {
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
    LOG_INFO << L"用法: m3_demo.exe [--ac] [--strict N] [--no-il] <target_exe> [args...]";
    LOG_INFO << L"      target 记得带 --ipc，才会跑 IPC 客户端逻辑";
    LOG_INFO << L"      冒烟前置: mkdir C:\\sandbox_share 且放一个 hello.txt";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        PrintUsage();
        return 1;
    }

    using namespace sandbox;

    LOG_INFO << L"M3 配置：ac=" << (a.use_ac ? L"on" : L"off") << L" strict=" << a.strict_level
             << L" IL=" << (a.use_il ? L"Low" : L"off");

    // ---------- 1) 可选 AppContainer ----------
    AppContainer ac;
    std::wstring pkg_sid_sddl;
    if (a.use_ac) {
        if (auto ec = ac.Create(L"com.wemeet.sandbox.demo.m3", L"Wemeet Sandbox M3 Demo")) {
            LOG_ERROR << L"AppContainer.Create 失败: " << DescribeError(ec).c_str();
            return ec.value();
        }
        pkg_sid_sddl = ac.PackageSidString();
        LOG_INFO << L"AppContainer: package SID = " << pkg_sid_sddl.c_str();
    }

    // ---------- 2) 命名管道服务端（launch 前先建好）----------
    // 关键：若走 AppContainer，把管道 SD 授权 target 的 Package SID，否则
    // AppContainer target CreateFileW 连管道会 ACCESS_DENIED。这一步把 M2 的
    // AppContainer 和 M3 的 IPC 缝在一起。
    PipeServer server;
    if (auto ec = server.Create(pkg_sid_sddl)) {
        LOG_ERROR << L"PipeServer.Create 失败: " << DescribeError(ec).c_str();
        return ec.value();
    }

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
    MitigationConfig mit_cfg = BuildMitigation(a.strict_level);
    mit_cfg.strict_signed_dll = false;  // 见 M2：AppContainer runtime 需要非纯签名 DLL

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
    if (auto ec = attr_list.Configure(mit_cfg, /*parent_process*/ nullptr, sec_caps_ptr)) {
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
    // 等 target 连上，然后循环处理它的请求，直到 target 断开管道（它跑完 IPC
    // demo 进入心跳后不再发消息，ReadFile 会返回 BROKEN_PIPE）。
    LOG_INFO << L"PipeServer: 等待 target 连接……";
    if (auto ec = server.WaitForClient()) {
        LOG_WARN << L"WaitForClient 失败: " << DescribeError(ec).c_str();
    } else {
        for (;;) {
            auto ec = server.ServeOneRequest(res.process.get());
            if (ec) {
                // 对端断开（BROKEN_PIPE）是正常结束信号。
                if (ec.value() == ERROR_BROKEN_PIPE || ec.value() == ERROR_PIPE_NOT_CONNECTED) {
                    LOG_INFO << L"PipeServer: target 已断开管道，服务循环结束";
                } else {
                    LOG_WARN << L"ServeOneRequest 结束: " << DescribeError(ec).c_str();
                }
                break;
            }
        }
    }

    // ---------- 8) 等 target 退出 ----------
    LOG_INFO << L"等待 target 退出中……（target 在心跳，手动关闭它才结束）";
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
