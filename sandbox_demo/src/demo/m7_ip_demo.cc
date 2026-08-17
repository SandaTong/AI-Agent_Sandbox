// -----------------------------------------------------------------------------
// demo/m7_ip_demo.cc
// -----------------------------------------------------------------------------
// M7【形态 C：DNS→IP 联动 M6 WFP】演示（M4 hook 思路 + M6 WFP 合体）。
//
// 形态 A（m7_demo）在 target **进程内** hook 域名解析，是"域名字符串"维度的管控。
// 形态 C 换一个思路，演示"域名 → IP → WFP"的联动架构：
//   1. broker 侧**自己先解析**白名单域名（GetAddrInfoW），拿到"域名 → IP 集合"；
//   2. 把这些 IP 交给 M6 的 WFP filter，实现"只有白名单域名解析出的 IP 才允许连"
//      —— 域名在 broker 侧翻译成 IP，WFP 在内核层按 IP 兜底。
//
// 【为什么要有 C：纵深防御】形态 A 的弱点是——agent 若直接用 IP 连（不解析域名）
//   就绕过了 hook。形态 C 在 IP 维度补一道：即使绕过域名解析，非白名单 IP 也连
//   不上。A（hostname 维度）+ C（IP 维度）两道关叠加 = 纵深防御。
//
// 【⚠️ 继承 M6 的已知本机限制】C 依赖 WFP 按 IP 精确匹配放行/拦截，而 M6 实测
//   本机纯用户态 ALE_AUTH_CONNECT_V4 层 IP 条件不命中（详见 M6.md § 四）。所以
//   本 demo 的 IP 联动部分在本机可能不真正生效——它的价值是**演示 DNS→IP→WFP
//   的联动架构**。真正落地需内核态 callout。为保证"能拦住 target"这一沙箱语义，
//   本 demo 同时用 M6 的 AppID 形态兜底（按 exe 精确禁网），把"域名→IP 解析结果"
//   作为策略信息打印出来，展示联动链路。
//
// 用法（需管理员权限——WFP 要写权限）:
//   m7_ip_demo.exe [--allow <domain>]... [--no-il] <target_exe> [args...]
// -----------------------------------------------------------------------------
#include <winsock2.h>
#include <ws2tcpip.h>

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

#pragma comment(lib, "ws2_32.lib")

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
        r.allow.emplace_back(L"example.com");
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

std::wstring ToAbsolutePath(const std::wstring& p) {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = ::GetFullPathNameW(p.c_str(), MAX_PATH, buf, nullptr);
    return (n > 0 && n < MAX_PATH) ? std::wstring(buf) : p;
}

// broker 侧解析一个域名，返回它的所有 IPv4 点分串（这就是"域名→IP"联动的核心）。
std::vector<std::wstring> ResolveIpv4(const std::wstring& host) {
    std::vector<std::wstring> ips;
    ADDRINFOW hints{};
    hints.ai_family = AF_INET;  // 只要 IPv4
    hints.ai_socktype = SOCK_STREAM;
    PADDRINFOW result = nullptr;
    if (::GetAddrInfoW(host.c_str(), nullptr, &hints, &result) != 0 || !result)
        return ips;
    for (ADDRINFOW* p = result; p; p = p->ai_next) {
        if (p->ai_family != AF_INET)
            continue;
        auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        wchar_t buf[64] = {};
        ::InetNtopW(AF_INET, &sa->sin_addr, buf, _countof(buf));
        ips.emplace_back(buf);
    }
    ::FreeAddrInfoW(result);
    return ips;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    CliArgs a = ParseArgs(argc, argv);
    if (a.target_start < 0) {
        LOG_INFO << L"用法: m7_ip_demo.exe [--allow <domain>]... [--no-il] <target_exe>（需管理员）";
        return 1;
    }

    using namespace sandbox;

    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        LOG_ERROR << L"WSAStartup 失败";
        return 1;
    }

    std::wstring target_abs = ToAbsolutePath(argv[a.target_start]);
    LOG_INFO << L"M7【DNS→IP 联动 WFP】配置：IL=" << (a.use_il ? L"Low" : L"off")
             << L" target=" << target_abs.c_str();

    // ---------- 0) broker 侧解析白名单域名 → IP（联动链路的核心）----------
    LOG_INFO << L"—— DNS→IP 解析（broker 侧）——";
    std::vector<std::wstring> allow_ips;
    for (const auto& d : a.allow) {
        auto ips = ResolveIpv4(d);
        if (ips.empty()) {
            LOG_WARN << L"  " << d.c_str() << L" 解析失败（跳过）";
            continue;
        }
        for (const auto& ip : ips) {
            LOG_INFO << L"  " << d.c_str() << L" -> " << ip.c_str();
            allow_ips.push_back(ip);
        }
    }

    // ---------- 1) WFP：装策略 ----------
    // 【本可以做的】把 allow_ips 作为"IP 白名单"放行、其余拦——但 M6 已证明本机
    // WFP IP 精确匹配不命中（M6.md § 四）。为保证沙箱语义真的生效，这里用 M6 的
    // AppID 形态兜底：按 exe 精确禁 target 全部 outbound。allow_ips 作为"域名→IP
    // 联动策略"打印展示（真实产品里会把它下发到内核 callout 做 IP 白名单）。
    WfpFilter wfp;
    if (auto ec = wfp.Open()) {
        LOG_ERROR << L"WfpFilter.Open 失败（是否以管理员运行?）: " << DescribeError(ec).c_str();
        ::WSACleanup();
        return ec.value();
    }
    LOG_INFO << L"—— WFP 联动策略 ——";
    LOG_INFO << L"  白名单域名共解析出 " << allow_ips.size()
             << L" 个 IP（真实产品会下发到内核 callout 做 IP 白名单）";
    LOG_INFO << L"  本 demo 用 AppID 形态兜底禁 target 全部 outbound（WFP IP 精确匹配"
                L"本机不命中，见 M6.md § 四）";
    WfpPolicy policy;
    policy.kind = WfpPolicyKind::kBlockAppId;
    policy.block_app_path = target_abs;
    if (auto ec = wfp.Apply(policy)) {
        LOG_ERROR << L"WfpFilter.Apply 失败: " << DescribeError(ec).c_str();
        ::WSACleanup();
        return ec.value();
    }

    // ---------- 2) Job ----------
    JobManager job;
    JobPolicy job_policy{};
    if (auto ec = job.Create(job_policy)) {
        LOG_ERROR << L"JobManager.Create 失败: " << DescribeError(ec).c_str();
        ::WSACleanup();
        return ec.value();
    }

    // ---------- 3) Token ----------
    TokenManager token;
    if (auto ec = token.CreateRestricted()) {
        LOG_ERROR << L"TokenManager.CreateRestricted 失败: " << DescribeError(ec).c_str();
        ::WSACleanup();
        return ec.value();
    }
    if (a.use_il) {
        if (auto ec = token.SetIntegrityLevel(IntegrityLevel::kLow)) {
            LOG_ERROR << L"TokenManager.SetIntegrityLevel 失败: " << DescribeError(ec).c_str();
            ::WSACleanup();
            return ec.value();
        }
    }

    // ---------- 4) Mitigation ----------
    MitigationConfig mit_cfg{};
    mit_cfg.strict_signed_dll = false;
    mit_cfg.prohibit_dynamic_code = false;
    MitigationAttrList attr_list;
    if (auto ec = attr_list.Configure(mit_cfg, nullptr, nullptr)) {
        LOG_ERROR << L"MitigationAttrList.Configure 失败: " << DescribeError(ec).c_str();
        ::WSACleanup();
        return ec.value();
    }

    // ---------- 5) Launch ----------
    LaunchOptions opts;
    opts.exe_path = argv[a.target_start];
    opts.cmd_line = BuildCmdLine(argc, argv, a.target_start);
    opts.attr_list = &attr_list;

    ProcessLauncher launcher(job, token);
    LaunchResult res;
    if (auto ec = launcher.Launch(opts, res)) {
        LOG_ERROR << L"ProcessLauncher.Launch 失败: " << DescribeError(ec).c_str();
        ::WSACleanup();
        return ec.value();
    }
    LOG_INFO << L"ProcessLauncher: pid=" << res.process_id
             << L"；观察 target 的 jailbreak-7/8（AppID 兜底应拦下 outbound）";

    // ---------- 6) 等 target 退出 ----------
    DWORD exit_code = 0;
    auto ec = ProcessLauncher::WaitForExit(res.process.get(), std::chrono::milliseconds::zero(),
                                           exit_code);
    if (ec)
        LOG_WARN << L"WaitForExit 返回异常: " << DescribeError(ec).c_str();
    else
        LOG_INFO << L"Target 退出，exit_code=0x" << std::hex << exit_code << std::dec;

    ::WSACleanup();
    return 0;
}
