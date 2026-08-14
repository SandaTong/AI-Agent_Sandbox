// -----------------------------------------------------------------------------
// core/wfp_filter.h
// -----------------------------------------------------------------------------
// M6：Windows Filtering Platform (WFP) 用户态网络管控。
//
// 【M6 要解决什么——还 M2 留下的两笔债】
//   M2 firewall 加餐用 INetFwPolicy2（Windows Firewall COM）给 target 加过
//   outbound block 规则，但有两个硬伤（见 docs/notes/M2.md § 九）：
//     ① loopback bypass —— Windows Firewall 对 127.0.0.1/::1 不走规则匹配，
//        回环流量拦不下。
//     ② 只能按 Package SID 匹配 —— 普通 Low IL target（非 AppContainer）拦不了。
//   而且 jailbreak-7（TCP 8.8.8.8）从 M0 到 M5 一直是 SUCCESS——target 的网络
//   出口从没被真正精确管控过。M6 用 WFP 补齐。
//
// 【为什么 WFP 比 Windows Firewall 强】
//   Windows Firewall(mpssvc) 本身就是**建在 WFP 之上**的一个上层策略引擎。
//   WFP 是内核网络栈里的过滤框架，在 TCP/IP 处理的多个「分层(layer)」上都
//   开放了挂 filter 的能力。直接对 WFP 编程 = 绕过 Firewall 那层的封装/绕过
//   它的 loopback bypass，在更底层按 远程IP/端口/本地AppID 精确匹配。
//
// 【WFP 的四个核心概念（编程模型）】
//   1. Engine（引擎）：FwpmEngineOpen 打开一个到内核过滤引擎的会话句柄。
//   2. Layer（分层）：内核网络栈上的固定挂载点。我们用
//        FWPM_LAYER_ALE_AUTH_CONNECT_V4 —— "应用层强制(ALE)在 connect() 发起
//        出站连接时的授权分层"，在这里能拿到 远程IP/端口/发起进程AppID。
//   3. Sublayer（子层）：自建一个 sublayer 把我们的 filter 归组，便于按
//        sublayer key 一次性清理，也隔离权重仲裁。
//   4. Filter（过滤器）：一条规则 = 若干 condition（匹配条件）+ action
//        (PERMIT/BLOCK) + weight（权重，高的先裁决）。多条 filter 命中时按
//        权重和 BLOCK-override 语义仲裁。
//
// 【两种策略形态（M6 做两个 demo 各演示一种）】
//   形态 A（IP 黑名单，m6_demo）：对每个黑名单 IP 加一条 BLOCK，其余目标放行。
//     只加 BLOCK filter、不涉及 PERMIT-over-BLOCK 仲裁，逻辑稳。效果：让
//     jailbreak-7 的 8.8.8.8 变 BLOCKED，未列入黑名单的目标仍可连。
//     —— 演示 WFP 按 FWPM_CONDITION_IP_REMOTE_ADDRESS 精确匹配远程 IP 的能力。
//   形态 C（AppID 精确匹配，m6_appid_demo）：只对指定 exe（hello_target.exe）
//     的出站连接加 BLOCK，用 FWPM_CONDITION_ALE_APP_ID 条件匹配。效果：只拦
//     那个 target 进程，同机其他进程网络不受影响。AppID 通过
//     FwpmGetAppIdFromFileName0 把 exe 路径转成 WFP 认的 blob。
//
// 【权限 & 清理】
//   * 改 WFP filter 需要管理员权限（FwpmEngineOpen 要 FWPM_SESSION 或默认 RPC
//     到 BFE 服务，写 filter 要写权限）。非管理员会得 FWP_E_* / ACCESS_DENIED。
//   * 用 FWPM_SESSION_FLAG_DYNAMIC 打开 engine：会话句柄一关，本会话加的所有
//     filter/sublayer 由 BFE 自动清理——**进程崩了也不会残留脏规则**。这是
//     用户态 WFP 的最佳实践（比 INetFwPolicy2 那种"析构里手动删"更稳）。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <system_error>
#include <vector>

namespace sandbox {

// 一条网络策略的形态。
enum class WfpPolicyKind {
    kIpBlocklist,  // 形态 A：按 IP 精确拦截指定目标（黑名单），其余放行
    kBlockAppId,   // 形态 C：只拦指定 exe（AppID）的 outbound
};

struct WfpPolicy {
    WfpPolicyKind kind = WfpPolicyKind::kIpBlocklist;

    // 形态 A 用：黑名单 IPv4（点分字符串，如 "8.8.8.8"）。只拦这些目标 IP 的
    // outbound，其余目标（含白名单外公网、loopback）默认放行。
    //
    // 【为什么改成黑名单而非白名单】白名单需要"默认 BLOCK-all 兜底 + 白名单 IP
    // PERMIT 豁免"，而 WFP 里 PERMIT 要确定性豁免同 sublayer 的 BLOCK 涉及
    // CLEAR_ACTION_RIGHT / 独立 sublayer 权重等仲裁深水区（实测 PERMIT 压不住
    // 兜底 BLOCK）。黑名单只加 BLOCK filter、不涉及 PERMIT-over-BLOCK 仲裁，
    // 逻辑更稳，同样能演示"WFP 按远程 IP 精确匹配拦截"这一核心能力。
    std::vector<std::wstring> block_ipv4;

    // 形态 C 用：要精确拦截其 outbound 的 exe 绝对路径（如 hello_target.exe）。
    std::wstring block_app_path;

    // 【重要】作用域限定：WFP filter 默认作用于**全机**流量。为避免 demo 误伤
    // broker 自己和系统网络，两种形态都用这个 exe 路径把规则**限定到只对该进程
    // 生效**（通过叠加 FWPM_CONDITION_ALE_APP_ID 条件）。
    //   - 形态 A：scope_app_path = target 路径 → "只对 target 拦黑名单 IP"
    //   - 形态 C：block_app_path 本身就是作用对象，scope 可留空
    // 留空则规则作用于全机（危险，仅在明确需要时用）。
    std::wstring scope_app_path;
};

// WFP 用户态过滤器管理器。RAII：析构关闭 engine，DYNAMIC 会话的所有 filter
// 由 BFE 自动清理。
class WfpFilter {
 public:
    WfpFilter() = default;
    ~WfpFilter();

    WfpFilter(const WfpFilter&) = delete;
    WfpFilter& operator=(const WfpFilter&) = delete;

    // 打开 WFP 引擎（DYNAMIC 会话）+ 建自有 sublayer。需管理员权限。
    std::error_code Open();

    // 按 policy 装配 filter（Open 之后调用）。可多次调用叠加规则。
    std::error_code Apply(const WfpPolicy& policy);

    // 关闭引擎（析构会自动调）。DYNAMIC 会话下 filter 随之被 BFE 清理。
    void Close();

 private:
    std::error_code EnsureSublayer();
    // 形态 A：加"按 IP 精确 BLOCK"（黑名单，逐个 IP 一条 BLOCK，限定到 scope_app）。
    std::error_code ApplyIpBlocklist(const std::vector<std::wstring>& block_ipv4,
                                     const std::wstring& scope_app_path);
    // 形态 C：加"按 AppID BLOCK outbound"。
    std::error_code ApplyBlockAppId(const std::wstring& app_path);

    HANDLE engine_ = nullptr;  // FwpmEngineOpen 返回的引擎句柄
    bool sublayer_added_ = false;
};

}  // namespace sandbox
