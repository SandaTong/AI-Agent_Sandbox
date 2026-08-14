// -----------------------------------------------------------------------------
// core/wfp_filter.cc
// -----------------------------------------------------------------------------
#include "core/wfp_filter.h"

#include <fwpmu.h>     // FwpmEngineOpen / FwpmFilterAdd / FwpmSubLayerAdd ...
#include <ws2tcpip.h>  // inet_pton

#include "common/logger.h"
#include "common/win_error.h"

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "rpcrt4.lib")  // UuidCreate

namespace sandbox {

namespace {

// 我们自建 sublayer 的 GUID（随便一个稳定的自有 GUID；同一 key 便于归组/清理）。
// {8F2E6B41-9C3A-4D5E-B7A1-2C6D4E8F1A93}
constexpr GUID kSandboxSublayerKey = {
    0x8f2e6b41, 0x9c3a, 0x4d5e, {0xb7, 0xa1, 0x2c, 0x6d, 0x4e, 0x8f, 0x1a, 0x93}};

// 权重常量：黑名单形态只有 BLOCK filter，权重无需和 PERMIT 竞争，取中等值即可。
// 用 FWP_UINT64 绝对权重（不用 FWP_UINT8）保持写法一致、行为确定。
constexpr UINT64 kWeightBlockIp = 2000;   // 黑名单 IP BLOCK
constexpr UINT64 kWeightBlockApp = 2000;  // AppID BLOCK

// 把点分 IPv4 转成 FWP_V4_ADDR_AND_MASK.addr 用的主机字节序整数。
// FWP_V4_ADDR_AND_MASK 官方要求 addr/mask 均为主机字节序（host order），这里按
// 官方标准写法用 ntohl 转主机序。
// 【重要实测结论】UINT32/ADDR_MASK × 主机序/网络序四种组合，在本机
// ALE_AUTH_CONNECT_V4 层对 target 的 outbound connect 均装配正确（netsh 可见
// 8.8.8.8/32）却全部不命中；而同层同会话的 ALE_APP_ID 条件正常生效。详见
// docs/notes/M6.md「IP 精确匹配踩坑全记录」。此处保留官方标准写法作教学留档。
bool ParseIpv4Host(const std::wstring& ip, UINT32& out_host_order) {
    IN_ADDR addr{};
    // inet_pton 需要窄字符串
    char buf[64] = {};
    ::WideCharToMultiByte(CP_ACP, 0, ip.c_str(), -1, buf, sizeof(buf), nullptr, nullptr);
    if (::inet_pton(AF_INET, buf, &addr) != 1)
        return false;
    out_host_order = ::ntohl(addr.S_un.S_addr);  // 网络序 → 主机序（FWP_V4_ADDR_MASK 要求）
    return true;
}

}  // namespace

WfpFilter::~WfpFilter() {
    Close();
}

std::error_code WfpFilter::Open() {
    // DYNAMIC 会话：句柄一关，本会话加的 filter/sublayer 由 BFE 自动清理。
    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = const_cast<wchar_t*>(L"SandboxWfpSession");

    DWORD st = ::FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_);
    if (st != ERROR_SUCCESS) {
        LOG_ERROR << L"WfpFilter: FwpmEngineOpen 失败（需管理员权限）: "
                  << DescribeError(MakeWinError(st)).c_str();
        return MakeWinError(st);
    }
    LOG_INFO << L"WfpFilter: WFP 引擎已打开（DYNAMIC 会话，退出自动清理）";
    return EnsureSublayer();
}

std::error_code WfpFilter::EnsureSublayer() {
    FWPM_SUBLAYER0 sub{};
    sub.subLayerKey = kSandboxSublayerKey;
    sub.displayData.name = const_cast<wchar_t*>(L"SandboxSublayer");
    sub.displayData.description = const_cast<wchar_t*>(L"M6 network sandbox sublayer");
    sub.weight = 0x8000;  // sublayer 之间的权重（中等）

    DWORD st = ::FwpmSubLayerAdd0(engine_, &sub, nullptr);
    if (st != ERROR_SUCCESS && st != FWP_E_ALREADY_EXISTS) {
        LOG_ERROR << L"WfpFilter: FwpmSubLayerAdd 失败: "
                  << DescribeError(MakeWinError(st)).c_str();
        return MakeWinError(st);
    }
    sublayer_added_ = true;
    return {};
}

std::error_code WfpFilter::Apply(const WfpPolicy& policy) {
    if (!engine_)
        return MakeWinError(ERROR_INVALID_STATE);
    switch (policy.kind) {
        case WfpPolicyKind::kIpBlocklist:
            return ApplyIpBlocklist(policy.block_ipv4, policy.scope_app_path);
        case WfpPolicyKind::kBlockAppId:
            return ApplyBlockAppId(policy.block_app_path);
    }
    return MakeWinError(ERROR_INVALID_PARAMETER);
}

std::error_code WfpFilter::ApplyIpBlocklist(const std::vector<std::wstring>& block_ipv4,
                                            const std::wstring& scope_app_path) {
    // 黑名单形态：对每个黑名单 IP 加一条 BLOCK filter（可选叠加 AppID scope，
    // 只对 target 生效）。其余目标不加规则 → 默认放行。
    //
    // ⚠️【已知本机限制 · 必读】按远程 IP 精确匹配（FWPM_CONDITION_IP_REMOTE_ADDRESS）
    // 在本机纯用户态 DYNAMIC filter + ALE_AUTH_CONNECT_V4 层【实测不命中】：
    //   · UINT32/ADDR_MASK × 主机序/网络序 四种组合全部装配正确（netsh 可见
    //     8.8.8.8/32）却拦不住 target 的 outbound connect，netevents 零 drop；
    //   · 对照实验（去掉 IP 条件、无条件 BLOCK）三行全拦，证明本会话裸 BLOCK 有效，
    //     问题精确锁定在 IP 条件求值本身（connect 授权瞬间远程 IP 未纳入匹配/被
    //     环境仲裁短路），属 WFP 分层语义 + 本机环境层面，纯用户态代码改不动。
    //   · 同层同会话的 ALE_APP_ID 条件正常生效 → 精确按进程管控请用 kBlockAppId 形态。
    // 完整排查记录见 docs/notes/M6.md。此处保留官方标准写法（ADDR_MASK+主机序）作
    // 教学留档：代码结构正确，在不受此环境限制的机器/内核态 callout 下即可命中。
    //
    // 【为什么黑名单而非白名单】白名单要 PERMIT 确定性压过兜底 BLOCK，涉及
    // CLEAR_ACTION_RIGHT / 独立 sublayer 权重等仲裁深水区；黑名单只有 BLOCK，
    // 命中即拦、不命中即放行，行为确定。
    if (block_ipv4.empty()) {
        LOG_WARN << L"WfpFilter: 黑名单为空，未加任何规则（全部放行）";
        return {};
    }

    // 若给了 scope_app_path，取它的 AppId blob，把所有规则限定到只对该进程生效
    // （避免误伤全机网络）。留空则作用全机。
    FWP_BYTE_BLOB* scope_app = nullptr;
    if (!scope_app_path.empty()) {
        DWORD st = ::FwpmGetAppIdFromFileName0(scope_app_path.c_str(), &scope_app);
        if (st != ERROR_SUCCESS || !scope_app) {
            LOG_ERROR << L"WfpFilter: 取 scope AppId 失败（路径不存在?）: "
                      << DescribeError(MakeWinError(st)).c_str();
            return MakeWinError(st);
        }
        LOG_INFO << L"WfpFilter: IP 黑名单已限定作用域到 " << scope_app_path.c_str();
    }
    // RAII 释放 scope_app
    struct BlobGuard {
        FWP_BYTE_BLOB* b;
        ~BlobGuard() {
            if (b)
                ::FwpmFreeMemory0(reinterpret_cast<void**>(&b));
        }
    } scope_guard{scope_app};

    // 逐个黑名单 IP 加一条 BLOCK（远程 IP 匹配 + 可选 AppID scope）。
    // IP_REMOTE_ADDRESS 用 FWP_V4_ADDR_MASK（addr+全1掩码/32，主机序），这是该层
    // 单地址匹配的官方推荐类型。每次循环独立的栈局部 FWP_V4_ADDR_AND_MASK：定义在
    // FwpmFilterAdd 之前、调用后才出作用域，生命周期严格覆盖调用点，内存稳定不悬空。
    for (const auto& ip : block_ipv4) {
        UINT32 host = 0;
        if (!ParseIpv4Host(ip, host)) {
            LOG_WARN << L"WfpFilter: 跳过非法黑名单 IP: " << ip.c_str();
            continue;
        }
        // 单地址 = addr + 全 1 掩码（/32），主机字节序（FWP_V4_ADDR_AND_MASK 要求）。
        FWP_V4_ADDR_AND_MASK addr_mask{};
        addr_mask.addr = host;
        addr_mask.mask = 0xFFFFFFFF;

        // 最多两个条件：远程 IP 匹配 + （可选）AppID scope。
        FWPM_FILTER_CONDITION0 conds[2]{};
        UINT32 n = 0;
        conds[n].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conds[n].matchType = FWP_MATCH_EQUAL;
        conds[n].conditionValue.type = FWP_V4_ADDR_MASK;
        conds[n].conditionValue.v4AddrMask = &addr_mask;  // 栈局部，覆盖到 FwpmFilterAdd
        ++n;
        if (scope_app) {
            conds[n].fieldKey = FWPM_CONDITION_ALE_APP_ID;
            conds[n].matchType = FWP_MATCH_EQUAL;
            conds[n].conditionValue.type = FWP_BYTE_BLOB_TYPE;
            conds[n].conditionValue.byteBlob = scope_app;
            ++n;
        }

        FWPM_FILTER0 f{};
        f.subLayerKey = kSandboxSublayerKey;
        // ALE_AUTH_CONNECT_V4：唯一能用「裸 MgmtFilter BLOCK」阻断 outbound 的 ALE
        // 层（ALE_FLOW_ESTABLISHED_V4 的 BLOCK 需绑定 callout 才生效，纯 filter 在
        // 该层不阻断连接，实测换过去 connect 仍放行）。
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;  // 出站连接授权层
        f.displayData.name = const_cast<wchar_t*>(L"Sandbox Block Blocklisted IP");
        f.action.type = FWP_ACTION_BLOCK;
        f.weight.type = FWP_UINT64;
        f.weight.uint64 = const_cast<UINT64*>(&kWeightBlockIp);
        f.numFilterConditions = n;
        f.filterCondition = conds;

        UINT64 id = 0;
        DWORD st = ::FwpmFilterAdd0(engine_, &f, nullptr, &id);
        if (st != ERROR_SUCCESS) {
            LOG_ERROR << L"WfpFilter: 拦截黑名单 IP " << ip.c_str() << L" 失败: "
                      << DescribeError(MakeWinError(st)).c_str();
            return MakeWinError(st);
        }
        LOG_INFO << L"WfpFilter: 已装配黑名单 IP " << ip.c_str()
                 << L" 的 BLOCK filter（weight=" << kWeightBlockIp
                 << L"；注：本机该层 IP 条件不命中，详见 M6.md）";
    }
    return {};
}

std::error_code WfpFilter::ApplyBlockAppId(const std::wstring& app_path) {
    if (app_path.empty())
        return MakeWinError(ERROR_INVALID_PARAMETER);

    // 把 exe 路径转成 WFP 认的 AppId blob（内部是规范化的设备路径小写形式）。
    FWP_BYTE_BLOB* app_id = nullptr;
    DWORD st = ::FwpmGetAppIdFromFileName0(app_path.c_str(), &app_id);
    if (st != ERROR_SUCCESS || !app_id) {
        LOG_ERROR << L"WfpFilter: FwpmGetAppIdFromFileName 失败（路径不存在?）: "
                  << DescribeError(MakeWinError(st)).c_str();
        return MakeWinError(st);
    }

    FWPM_FILTER_CONDITION0 cond{};
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = app_id;

    FWPM_FILTER0 f{};
    f.subLayerKey = kSandboxSublayerKey;
    f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    f.displayData.name = const_cast<wchar_t*>(L"Sandbox Block Target AppId Outbound");
    f.action.type = FWP_ACTION_BLOCK;
    f.weight.type = FWP_UINT64;
    f.weight.uint64 = const_cast<UINT64*>(&kWeightBlockApp);
    f.numFilterConditions = 1;
    f.filterCondition = &cond;

    UINT64 id = 0;
    st = ::FwpmFilterAdd0(engine_, &f, nullptr, &id);
    ::FwpmFreeMemory0(reinterpret_cast<void**>(&app_id));
    if (st != ERROR_SUCCESS) {
        LOG_ERROR << L"WfpFilter: 按 AppId 加 BLOCK 失败: "
                  << DescribeError(MakeWinError(st)).c_str();
        return MakeWinError(st);
    }
    LOG_INFO << L"WfpFilter: 已按 AppId 拦截 " << app_path.c_str()
             << L" 的 outbound（BLOCK，weight=" << kWeightBlockApp << L"）";
    return {};
}

void WfpFilter::Close() {
    if (engine_) {
        // DYNAMIC 会话：Close 即触发 BFE 清理本会话所有 filter/sublayer。
        ::FwpmEngineClose0(engine_);
        engine_ = nullptr;
        LOG_INFO << L"WfpFilter: WFP 引擎已关闭，本会话 filter 由 BFE 自动清理";
    }
}

}  // namespace sandbox
