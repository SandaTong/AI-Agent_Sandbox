// -----------------------------------------------------------------------------
// minifilter/mf_ctl.cc
// -----------------------------------------------------------------------------
// 【M9】Minifilter 用户态控制程序：
//   1) 连内核通信端口 MF_PORT_NAME
//   2) 下发敏感路径黑名单策略（命令行传入若干关键词）
//   3) 循环接收内核上报的审计记录并打印（哪个 PID 打开了哪个路径，放行/被拦）
//
// 用法（管理员运行，且 sys 已 fltmc load）:
//   mf_ctl.exe [敏感关键词1] [敏感关键词2] ...
//   例: mf_ctl.exe \sandbox_secret\   passwd
//   不传关键词则只审计不拦截（形态 A）；传了就下发黑名单（形态 B 生效）。
//
// 编译：普通 MSVC 即可（链接 fltlib.lib）。这是用户态程序，不需要 WDK。
// -----------------------------------------------------------------------------
#include <windows.h>
#include <fltuser.h>  // FilterConnectCommunicationPort / FilterGetMessage / FilterSendMessage

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "mf_protocol.h"

#pragma comment(lib, "fltlib.lib")

namespace {

// 收消息时：FltMgr 在我们的结构体前面加一个 FILTER_MESSAGE_HEADER。
// 所以接收缓冲 = 头 + MfAuditRecord。
struct AuditMessage {
    FILTER_MESSAGE_HEADER header;
    MfAuditRecord record;
};

// 把命令行关键词打包成 MfPolicyUpdate 下发给内核。
HRESULT SendPolicy(HANDLE port, const std::vector<std::wstring>& keywords) {
    MfPolicyUpdate upd;
    std::memset(&upd, 0, sizeof(upd));
    upd.msg_type = kMfPolicySet;

    unsigned int n = 0;
    for (const auto& kw : keywords) {
        if (n >= MF_MAX_RULES)
            break;
        unsigned int len = static_cast<unsigned int>(kw.size());
        if (len == 0 || len > MF_MAX_PATH_CHARS - 1)
            continue;
        upd.rules[n].len_chars = len;
        std::memcpy(upd.rules[n].text, kw.c_str(), len * sizeof(wchar_t));
        ++n;
    }
    upd.rule_count = n;

    // FilterSendMessage：用户 -> 内核（对应内核侧 PortMessage 回调）。
    DWORD returned = 0;
    HRESULT hr = ::FilterSendMessage(port, &upd, sizeof(upd), nullptr, 0, &returned);
    if (SUCCEEDED(hr))
        std::wprintf(L"[mf_ctl] 已下发策略：%u 条敏感关键词\n", n);
    else
        std::wprintf(L"[mf_ctl] 下发策略失败 hr=0x%08X\n", hr);
    return hr;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    // ---- 1) 连接内核通信端口 ----
    HANDLE port = nullptr;
    HRESULT hr = ::FilterConnectCommunicationPort(MF_PORT_NAME, 0, nullptr, 0, nullptr, &port);
    if (FAILED(hr)) {
        std::wprintf(L"[mf_ctl] 连接端口失败 hr=0x%08X\n", hr);
        std::wprintf(L"         请确认：① 管理员运行 ② 驱动已加载(fltmc load sandboxmf)\n");
        return 1;
    }
    std::wprintf(L"[mf_ctl] 已连上 Minifilter 通信端口 %ls\n", MF_PORT_NAME);

    // ---- 2) 下发策略（命令行关键词）----
    std::vector<std::wstring> keywords;
    for (int i = 1; i < argc; ++i)
        keywords.push_back(argv[i]);
    if (!keywords.empty()) {
        SendPolicy(port, keywords);
    } else {
        std::wprintf(L"[mf_ctl] 未传关键词：仅审计不拦截（形态 A）。要拦截请传敏感关键词。\n");
    }

    std::wprintf(L"[mf_ctl] 开始接收审计上报，Ctrl+C 退出……\n");
    std::wprintf(L"-----------------------------------------------------------\n");

    // ---- 3) 循环收审计记录 ----
    for (;;) {
        AuditMessage msg;
        std::memset(&msg, 0, sizeof(msg));
        // FilterGetMessage：内核 -> 用户（阻塞等内核 FltSendMessage）。
        hr = ::FilterGetMessage(port, &msg.header, sizeof(msg), nullptr);
        if (FAILED(hr)) {
            std::wprintf(L"[mf_ctl] FilterGetMessage 失败 hr=0x%08X，退出\n", hr);
            break;
        }
        const MfAuditRecord& r = msg.record;
        if (r.msg_type != kMfAudit)
            continue;

        unsigned int n = r.path_chars;
        if (n > MF_MAX_PATH_CHARS - 1)
            n = MF_MAX_PATH_CHARS - 1;
        std::wstring path(r.path, n);

        const wchar_t* tag = (r.verdict == kMfBlocked) ? L"BLOCKED ⭐" : L"allow";
        std::wprintf(L"[audit] pid=%-6u %-9ls %ls\n", r.process_id, tag, path.c_str());
        std::fflush(stdout);
    }

    ::CloseHandle(port);
    return 0;
}
