// -----------------------------------------------------------------------------
// core/pipe_server.cc
// -----------------------------------------------------------------------------
#include "core/pipe_server.h"

#include <sddl.h>  // ConvertStringSecurityDescriptorToSecurityDescriptorW

#include <cstring>
#include <vector>

#include "common/logger.h"
#include "common/win_error.h"

#pragma comment(lib, "advapi32.lib")

namespace sandbox {

namespace {

// M3 演示用的"文件访问白名单"：只允许 target 请 broker 打开这个目录下的文件。
// 生产上这里会是一套完整的策略引擎（前缀匹配 + 规范化 + 大小写折叠 + 符号
// 链接解析）。M3 用最简单的"前缀 + 拒 .. 逃逸"演示核心思想。
constexpr const wchar_t* kAllowedDirPrefix = L"C:\\sandbox_share\\";

// 把 broker 收到的路径规范化并做白名单校验。返回 true 才允许打开。
// 关键安全点：
//   1. 长度上限（防超长路径 DoS）——调用前已由 payload_size 保证
//   2. 拒绝含 ".." 的路径（防 C:\sandbox_share\..\..\Windows\ 目录穿越）
//   3. 必须以白名单前缀开头（大小写不敏感比较）
[[nodiscard]] bool IsPathAllowed(const std::wstring& path) {
    if (path.empty() || path.size() > ipc::kMaxPathChars)
        return false;
    // 拒绝目录穿越
    if (path.find(L"..") != std::wstring::npos)
        return false;
    // 前缀白名单（大小写不敏感）
    const size_t prefix_len = wcslen(kAllowedDirPrefix);
    if (path.size() < prefix_len)
        return false;
    if (_wcsnicmp(path.c_str(), kAllowedDirPrefix, prefix_len) != 0)
        return false;
    return true;
}

// 阻塞读一条完整消息（头 + payload）到 buf。返回读到的总字节数或错误。
// 消息模式下一次 ReadFile 拿一整条消息；但为稳妥，先读头再按 payload_size
// 读体（若一次 ReadFile 已带出全部则直接用）。
std::error_code ReadMessage(HANDLE pipe, std::vector<uint8_t>& buf) {
    // 先给一个足够大的缓冲（头 + 最大 payload），消息模式一次读整条。
    buf.resize(sizeof(ipc::MsgHeader) + ipc::kMaxPayloadBytes);
    DWORD read = 0;
    if (!::ReadFile(pipe, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr)) {
        return LastError();
    }
    if (read < sizeof(ipc::MsgHeader)) {
        return MakeWinError(ERROR_INVALID_DATA);
    }
    buf.resize(read);
    return {};
}

// 写一条消息（头 + payload 已拼在 buf 里）。
std::error_code WriteMessage(HANDLE pipe, const void* data, DWORD size) {
    DWORD written = 0;
    if (!::WriteFile(pipe, data, size, &written, nullptr) || written != size) {
        return LastError();
    }
    return {};
}

// 组一条只含定长响应体的消息并发出去。
template <typename BodyT>
std::error_code SendResponse(HANDLE pipe, ipc::MsgType type, const BodyT& body) {
    std::vector<uint8_t> out(sizeof(ipc::MsgHeader) + sizeof(BodyT));
    auto* h = reinterpret_cast<ipc::MsgHeader*>(out.data());
    h->magic = ipc::kProtocolMagic;
    h->version = ipc::kProtocolVersion;
    h->type = static_cast<uint32_t>(type);
    h->payload_size = sizeof(BodyT);
    std::memcpy(out.data() + sizeof(ipc::MsgHeader), &body, sizeof(BodyT));
    return WriteMessage(pipe, out.data(), static_cast<DWORD>(out.size()));
}

}  // namespace

std::error_code PipeServer::Create(const std::wstring& package_sid_sddl) {
    // ---- 构造 SDDL：DACL(谁能连) + SACL(mandatory label，允许低 IL 访问) ----
    //
    // 【D: 段 = DACL，按 SID 授权】
    //   SY = SYSTEM 全权，BA = Builtin Administrators 全权。
    //   WD = Everyone —— 之所以放 Everyone，是因为 target 可能是 Low IL 的普通
    //   token（M0/M1 场景，不带 AppContainer），它既不是 SYSTEM 也不是 Admin，
    //   一旦我们显式写了 DACL，就没有默认的"创建者授权"兜底了，不放 Everyone
    //   的话 Low IL target 不匹配任何 ACE → CreateFileW 得 ACCESS_DENIED(gle=5)。
    //   ⚠️ 生产上不应放 Everyone（等于把管道对全机开放，制造新攻击面），而应
    //   精确到目标进程 token 的 user SID 或 AppContainer Package SID（最小授权）。
    //   demo 为了让不带 --ac 的组也能连，这里用 Everyone。
    //   带 --ac 时额外追加一条针对 Package SID 的授权（AppContainer 专用路径）。
    //
    // 【S: 段 = SACL，这里放 mandatory labelACE】
    //   ML = mandatory label；LW = Low mandatory level (S-1-16-4096)；NW = No-
    //   Write-Up 策略位。Windows 访问检查是**双门**（DACL AND Mandatory Label，
    //   见 M1 § 七坑 #4）：管道默认继承创建者(Medium IL)的 label，Low IL target
    //   NoWriteUp 到 Medium label 会被一票否决。把管道 label 降到 Low，Low IL
    //   主体才能通过完整性检查。这是"Low IL / AppContainer 能连管道"的另一半。
    std::wstring sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)";
    if (!package_sid_sddl.empty()) {
        sddl += L"(A;;GA;;;";
        sddl += package_sid_sddl;  // 形如 S-1-15-2-...
        sddl += L")";
        LOG_INFO << L"PipeServer: 管道 SD 追加授权 AppContainer SID " << package_sid_sddl.c_str();
    }
    sddl += L"S:(ML;;NW;;;LW)";  // mandatory label 降到 Low

    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &psd,
                                                                nullptr)) {
        LOG_ERROR << L"PipeServer: SDDL 解析失败: " << DescribeError(LastError()).c_str();
        return LastError();
    }
    // psd 需在函数结束前 LocalFree；用 RAII lambda 兜底。
    struct SdGuard {
        PSECURITY_DESCRIPTOR p;
        ~SdGuard() {
            if (p)
                ::LocalFree(p);
        }
    } sd_guard{psd};

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = psd;
    sa.bInheritHandle = FALSE;

    // \\.\pipe\<shortname>
    std::wstring full_name = L"\\\\.\\pipe\\";
    full_name += ipc::kPipeShortName;

    HANDLE h = ::CreateNamedPipeW(
        full_name.c_str(),
        PIPE_ACCESS_DUPLEX,                                     // 双向
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,  // 消息模式 + 阻塞
        1,                                               // nMaxInstances：M3 只服务一个 target
        sizeof(ipc::MsgHeader) + ipc::kMaxPayloadBytes,  // out buffer
        sizeof(ipc::MsgHeader) + ipc::kMaxPayloadBytes,  // in buffer
        0,                                               // 默认超时
        &sa);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_ERROR << L"PipeServer: CreateNamedPipeW 失败: " << DescribeError(LastError()).c_str();
        return LastError();
    }
    pipe_.reset(h);
    LOG_INFO << L"PipeServer: 管道已就绪 " << full_name.c_str();
    return {};
}

std::error_code PipeServer::WaitForClient() {
    if (!pipe_.valid())
        return MakeWinError(ERROR_INVALID_HANDLE);
    // ConnectNamedPipe：阻塞等 target 连上。如果 target 在我们调用前就连上了，
    // 返回 FALSE 且 gle==ERROR_PIPE_CONNECTED，这也算成功。
    if (!::ConnectNamedPipe(pipe_.get(), nullptr)) {
        DWORD gle = ::GetLastError();
        if (gle != ERROR_PIPE_CONNECTED) {
            LOG_ERROR << L"PipeServer: ConnectNamedPipe 失败: "
                      << DescribeError(MakeWinError(gle)).c_str();
            return MakeWinError(gle);
        }
    }
    LOG_INFO << L"PipeServer: target 已连接";
    return {};
}

std::error_code PipeServer::ServeOneRequest(HANDLE target_process) {
    std::vector<uint8_t> buf;
    if (auto ec = ReadMessage(pipe_.get(), buf)) {
        return ec;  // 通常是对端断开（ERROR_BROKEN_PIPE）
    }

    ipc::MsgHeader hdr{};
    std::memcpy(&hdr, buf.data(), sizeof(hdr));

    // 铁律：不信任对端，先校验头。
    if (!ipc::ValidateHeader(hdr)) {
        LOG_WARN << L"PipeServer: 收到非法消息头 (magic/version/size)，丢弃";
        return MakeWinError(ERROR_INVALID_DATA);
    }
    // payload 实际字节数必须和头声明一致（防止 target 声明大 payload 但只发一点）。
    if (buf.size() != sizeof(ipc::MsgHeader) + hdr.payload_size) {
        LOG_WARN << L"PipeServer: payload_size 与实际字节数不符，丢弃";
        return MakeWinError(ERROR_INVALID_DATA);
    }

    const void* payload = buf.data() + sizeof(ipc::MsgHeader);
    switch (static_cast<ipc::MsgType>(hdr.type)) {
        case ipc::MsgType::kOpenFileRequest:
            return HandleOpenFile(hdr, payload, target_process);
        case ipc::MsgType::kPingRequest:
            return HandlePing(hdr);
        default:
            LOG_WARN << L"PipeServer: 未知 MsgType=" << hdr.type << L"，丢弃";
            return MakeWinError(ERROR_INVALID_DATA);
    }
}

std::error_code PipeServer::HandlePing(const ipc::MsgHeader&) {
    ipc::OpenFileResponse dummy{};  // pong 无实际体，复用一个空响应结构占位
    dummy.result = static_cast<uint32_t>(ipc::ResultCode::kOk);
    dummy.dup_handle = 0;
    LOG_INFO << L"PipeServer: 收到 Ping，回 Pong";
    return SendResponse(pipe_.get(), ipc::MsgType::kPongResponse, dummy);
}

std::error_code PipeServer::HandleOpenFile(const ipc::MsgHeader& hdr, const void* payload,
                                           HANDLE target_process) {
    ipc::OpenFileResponse resp{};
    resp.dup_handle = 0;

    // 解析变长路径，全程做边界校验。
    if (hdr.payload_size < sizeof(ipc::OpenFileRequest)) {
        resp.result = static_cast<uint32_t>(ipc::ResultCode::kBadRequest);
        return SendResponse(pipe_.get(), ipc::MsgType::kOpenFileResponse, resp);
    }
    ipc::OpenFileRequest req{};
    std::memcpy(&req, payload, sizeof(req));

    // path_chars 与 payload_size 自洽校验（绝不信任单一字段）。
    const size_t expected =
        sizeof(ipc::OpenFileRequest) + static_cast<size_t>(req.path_chars) * sizeof(wchar_t);
    if (req.path_chars == 0 || req.path_chars > ipc::kMaxPathChars ||
        expected != hdr.payload_size) {
        LOG_WARN << L"PipeServer: OpenFile 请求 path_chars 非法";
        resp.result = static_cast<uint32_t>(ipc::ResultCode::kBadRequest);
        return SendResponse(pipe_.get(), ipc::MsgType::kOpenFileResponse, resp);
    }

    const auto* path_ptr = reinterpret_cast<const wchar_t*>(static_cast<const uint8_t*>(payload) +
                                                            sizeof(ipc::OpenFileRequest));
    std::wstring path(path_ptr, req.path_chars);

    // ---- 策略检查：路径白名单 ----
    if (!IsPathAllowed(path)) {
        LOG_WARN << L"PipeServer: 拒绝打开越权路径: " << path.c_str();
        resp.result = static_cast<uint32_t>(ipc::ResultCode::kDenied);
        return SendResponse(pipe_.get(), ipc::MsgType::kOpenFileResponse, resp);
    }

    // ---- broker 代劳打开文件（只读） ----
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        LOG_WARN << L"PipeServer: broker 打开文件失败: " << DescribeError(LastError()).c_str();
        resp.result = static_cast<uint32_t>(ipc::ResultCode::kInternalError);
        return SendResponse(pipe_.get(), ipc::MsgType::kOpenFileResponse, resp);
    }
    ScopedHandle file_guard(file);  // 复制成功后 broker 侧这个句柄可关闭

    // ---- 关键：DuplicateHandle 把句柄复制进 target 的 handle table ----
    // HANDLE 是进程私有的 handle table 索引，不能直接传数值。必须让内核在
    // target 进程里新建一个指向同一内核对象的句柄，返回的新句柄值才在 target
    // 那边有效。这一步是"broker 代劳 + 交还资源"的核心。
    HANDLE dup = nullptr;
    if (!::DuplicateHandle(::GetCurrentProcess(), file, target_process, &dup, 0, FALSE,
                           DUPLICATE_SAME_ACCESS)) {
        LOG_ERROR << L"PipeServer: DuplicateHandle 到 target 失败: "
                  << DescribeError(LastError()).c_str();
        resp.result = static_cast<uint32_t>(ipc::ResultCode::kInternalError);
        return SendResponse(pipe_.get(), ipc::MsgType::kOpenFileResponse, resp);
    }

    resp.result = static_cast<uint32_t>(ipc::ResultCode::kOk);
    resp.dup_handle = reinterpret_cast<uint64_t>(dup);
    LOG_INFO << L"PipeServer: 已代劳打开 " << path.c_str() << L" 并 DuplicateHandle 到 target (dup="
             << resp.dup_handle << L")";
    return SendResponse(pipe_.get(), ipc::MsgType::kOpenFileResponse, resp);
}

}  // namespace sandbox
