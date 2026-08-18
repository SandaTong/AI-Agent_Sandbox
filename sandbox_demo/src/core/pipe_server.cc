// -----------------------------------------------------------------------------
// core/pipe_server.cc
// -----------------------------------------------------------------------------
#include "core/pipe_server.h"

#include <sddl.h>  // ConvertStringSecurityDescriptorToSecurityDescriptorW

#include <cstring>
#include <cwctype>  // towupper
#include <vector>

#include "common/logger.h"
#include "common/win_error.h"

#pragma comment(lib, "advapi32.lib")

namespace sandbox {

namespace {

// M8 默认策略：不显式 SetFilePolicy 时用它，等价于 M3 的"单个只读目录"行为，
// 保证 M3 demo 走本类时行为不变。M8 demo 会显式配置多规则策略覆盖它。
constexpr const wchar_t* kDefaultReadOnlyDir = L"C:\\sandbox_share\\";

// 把路径转成"大写 + 规范化前缀比较用"的形式。仅用于和已大写的规则前缀比较。
std::wstring ToUpper(std::wstring s) {
    for (auto& c : s)
        c = static_cast<wchar_t>(::towupper(c));
    return s;
}

// 【M8 核心安全点：先开句柄，再由内核回吐真实路径做校验，防 TOCTOU】
//   传统做法是"先对字符串路径做白名单判断，再 CreateFileW 打开"。但字符串和
//   真正打开的对象之间存在检查时机差（TOCTOU）：symlink / 目录联结 / 8.3 短名 /
//   ADS(::$DATA) / 相对分量 等都能让"看起来在白名单里的字符串"实际指向白名单外
//   的文件。攻击者可在校验通过后、打开前把路径换掉。
//   M8 做法：先用请求的 disposition 打开句柄，再用 GetFinalPathNameByHandleW
//   让内核回吐这个句柄**真正指向**的规范化全路径（已解析 symlink / junction /
//   短名，统一大小写为磁盘真实大小写），拿这个"事后真身"去比白名单。校验对象
//   和最终使用对象是同一个内核文件对象，杜绝检查时机攻击。
//   返回 true 且 out_final 填入 \\?\ 前缀去掉后的规范全路径（大写）。
[[nodiscard]] bool QueryFinalPath(HANDLE file, std::wstring& out_final) {
    // 先问长度。VOLUME_NAME_DOS 返回 C:\... 形式（去掉 \\?\ 前缀更好比较）。
    DWORD len = ::GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (len == 0)
        return false;
    std::wstring buf(len, L'\0');
    DWORD got = ::GetFinalPathNameByHandleW(file, buf.data(), len, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (got == 0 || got >= len)
        return false;
    buf.resize(got);
    // GetFinalPathNameByHandleW 通常返回 \\?\C:\... 前缀，去掉它便于和 C:\ 前缀规则比。
    constexpr const wchar_t* kDosPrefix = L"\\\\?\\";
    if (buf.compare(0, 4, kDosPrefix) == 0)
        buf.erase(0, 4);
    out_final = ToUpper(std::move(buf));
    return true;
}

// 把 AccessMode 翻译成收敛过的 Win32 dwDesiredAccess。只认这三种，绝不透传
// target 传来的裸权限位（防 WRITE_DAC/WRITE_OWNER/GENERIC_ALL 等危险请求）。
DWORD ToDesiredAccess(ipc::AccessMode m) {
    switch (m) {
        case ipc::AccessMode::kReadWrite:
            return GENERIC_READ | GENERIC_WRITE;
        case ipc::AccessMode::kWrite:
            return GENERIC_WRITE;
        case ipc::AccessMode::kRead:
        default:
            return GENERIC_READ;
    }
}

DWORD ToCreationDisposition(ipc::Disposition d) {
    switch (d) {
        case ipc::Disposition::kOpenAlways:
            return OPEN_ALWAYS;
        case ipc::Disposition::kCreateAlways:
            return CREATE_ALWAYS;
        case ipc::Disposition::kOpenExisting:
        default:
            return OPEN_EXISTING;
    }
}

bool WantsWrite(ipc::AccessMode m) {
    return m == ipc::AccessMode::kReadWrite || m == ipc::AccessMode::kWrite;
}

// 请求侧字符串的粗筛（正式判定以 QueryFinalPath 的事后真身为准，这里只挡明显
// 非法输入，减少无谓的 CreateFileW）。
[[nodiscard]] bool PrefilterPath(const std::wstring& path) {
    if (path.empty() || path.size() > ipc::kMaxPathChars)
        return false;
    // 拒绝含 ".." 的路径（防 C:\sandbox_share\..\..\Windows\ 目录穿越）。
    // 注意这是"粗筛"，真正的防穿越靠 QueryFinalPath 事后真身校验。
    if (path.find(L"..") != std::wstring::npos)
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

void PipeServer::SetFilePolicy(std::vector<FilePolicyRule> rules) {
    // 规范化每条规则的前缀：统一大写、确保以反斜杠结尾（前缀匹配才准确）。
    for (auto& r : rules) {
        r.dir_prefix = ToUpper(r.dir_prefix);
        if (!r.dir_prefix.empty() && r.dir_prefix.back() != L'\\')
            r.dir_prefix.push_back(L'\\');
    }
    policy_ = std::move(rules);
    LOG_INFO << L"PipeServer: 已设置文件策略，规则数=" << policy_.size();
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

    auto reply = [&](ipc::ResultCode rc) {
        resp.result = static_cast<uint32_t>(rc);
        return SendResponse(pipe_.get(), ipc::MsgType::kOpenFileResponse, resp);
    };

    // ---- 解析请求 body（兼容 M3 v1 只有 path_chars，与 M8 v2 带 access/dispo）----
    if (hdr.payload_size < ipc::kOpenFileRequestV1Size) {
        return reply(ipc::ResultCode::kBadRequest);
    }
    // 先读 path_chars（v1/v2 共有的第一个字段）。
    uint32_t path_chars = 0;
    std::memcpy(&path_chars, payload, sizeof(uint32_t));

    // 判断是 v1 还是 v2：v2 body 至少有完整的 OpenFileRequest(12B)。
    ipc::AccessMode access = ipc::AccessMode::kRead;
    ipc::Disposition dispo = ipc::Disposition::kOpenExisting;
    uint32_t fixed_body = ipc::kOpenFileRequestV1Size;  // v1 默认
    const bool is_v2 = hdr.payload_size >= sizeof(ipc::OpenFileRequest) +
                                               sizeof(wchar_t);  // 至少 12 + 1 字符
    if (is_v2) {
        ipc::OpenFileRequest req{};
        std::memcpy(&req, payload, sizeof(req));
        path_chars = req.path_chars;
        // 只认合法枚举值，非法一律降级为最保守的只读/OpenExisting（不信任 target）。
        if (req.access_mode <= static_cast<uint32_t>(ipc::AccessMode::kWrite))
            access = static_cast<ipc::AccessMode>(req.access_mode);
        if (req.disposition <= static_cast<uint32_t>(ipc::Disposition::kCreateAlways))
            dispo = static_cast<ipc::Disposition>(req.disposition);
        fixed_body = sizeof(ipc::OpenFileRequest);
    }

    // path_chars 与 payload_size 自洽校验（绝不信任单一字段）。
    const size_t expected = fixed_body + static_cast<size_t>(path_chars) * sizeof(wchar_t);
    if (path_chars == 0 || path_chars > ipc::kMaxPathChars || expected != hdr.payload_size) {
        LOG_WARN << L"PipeServer: OpenFile 请求 path_chars 非法";
        return reply(ipc::ResultCode::kBadRequest);
    }

    const auto* path_ptr = reinterpret_cast<const wchar_t*>(
        static_cast<const uint8_t*>(payload) + fixed_body);
    std::wstring path(path_ptr, path_chars);

    // ---- 请求侧粗筛（长度 / .. 穿越）----
    if (!PrefilterPath(path)) {
        LOG_WARN << L"PipeServer: OpenFile 路径粗筛不通过: " << path.c_str();
        return reply(ipc::ResultCode::kDenied);
    }

    const bool wants_write = WantsWrite(access);
    LOG_INFO << L"PipeServer: OpenFile 请求 path=" << path.c_str() << L" access="
             << static_cast<uint32_t>(access) << L" dispo=" << static_cast<uint32_t>(dispo);

    // ---- broker 代劳打开文件（用收敛过的 access + 请求的 disposition）----
    // 关键顺序：先打开，再用 GetFinalPathNameByHandle 拿事后真身校验白名单（防
    // TOCTOU）。写场景 disposition 可能是 OPEN_ALWAYS/CREATE_ALWAYS，会真的创建
    // 文件——所以创建前必须先确认目标目录是"可写规则"覆盖的。为避免"先创建了白名
    // 单外文件再拒绝"的副作用，这里对写请求先用 OPEN_EXISTING 探一次真身校验，
    // 通过后再按真实 disposition 打开。读请求直接按 OPEN_EXISTING 打开即可。
    DWORD desired = ToDesiredAccess(access);
    DWORD share = FILE_SHARE_READ | (wants_write ? 0 : FILE_SHARE_WRITE);

    // 第一次打开：无论读写都先以 OPEN_EXISTING + 请求的 access 试开，用于拿真身。
    //   * 若文件不存在且是纯创建请求(CREATE_ALWAYS/OPEN_ALWAYS)，这次会失败，
    //     我们退化到"用父目录真身校验"分支。
    HANDLE probe = ::CreateFileW(path.c_str(), desired, share, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
    std::wstring final_path;
    bool need_verify_via_parent = false;
    if (probe != INVALID_HANDLE_VALUE) {
        ScopedHandle probe_guard(probe);
        if (!QueryFinalPath(probe, final_path)) {
            LOG_WARN << L"PipeServer: GetFinalPathNameByHandle 失败";
            return reply(ipc::ResultCode::kInternalError);
        }
    } else {
        DWORD gle = ::GetLastError();
        if (gle == ERROR_FILE_NOT_FOUND && dispo != ipc::Disposition::kOpenExisting) {
            // 允许创建的场景：文件还不存在，用父目录做真身校验（对父目录开句柄）。
            need_verify_via_parent = true;
        } else {
            LOG_WARN << L"PipeServer: broker 打开文件失败: " << DescribeError(MakeWinError(gle)).c_str();
            return reply(ipc::ResultCode::kInternalError);
        }
    }

    if (need_verify_via_parent) {
        // 取父目录：截到最后一个反斜杠。
        std::wstring parent = path;
        size_t slash = parent.find_last_of(L'\\');
        if (slash == std::wstring::npos)
            return reply(ipc::ResultCode::kDenied);
        parent.erase(slash + 1);
        HANDLE dir = ::CreateFileW(parent.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (dir == INVALID_HANDLE_VALUE) {
            LOG_WARN << L"PipeServer: 打开父目录失败: " << DescribeError(LastError()).c_str();
            return reply(ipc::ResultCode::kInternalError);
        }
        ScopedHandle dir_guard(dir);
        std::wstring parent_final;
        if (!QueryFinalPath(dir, parent_final)) {
            return reply(ipc::ResultCode::kInternalError);
        }
        // 用父目录真身拼回文件名当作 final_path（末尾补上文件名分量的大写）。
        std::wstring file_name = path.substr(slash + 1);
        if (parent_final.back() != L'\\')
            parent_final.push_back(L'\\');
        final_path = parent_final + ToUpper(file_name);
    }

    // ---- 策略判定：事后真身命中哪条规则 + 该规则是否允许本次 access ----
    const FilePolicyRule* matched = nullptr;
    if (policy_.empty()) {
        // 默认策略：单个只读目录（兼容 M3）。
        static const std::wstring kDefault = ToUpper(kDefaultReadOnlyDir);
        if (final_path.compare(0, kDefault.size(), kDefault) == 0 && !wants_write) {
            static const FilePolicyRule kDefRule{kDefault, false};
            matched = &kDefRule;
        }
    } else {
        for (const auto& r : policy_) {
            if (r.dir_prefix.size() <= final_path.size() &&
                final_path.compare(0, r.dir_prefix.size(), r.dir_prefix) == 0) {
                matched = &r;
                break;
            }
        }
    }

    if (!matched) {
        LOG_WARN << L"PipeServer: 拒绝越权路径(真身): " << final_path.c_str();
        return reply(ipc::ResultCode::kDenied);
    }
    if (wants_write && !matched->allow_write) {
        LOG_WARN << L"PipeServer: 命中只读规则但请求写，拒绝: " << final_path.c_str();
        return reply(ipc::ResultCode::kAccessNotAllowed);
    }

    // ---- 真正打开（按请求的 disposition；此时白名单已用真身确认）----
    HANDLE file = ::CreateFileW(path.c_str(), desired, share, nullptr, ToCreationDisposition(dispo),
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        LOG_WARN << L"PipeServer: 最终打开失败: " << DescribeError(LastError()).c_str();
        return reply(ipc::ResultCode::kInternalError);
    }
    ScopedHandle file_guard(file);

    // ---- 关键：DuplicateHandle 把句柄复制进 target 的 handle table ----
    // M8 增强：不再用 DUPLICATE_SAME_ACCESS 原样复制，而是按本次策略允许的最小
    // access 显式指定——把 broker 句柄可能带的多余权限位裁掉，交给 target 的句柄
    // 只有它这次真正需要的权限（最小权限原则，即使 target 被攻破也放大不了权限）。
    DWORD dup_access = wants_write ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
    HANDLE dup = nullptr;
    if (!::DuplicateHandle(::GetCurrentProcess(), file, target_process, &dup, dup_access, FALSE, 0)) {
        LOG_ERROR << L"PipeServer: DuplicateHandle 到 target 失败: "
                  << DescribeError(LastError()).c_str();
        return reply(ipc::ResultCode::kInternalError);
    }

    resp.result = static_cast<uint32_t>(ipc::ResultCode::kOk);
    resp.dup_handle = reinterpret_cast<uint64_t>(dup);
    LOG_INFO << L"PipeServer: 已代劳打开(真身校验通过) " << final_path.c_str()
             << L" 并 DuplicateHandle 到 target (dup=" << resp.dup_handle << L")";
    return SendResponse(pipe_.get(), ipc::MsgType::kOpenFileResponse, resp);
}

}  // namespace sandbox
