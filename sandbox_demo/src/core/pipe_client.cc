// -----------------------------------------------------------------------------
// core/pipe_client.cc
// -----------------------------------------------------------------------------
#include "core/pipe_client.h"

#include <cstring>
#include <vector>

#include "common/logger.h"
#include "common/win_error.h"

namespace sandbox {

namespace {

std::wstring FullPipeName() {
    std::wstring n = L"\\\\.\\pipe\\";
    n += ipc::kPipeShortName;
    return n;
}

// 写一条消息（头 + payload 已拼好）。
std::error_code WriteAll(HANDLE pipe, const void* data, DWORD size) {
    DWORD written = 0;
    if (!::WriteFile(pipe, data, size, &written, nullptr) || written != size) {
        return LastError();
    }
    return {};
}

// 读一条完整消息到 buf（消息模式，一次 ReadFile 拿整条）。
std::error_code ReadAll(HANDLE pipe, std::vector<uint8_t>& buf) {
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

}  // namespace

std::error_code PipeClient::Connect(DWORD timeout_ms) {
    const std::wstring name = FullPipeName();
    const DWORD deadline = ::GetTickCount() + timeout_ms;

    for (;;) {
        HANDLE h = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            // 切到消息读模式，和 server 的 PIPE_TYPE_MESSAGE 对齐。
            DWORD mode = PIPE_READMODE_MESSAGE;
            if (!::SetNamedPipeHandleState(h, &mode, nullptr, nullptr)) {
                DWORD gle = ::GetLastError();
                ::CloseHandle(h);
                return MakeWinError(gle);
            }
            pipe_.reset(h);
            LOG_INFO << L"PipeClient: 已连上 broker 管道";
            return {};
        }

        DWORD gle = ::GetLastError();
        if (gle == ERROR_ACCESS_DENIED) {
            // 这是"沙箱 IPC 授权"未生效的典型信号——broker 没给本 target 的
            // Package SID 授权连接权限。直接返回，不重试。
            LOG_ERROR << L"PipeClient: 连接被拒 (ACCESS_DENIED)——broker 未授权本 "
                         L"AppContainer 的 Package SID";
            return MakeWinError(gle);
        }
        if (gle == ERROR_PIPE_BUSY) {
            // 管道实例被占用，等一下再试。
            if (::GetTickCount() > deadline)
                return MakeWinError(ERROR_PIPE_BUSY);
            ::WaitNamedPipeW(name.c_str(), 200);
            continue;
        }
        if (gle == ERROR_FILE_NOT_FOUND) {
            // broker 还没建好管道，稍等重试。
            if (::GetTickCount() > deadline)
                return MakeWinError(ERROR_FILE_NOT_FOUND);
            ::Sleep(100);
            continue;
        }
        return MakeWinError(gle);
    }
}

std::error_code PipeClient::Ping() {
    if (!pipe_.valid())
        return MakeWinError(ERROR_INVALID_HANDLE);

    ipc::MsgHeader hdr{};
    hdr.magic = ipc::kProtocolMagic;
    hdr.version = ipc::kProtocolVersion;
    hdr.type = static_cast<uint32_t>(ipc::MsgType::kPingRequest);
    hdr.payload_size = 0;

    if (auto ec = WriteAll(pipe_.get(), &hdr, sizeof(hdr)))
        return ec;

    std::vector<uint8_t> buf;
    if (auto ec = ReadAll(pipe_.get(), buf))
        return ec;

    ipc::MsgHeader rh{};
    std::memcpy(&rh, buf.data(), sizeof(rh));
    if (!ipc::ValidateHeader(rh) ||
        static_cast<ipc::MsgType>(rh.type) != ipc::MsgType::kPongResponse) {
        return MakeWinError(ERROR_INVALID_DATA);
    }
    return {};
}

std::error_code PipeClient::RequestOpenFile(const std::wstring& path, HANDLE& out_handle,
                                            ipc::ResultCode& out_result) {
    // M3 兼容语义：只读 + 打开已存在。转调 M8 完整版。
    return RequestOpenFileEx(path, ipc::AccessMode::kRead, ipc::Disposition::kOpenExisting,
                             out_handle, out_result);
}

std::error_code PipeClient::RequestOpenFileEx(const std::wstring& path, ipc::AccessMode access,
                                              ipc::Disposition disposition, HANDLE& out_handle,
                                              ipc::ResultCode& out_result) {
    out_handle = nullptr;
    out_result = ipc::ResultCode::kInternalError;

    if (!pipe_.valid())
        return MakeWinError(ERROR_INVALID_HANDLE);
    if (path.empty() || path.size() > ipc::kMaxPathChars)
        return MakeWinError(ERROR_INVALID_PARAMETER);

    // ---- 组请求消息：头 + OpenFileRequest(v2: path_chars+access+dispo) + 路径 ----
    const uint32_t path_chars = static_cast<uint32_t>(path.size());
    const uint32_t payload_size =
        sizeof(ipc::OpenFileRequest) + path_chars * sizeof(wchar_t);

    std::vector<uint8_t> out(sizeof(ipc::MsgHeader) + payload_size);
    auto* h = reinterpret_cast<ipc::MsgHeader*>(out.data());
    h->magic = ipc::kProtocolMagic;
    h->version = ipc::kProtocolVersion;  // v2
    h->type = static_cast<uint32_t>(ipc::MsgType::kOpenFileRequest);
    h->payload_size = payload_size;

    auto* body = reinterpret_cast<ipc::OpenFileRequest*>(out.data() + sizeof(ipc::MsgHeader));
    body->path_chars = path_chars;
    body->access_mode = static_cast<uint32_t>(access);
    body->disposition = static_cast<uint32_t>(disposition);
    std::memcpy(out.data() + sizeof(ipc::MsgHeader) + sizeof(ipc::OpenFileRequest), path.data(),
                path_chars * sizeof(wchar_t));

    if (auto ec = WriteAll(pipe_.get(), out.data(), static_cast<DWORD>(out.size())))
        return ec;

    // ---- 收响应 ----
    std::vector<uint8_t> buf;
    if (auto ec = ReadAll(pipe_.get(), buf))
        return ec;

    ipc::MsgHeader rh{};
    std::memcpy(&rh, buf.data(), sizeof(rh));
    if (!ipc::ValidateHeader(rh) ||
        static_cast<ipc::MsgType>(rh.type) != ipc::MsgType::kOpenFileResponse ||
        buf.size() != sizeof(ipc::MsgHeader) + sizeof(ipc::OpenFileResponse)) {
        return MakeWinError(ERROR_INVALID_DATA);
    }

    ipc::OpenFileResponse resp{};
    std::memcpy(&resp, buf.data() + sizeof(ipc::MsgHeader), sizeof(resp));
    out_result = static_cast<ipc::ResultCode>(resp.result);
    if (out_result == ipc::ResultCode::kOk) {
        // broker 已把文件句柄 DuplicateHandle 进本进程，dup_handle 在这里直接可用。
        out_handle = reinterpret_cast<HANDLE>(resp.dup_handle);
    }
    return {};
}

}  // namespace sandbox
