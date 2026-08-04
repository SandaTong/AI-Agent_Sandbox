#pragma once
#include <windows.h>
#include <string>
#include <system_error>

// RAII wrapper for HANDLE
class ScopedHandle {
    HANDLE handle_{INVALID_HANDLE_VALUE};
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE h) : handle_(h) {}
    ~ScopedHandle() { close(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
  if (this != &other) {
          close();
  handle_ = other.handle_;
        other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    HANDLE get() const { return handle_; }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != NULL; }

    void close() {
        if (valid()) {
       CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }
};

// Sandbox
class Sandbox {
public:
    Sandbox();
    ~Sandbox();

    // Launch a restricted process
    std::error_code launch(const std::wstring& exe_path,
           const std::wstring& cmdline = L"");

private:
    ScopedHandle job_;
    ScopedHandle restricted_token_;

    std::error_code create_job();
    std::error_code create_restricted_token();
    std::error_code launch_process(const std::wstring& exe_path,
     const std::wstring& cmdline);
};
