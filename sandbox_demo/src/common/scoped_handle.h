// -----------------------------------------------------------------------------
// common/scoped_handle.h
// -----------------------------------------------------------------------------
// RAII wrapper for Windows HANDLE, with proper move semantics.
//
// Why we need this:
//   Windows API returns HANDLE everywhere (files, tokens, processes, jobs, ...)
//   and forgetting to CloseHandle() leaks kernel objects. RAII binds the
//   lifetime to a stack variable — same idea as std::unique_ptr for HANDLE.
//
// Design decisions:
//   - Move-only (copies would duplicate ownership and double-close).
//   - Two "invalid" values in Win32: NULL and INVALID_HANDLE_VALUE. We treat
//     both as "no handle" to be safe (some APIs return one, some the other).
//   - noexcept everywhere — moving/closing must never throw.
//
// JD mapping (Windows W1- 进程管控/ 权限收敛):
//   Working with Access Token / Job Object / Process handles requires strict
//   handle hygiene. This class is the base primitive.
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>
#include <utility>

namespace sandbox {

class ScopedHandle {
 public:
    ScopedHandle() noexcept = default;
    explicit ScopedHandle(HANDLE h) noexcept : handle_(h) {}

    ~ScopedHandle() noexcept { close(); }

    // Move-only
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    // Raw access
    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

    // A HANDLE is valid iff it's not NULL AND not INVALID_HANDLE_VALUE.
    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    // Release ownership without closing (rare, e.g. give raw HANDLE to Win32 API
    // that takes ownership). Prefer get() for read-only access.
    [[nodiscard]] HANDLE release() noexcept {
        return std::exchange(handle_, nullptr);
    }

    // Replace the wrapped handle (closes the old one).
    void reset(HANDLE h = nullptr) noexcept {
        if (h != handle_) {
            close();
            handle_ = h;
        }
    }

    // Explicit conversion for `if (handle) { ... }` idiom.
    explicit operator bool() const noexcept { return valid(); }

 private:
    void close() noexcept {
        if (valid()) {
            ::CloseHandle(handle_);
        }
        handle_ = nullptr;
    }

    HANDLE handle_{nullptr};
};

}  // namespace sandbox
