// -----------------------------------------------------------------------------
// common/scoped_handle.h
// -----------------------------------------------------------------------------
// Windows HANDLE 的 RAII 封装（含正确的 move 语义）。
//
// 为什么需要它：
//   Windows API 到处返回 HANDLE（文件、Token、进程、Job……），一旦忘记
//   CloseHandle() 就会泄漏内核对象。RAII 把生命周期绑到栈变量上——和
//   std::unique_ptr 对普通指针做的事同一个思路。
//
// 设计要点：
//   - 只允许移动（拷贝会造成"两个人都拥有同一个 handle"，导致 double-close）。
//   - Win32 里有两种"无效值"：NULL 和 INVALID_HANDLE_VALUE（不同 API 返回不
//     同的那一个）。这里两种都当作"没有 handle"处理，最保险。
//   - 所有函数都 noexcept——move / close 绝不能抛异常。
//
// 对应 JD Windows 方向 W1（进程管控 / 权限收敛）:
//   操作 Access Token / Job Object / 进程句柄时都要求严格的 handle 卫生，
//   这个类是最底层的原语。
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

    // 只允许移动，禁止拷贝
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    // 只读访问原始 handle。
    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

    // 一个 HANDLE 有效，当且仅当它既不是 NULL 也不是 INVALID_HANDLE_VALUE。
    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    // 交出所有权但不关闭（少数场景用，例如把裸 HANDLE 交给某个
    // Win32 API 让它接管）。日常读取用 get() 就够了。
    [[nodiscard]] HANDLE release() noexcept { return std::exchange(handle_, nullptr); }

    // 替换当前持有的 handle（会关闭旧的那个）。
    void reset(HANDLE h = nullptr) noexcept {
        if (h != handle_) {
            close();
            handle_ = h;
        }
    }

    // 支持 `if (handle) { ... }` 惯用写法。
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
