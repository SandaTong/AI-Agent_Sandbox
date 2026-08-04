// -----------------------------------------------------------------------------
// common/win_error.h
// -----------------------------------------------------------------------------
// 把 Win32 的 GetLastError() 包装成 std::error_code，以及格式化错误码。
//
// 为什么这么做：
// - std::error_code 是 C++17 标准里"不用异常传错误"的规范做法（本工程
//     跨模块边界一律不抛异常）。
//   - std::system_category() 内部会调用 FormatMessage() 翻译 Win32 错误码，
//     所以 ec.message() 直接就有本地化的可读文案，不用自己拼字符串。
//
// 常见用法：
//   if (!SomeApi(...)) {
//       return LastError();   // -> std::error_code{GLE, system_category}
//   }
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <system_error>

namespace sandbox {

// 把当前的 GetLastError() 快照成 std::error_code（system_category 分类）。
[[nodiscard]] inline std::error_code LastError() noexcept {
    return {static_cast<int>(::GetLastError()), std::system_category()};
}

// 显式指定错误码 -> error_code。
[[nodiscard]] inline std::error_code MakeWinError(DWORD code) noexcept {
    return {static_cast<int>(code), std::system_category()};
}

// 格式化为可读字符串："[123] The device is not ready."
[[nodiscard]] inline std::string DescribeError(const std::error_code& ec) {
    return "[" + std::to_string(ec.value()) + "] " + ec.message();
}

}  // namespace sandbox
