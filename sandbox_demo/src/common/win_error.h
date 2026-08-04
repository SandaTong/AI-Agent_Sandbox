// -----------------------------------------------------------------------------
// common/win_error.h
// -----------------------------------------------------------------------------
// Convenience helpers to turn Win32 GetLastError() into std::error_code and to
// format Win32 error codes into human-readable strings.
//
// Why:
//   - std::error_code is the standard C++17 way to pass errors without
//     exceptions (which we forbid across the module boundary).
//   - std::system_category() knows how to FormatMessage() a Win32 code, so
//     ec.message() gives you the OS-localized message for free.
//
// Usage:
//   if (!SomeApi(...)) {
//       return LastError();   // -> std::error_code{GLE, system_category}
//   }
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <system_error>

namespace sandbox {

// Snapshot GetLastError() as a std::error_code (system_category).
[[nodiscard]] inline std::error_code LastError() noexcept {
    return {static_cast<int>(::GetLastError()), std::system_category()};
}

// Explicit code -> error_code.
[[nodiscard]] inline std::error_code MakeWinError(DWORD code) noexcept {
    return {static_cast<int>(code), std::system_category()};
}

// Formatted display: "[123] The device is not ready."
[[nodiscard]] inline std::string DescribeError(const std::error_code& ec) {
    return "[" + std::to_string(ec.value()) + "] " + ec.message();
}

}  // namespace sandbox
