// -----------------------------------------------------------------------------
// common/logger.h
// -----------------------------------------------------------------------------
// Ultra-tiny thread-safe stdout logger. We deliberately do NOT pull in spdlog
// or fmt to keep dependencies zero. Later milestones may swap this out.
//
// Levels:
//   INFO   — [+] normal progress
//   WARN   — [!] recoverable issue, worth attention
//   ERROR  — [-] hard failure
//   DEBUG  — [.] verbose, only emitted when SANDBOX_DEBUG defined
//
// Wide vs narrow:
//   Windows APIs return UTF-16 (LPWSTR) for paths / process images. To stay
//   loss-free we log in wide mode. LOG_INFO/LOG_ERROR emit std::wcout.
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace sandbox::log {

inline std::mutex& mutex() {
    static std::mutex m;
    return m;
}

enum class Level { kInfo, kWarn, kError, kDebug };

inline const wchar_t* Tag(Level lv) noexcept {
    switch (lv) {
        case Level::kInfo:  return L"[+]";
        case Level::kWarn:  return L"[!]";
        case Level::kError: return L"[-]";
        case Level::kDebug: return L"[.]";
    }
    return L"[?]";
}

// Building block: locked write to wcerr (unbuffered, cross-thread safe enough
// for demo). We use wcerr for everything so redirection works uniformly.
class LineStream {
 public:
    explicit LineStream(Level lv) : lv_(lv) {
        ss_ << Tag(lv_) << L' ';
    }
    ~LineStream() {
        std::lock_guard<std::mutex> lock(mutex());
        std::wcerr << ss_.str() << std::endl;
    }

    template <typename T>
    LineStream& operator<<(T&& v) {
        ss_ << std::forward<T>(v);
        return *this;
    }

 private:
    Level lv_;
    std::wostringstream ss_;
};

}  // namespace sandbox::log

#define LOG_INFO  ::sandbox::log::LineStream(::sandbox::log::Level::kInfo)
#define LOG_WARN  ::sandbox::log::LineStream(::sandbox::log::Level::kWarn)
#define LOG_ERROR ::sandbox::log::LineStream(::sandbox::log::Level::kError)

#ifdef SANDBOX_DEBUG
#define LOG_DEBUG ::sandbox::log::LineStream(::sandbox::log::Level::kDebug)
#else
// no-op stream — never allocates
#define LOG_DEBUG                                                     \
    if (true) {                                                       \
    } else                                                \
        ::sandbox::log::LineStream(::sandbox::log::Level::kDebug)
#endif
