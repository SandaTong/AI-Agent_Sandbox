// -----------------------------------------------------------------------------
// common/logger.h
// -----------------------------------------------------------------------------
// 一个"够用就好"的线程安全 stdout logger。刻意不引 spdlog / fmt，保持零
// 依赖；后续 milestone 可以随时替换实现。
//
// 日志等级：
//   INFO   — [+]  正常进度
//   WARN   — [!]  可恢复的异常，值得关注
//   ERROR  — [-]  硬失败
//   DEBUG  — [.]  冗余日志，仅在定义 SANDBOX_DEBUG 宏时输出
//
// 宽字符 vs 窄字符：
//   Windows API 返回 UTF-16（LPWSTR），比如路径、进程映像。为了不掉字符，
//   日志用宽字符模式，LOG_INFO / LOG_ERROR 走 std::wcerr。
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
        case Level::kInfo:
            return L"[+]";
        case Level::kWarn:
            return L"[!]";
        case Level::kError:
            return L"[-]";
        case Level::kDebug:
            return L"[.]";
    }
    return L"[?]";
}

// 基础构件：加锁后原子写一整行到 wcerr（无缓冲，多线程 demo 场景够用）。
// 全部走 wcerr 便于统一重定向输出。
class LineStream {
 public:
    explicit LineStream(Level lv) : lv_(lv) { ss_ << Tag(lv_) << L' '; }
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

#define LOG_INFO ::sandbox::log::LineStream(::sandbox::log::Level::kInfo)
#define LOG_WARN ::sandbox::log::LineStream(::sandbox::log::Level::kWarn)
#define LOG_ERROR ::sandbox::log::LineStream(::sandbox::log::Level::kError)

#ifdef SANDBOX_DEBUG
#define LOG_DEBUG ::sandbox::log::LineStream(::sandbox::log::Level::kDebug)
#else
// 空流：编译器会把整个语句优化掉，不产生任何分配。
#define LOG_DEBUG \
    if (true) {   \
    } else        \
        ::sandbox::log::LineStream(::sandbox::log::Level::kDebug)
#endif
