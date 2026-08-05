// -----------------------------------------------------------------------------
// common/logger.h
// -----------------------------------------------------------------------------
// 一个"够用就好"的线程安全 stdout logger。刻意不引spdlog / fmt，保持零
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
//
// Windows 控制台中文输出的坑：
//   MSVC 默认下 wcerr 处于 _O_TEXT（窄）模式，它会把 UTF-16 → 当前 locale
//   的单字节编码（GBK/ANSI），中文字符转换失败 -> 整行被吞。修复方法是
//   进程启动时用 _setmode(fd, _O_U16TEXT) 把 std handle 切到 UTF-16 二进制
//   模式，之后 wcerr 写出的宽字符会原样（UTF-16）送进控制台。
//   我们用一个静态初始化对象在 main 之前完成这个设置，业务代码零感知。
// -----------------------------------------------------------------------------
#pragma once

#include <fcntl.h>
#include <io.h>
#include <windows.h>

#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace sandbox::log {

// 进程启动时一次性把 wcerr / wcout 切到 UTF-16 模式，之后就能正常输出中文。
// 依赖 C++ 的静态初始化机制：任何 TU 只要 include 了本头文件、并且真的用了
// LOG_INFO / LOG_WARN / LOG_ERROR 中任意一个，就会触发这段代码在 main 之前执行。
struct WideConsoleInit {
    WideConsoleInit() noexcept {
        // 只调一次；如果 wcerr 已经写过东西，setmode 会失败，但那不影响后续输出。
        (void)_setmode(_fileno(stderr), _O_U16TEXT);
        (void)_setmode(_fileno(stdout), _O_U16TEXT);
        // 双保险：把控制台"输出 code page"也设成 UTF-8，方便 narrow 打印
        // 场景（例如 printf/std::cout）；对我们 wcerr 主路径不是必需的。
        ::SetConsoleOutputCP(CP_UTF8);
    }
};

// 这个 inline 变量保证跨 TU 只实例化一次，构造函数在 main 之前跑。
inline WideConsoleInit g_wide_console_init{};

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
