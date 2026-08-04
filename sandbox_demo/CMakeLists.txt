# =============================================================================
# sandbox_demo — Windows Agent Sandbox 学习/演示工程
#
# 目标 milestone（详见 docs/notes/*）:
#   M0   Job + Token + CREATE_SUSPENDED 基础闭环         (已完成)
#   M1   Integrity Level + STARTUPINFOEX Mitigation Policy
#   M2   AppContainer / LowBox Token
#   M3 Broker/Target 拆分 + Named-Pipe IPC
#   M4/5 Injector / Hook payload / anti-inject
#   M6/7 WFP 网络过滤 / DNS 域名管控
#   M8   用户态 File Broker
#   M9   内核 Minifilter 驱动
# =============================================================================
cmake_minimum_required(VERSION 3.20)
project(sandbox_demo LANGUAGES CXX)

# ----- 全局 C++ 设置 ----------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 所有 target 都能 #include "common/scoped_handle.h" 这种形式的相对路径。
include_directories(${CMAKE_SOURCE_DIR}/src)

# ----- MSVC 加固编译选项 ------------------------------------------------------
if(MSVC)
    add_compile_options(
 /W4          # 高警告等级
        /permissive-  # 严格标准符合性
        /utf-8           # 源码与执行字符集都用 UTF-8（避免 GBK 解析出错）
      /Zc:__cplusplus  # __cplusplus 宏返回真实值
        /EHsc    # C++ 异常模型（我们自己不抛，但 STL 需要）
    )
    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS
        UNICODE _UNICODE
    WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00   # 目标 Win10+（后续 Mitigation API 需要）
    )
endif()

# ----- 静态库 sandbox_core：common + core ------------------------------------
add_library(sandbox_core STATIC
    src/core/job_manager.cc
 src/core/token_manager.cc
    src/core/process_launcher.cc
)
target_include_directories(sandbox_core PUBLIC src)
target_link_libraries(sandbox_core PUBLIC
    kernel32.lib
    user32.lib
    advapi32.lib
    userenv.lib
)

# ----- M0 演示程序 -----------------------------------------------------------
add_executable(m0_demo src/demo/m0_demo.cc)
target_link_libraries(m0_demo PRIVATE sandbox_core)

# ----- 一个用来做冒烟对比的极简 target ---------------------------------------
# 直接双击 -> 看到"基线"行为（Medium IL，无 Job，特权齐全）；
# 通过 m0_demo 拉起 -> 看到"沙箱化"行为（Job + restricted token）。
# 后续 M1 降 IL、M2 上 AppContainer 时，它打印的 integrity_level 会变化，
# 这本身就是一个自内建的验证信号。
add_executable(hello_target src/demo/hello_target.cc)
target_link_libraries(hello_target PRIVATE advapi32.lib)

# ----- Visual Studio 解决方案里的分组 ----------------------------------------
set_target_properties(sandbox_core  PROPERTIES FOLDER "core")
set_target_properties(m0_demo       PROPERTIES FOLDER "demo")
set_target_properties(hello_target  PROPERTIES FOLDER "demo")
