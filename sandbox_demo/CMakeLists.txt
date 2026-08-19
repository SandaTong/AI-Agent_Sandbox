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
project(sandbox_demo LANGUAGES C CXX)

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

# ----- 第三方：MinHook（vendored 到 src/third_party/minhook，M4 API Hook 用）--
# 不用 add_subdirectory —— 它自带的 CMakeLists 有 install/export/config 逻辑，
# 对我们这个纯本地 demo 是噪声；而且我们全局开了 /W4 /permissive-，MinHook
# 的 C 代码会报一堆警告。所以这里自己定义一个干净的静态库 target，只编需要
# 的几个 .c，并单独关掉它的警告（第三方代码不该被我们的严格开关卡住）。
set(MINHOOK_DIR ${CMAKE_SOURCE_DIR}/src/third_party/minhook)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MINHOOK_HDE ${MINHOOK_DIR}/src/hde/hde64.c)
else()
    set(MINHOOK_HDE ${MINHOOK_DIR}/src/hde/hde32.c)
endif()
add_library(minhook STATIC
    ${MINHOOK_DIR}/src/buffer.c
    ${MINHOOK_DIR}/src/hook.c
    ${MINHOOK_DIR}/src/trampoline.c
    ${MINHOOK_HDE}
)
target_include_directories(minhook PUBLIC ${MINHOOK_DIR}/include)
target_include_directories(minhook PRIVATE ${MINHOOK_DIR}/src ${MINHOOK_DIR}/src/hde)
if(MSVC)
    # 第三方 C 代码：关掉我们的严格警告，避免 /W4 /permissive- 卡编译。
    target_compile_options(minhook PRIVATE /W0)
endif()
# minhook 也用静态 CRT，与 sandbox_hook.dll（/MTd）一致，否则 CRT 链接冲突。
set_property(TARGET minhook PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_target_properties(minhook PROPERTIES FOLDER "third_party")

# -----静态库 sandbox_core：common + core------------------------------------
add_library(sandbox_core STATIC
    src/core/job_manager.cc
    src/core/token_manager.cc
    src/core/process_launcher.cc
    src/core/mitigation.cc
    src/core/desktop_iso.cc
    src/core/appcontainer.cc
    src/core/firewall.cc
    src/core/pipe_server.cc
    src/core/pipe_client.cc
    src/core/file_acl.cc
    src/core/injector.cc
    src/core/self_defense.cc
    src/core/wfp_filter.cc
)
target_include_directories(sandbox_core PUBLIC src)
target_link_libraries(sandbox_core PUBLIC
    kernel32.lib
    user32.lib
    advapi32.lib
    userenv.lib
    fwpuclnt.lib
)

# ----- M0 演示程序 -----------------------------------------------------------
add_executable(m0_demo src/demo/m0_demo.cc)
target_link_libraries(m0_demo PRIVATE sandbox_core)

# ----- M1 演示程序（在 M0 基础上加Low IL + Mitigation + Alt Desktop） -------
add_executable(m1_demo src/demo/m1_demo.cc)
target_link_libraries(m1_demo PRIVATE sandbox_core)

# ----- M2 演示程序（在 M1 基础上加 AppContainer + Capability） --------------
add_executable(m2_demo src/demo/m2_demo.cc)
target_link_libraries(m2_demo PRIVATE sandbox_core)

# ----- M3 演示程序（Broker/Target Named-Pipe IPC 骨架） ----------------------
add_executable(m3_demo src/demo/m3_demo.cc)
target_link_libraries(m3_demo PRIVATE sandbox_core)

# ----- M4 演示程序（DLL注入 + API Hook 骨架） -------------------------------
add_executable(m4_demo src/demo/m4_demo.cc)
target_link_libraries(m4_demo PRIVATE sandbox_core)

# ----- M5 演示程序（反注入 mitigation + 运行时自检；用 M4 injector 攻防对照）--
add_executable(m5_demo src/demo/m5_demo.cc)
target_link_libraries(m5_demo PRIVATE sandbox_core)

# ----- M6 演示程序（WFP 用户态网络管控） -----------------------------------
# 形态 A：IP 白名单（默认拦 outbound + 放行白名单 IP，限定到 target）
add_executable(m6_demo src/demo/m6_demo.cc)
target_link_libraries(m6_demo PRIVATE sandbox_core)
# 形态 C：AppID 精确匹配（按 exe 路径拦 target 全部 outbound，含 loopback）
add_executable(m6_appid_demo src/demo/m6_appid_demo.cc)
target_link_libraries(m6_appid_demo PRIVATE sandbox_core)

# ----- M7 演示程序（DNS 域名维度管控） -------------------------------------
# 形态 A：DNS 域名白名单 Hook（注入 dns_hook.dll，hook GetAddrInfoW）
add_executable(m7_demo src/demo/m7_demo.cc)
target_link_libraries(m7_demo PRIVATE sandbox_core)
# 形态 C：DNS->IP 联动 M6 WFP（broker 侧解析域名拿 IP + AppID 兜底）
add_executable(m7_ip_demo src/demo/m7_ip_demo.cc)
target_link_libraries(m7_ip_demo PRIVATE sandbox_core ws2_32.lib)

# ----- M8 演示程序（用户态文件 Broker） -------------------------------------
# 形态 A：策略引擎增强版文件 broker（多规则白名单读写分离 + 防 TOCTOU + 最小权限句柄）
add_executable(m8_demo src/demo/m8_demo.cc)
target_link_libraries(m8_demo PRIVATE sandbox_core)
# 形态 B：DENY-ACE 从外部剥夺 target 写权限（SetNamedSecurityInfo 追加 DENY-WRITE）
add_executable(m8_denyacl_demo src/demo/m8_denyacl_demo.cc)
target_link_libraries(m8_denyacl_demo PRIVATE sandbox_core)

# ----- M9 用户态控制程序（连 Minifilter 通信端口，收审计 + 下发策略）----------
# 注意：Minifilter 驱动本体 sandbox_minifilter.sys 需 WDK 单独编译（见
# src/minifilter/README.md 和 sandbox_minifilter.vcxproj）；这里只编纯用户态的
# 控制程序 mf_ctl（链接 fltlib，普通 MSVC 即可）。
add_executable(mf_ctl src/minifilter/mf_ctl.cc)
target_include_directories(mf_ctl PRIVATE src/minifilter)
target_link_libraries(mf_ctl PRIVATE fltlib.lib)
set_target_properties(mf_ctl PROPERTIES FOLDER "demo")

# ----- dns_hook.dll：M7 注入进 target 的域名管控垫片（MinHook 钩 GetAddrInfoW）--
# 和 sandbox_hook.dll 同款配置：静态 CRT + 链接 minhook。
add_library(dns_hook SHARED src/demo/dns_hook.cc)
target_link_libraries(dns_hook PRIVATE minhook user32.lib ws2_32.lib)
set_target_properties(dns_hook PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>")
set_property(TARGET dns_hook PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ----- sandbox_hook.dll：被注入进 target 的拦截垫片（MinHook 钩 CreateFileW）--
# 静态链接 CRT，保持和 hello_target 一致（避免注入后依赖非签名 debug CRT）。
# 链接 minhook静态库（vendored）。
add_library(sandbox_hook SHARED src/demo/sandbox_hook.cc)
target_link_libraries(sandbox_hook PRIVATE minhook user32.lib)
set_target_properties(sandbox_hook PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>")
set_property(TARGET sandbox_hook PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ----- 一个用来做冒烟对比的极简 target ---------------------------------------
# 直接双击 -> 看到"基线"行为（Medium IL，无 Job，特权齐全）；
# 通过 m0_demo 拉起 -> 看到"沙箱化"行为（Job + restricted token）。
# 后续 M1 降 IL、M2 上 AppContainer 时，它打印的 integrity_level 会变化，
# 这本身就是一个自内建的验证信号。
#
# 重要：hello_target 必须**静态链接 CRT**（/MT + /MTd），否则 M1 的
# BLOCK_NON_MICROSOFT_BINARIES 会拦掉 VCRUNTIME140D.dll / ucrtbased.dll
# 这些 debug CRT（它们不带 Microsoft 根证书签名），导致 target 启动就
# 报 0xC0000142 (STATUS_DLL_INIT_FAILED)。静态链接后所有 CRT 代码都编进
# hello_target.exe 自身，加载器不再拉外部 DLL，mitigation 就通过了。
# hello_target 额外编入 pipe_client.cc（M3 IPC 客户端）和 self_defense.cc
# （M5 运行时自检）。它不链接 sandbox_core（避免拖入 userenv 等重依赖），
# 只带它自己需要的那几个源文件；这些都是纯 Win32（kernel32/ntdll/toolhelp），
# 依赖的 common/*.h 是 header-only。
add_executable(hello_target
    src/demo/hello_target.cc
    src/core/pipe_client.cc
    src/core/self_defense.cc)
target_link_libraries(hello_target PRIVATE advapi32.lib)
set_property(TARGET hello_target PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ----- unsigned_probe.dll ----------------------------------------------------
# 一个"非微软签名"的探测 DLL。基线/M0 里target 能加载成功；M1 因
# BLOCK_NON_MICROSOFT_BINARIES 生效，LoadLibraryW 返回 nullptr，gle=577
# (ERROR_INVALID_IMAGE_HASH)。用来干净演示 mitigation policy 的拦截。
add_library(unsigned_probe SHARED src/demo/unsigned_probe.cc)
set_target_properties(unsigned_probe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
)
# 同样静态链接 CRT，避免 unsigned_probe.dll 本身又依赖非签名的 debug CRT
# DLL（那样 M1 LoadLibraryW 时会因为间接依赖再次触发 mitigation）。
set_property(TARGET unsigned_probe PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ----- Visual Studio 解决方案里的分组 ----------------------------------------
set_target_properties(sandbox_core  PROPERTIES FOLDER "core")
set_target_properties(m0_demo       PROPERTIES FOLDER "demo")
set_target_properties(m1_demo       PROPERTIES FOLDER "demo")
set_target_properties(m2_demo   PROPERTIES FOLDER "demo")
set_target_properties(m3_demo       PROPERTIES FOLDER "demo")
set_target_properties(m4_demo       PROPERTIES FOLDER "demo")
set_target_properties(m5_demo       PROPERTIES FOLDER "demo")
set_target_properties(m6_demo       PROPERTIES FOLDER "demo")
set_target_properties(m6_appid_demo PROPERTIES FOLDER "demo")
set_target_properties(m7_demo       PROPERTIES FOLDER "demo")
set_target_properties(m7_ip_demo    PROPERTIES FOLDER "demo")
set_target_properties(m8_demo       PROPERTIES FOLDER "demo")
set_target_properties(m8_denyacl_demo PROPERTIES FOLDER "demo")
set_target_properties(dns_hook      PROPERTIES FOLDER "demo")
set_target_properties(sandbox_hook  PROPERTIES FOLDER "demo")
set_target_properties(hello_target  PROPERTIES FOLDER "demo")
set_target_properties(unsigned_probe PROPERTIES FOLDER "demo")
