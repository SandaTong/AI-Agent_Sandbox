# =============================================================================
# sandbox_demo — Windows Agent Sandbox learning project
#
# Target milestones (see docs/notes/*):
#   M0   Job + Token + CREATE_SUSPENDED baseline           (current)
#   M1Integrity Level + STARTUPINFOEX Mitigation Policy
#   M2   AppContainer / LowBox Token
#   M3   Broker/Target split + Named-Pipe IPC
#   M4/5 Injector / Hook payload / anti-inject
#   M6/7 WFP network firewall / DNS domain guard
#   M8   User-mode file broker
#   M9   Kernel-mode Minifilter driver
# =============================================================================
cmake_minimum_required(VERSION 3.20)
project(sandbox_demo LANGUAGES CXX)

# ----- Global C++ settings ----------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# All targets can #include from src/  (i.e. #include "common/scoped_handle.h")
include_directories(${CMAKE_SOURCE_DIR}/src)

# ----- MSVC hardening flags ---------------------------------------------------
if(MSVC)
    add_compile_options(
        /W4              # tight warnings
        /permissive-     # standards conformance
        /utf-8           # source & exec charset = UTF-8 (fixes the GBK bug)
        /Zc:__cplusplus  # report the real __cplusplus value
        /EHsc            # exception model (we don't throw, but STL needs this)
    )
    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00   # target Win10+ (needed for later Mitigation APIs)
    )
endif()

# ----- Shared static library: common + core ----------------------------------
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

# ----- M0 demo executable -----------------------------------------------------
add_executable(m0_demo src/demo/m0_demo.cc)
target_link_libraries(m0_demo PRIVATE sandbox_core)

# ----- A trivial target used as sandbox smoke-test payload --------------------
# Launch it directly to see the "baseline" (Medium IL, no job, all privileges).
# Launch it via m0_demo to see the "sandboxed" behavior (Job + restricted token).
# In later milestones (M1: Low IL, M2: AppContainer) the integrity_level line
# it prints will change accordingly — a nice built-in verification signal.
add_executable(hello_target src/demo/hello_target.cc)
target_link_libraries(hello_target PRIVATE advapi32.lib)

# ----- Group projects in Visual Studio Solution Explorer ---------------------
set_target_properties(sandbox_core  PROPERTIES FOLDER "core")
set_target_properties(m0_demo       PROPERTIES FOLDER "demo")
set_target_properties(hello_target  PROPERTIES FOLDER "demo")
