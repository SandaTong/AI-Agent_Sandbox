cmake_minimum_required(VERSION 3.16)
project(sandbox_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows 下关闭编译器警告（可选）
if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8)
endif()

add_executable(sandbox_demo
    src/main.cpp
    src/sandbox.cpp
    src/sandbox.h
)

target_link_libraries(sandbox_demo PRIVATE
    kernel32.lib
    user32.lib
    advapi32.lib
)