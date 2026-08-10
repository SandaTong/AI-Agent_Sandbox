// -----------------------------------------------------------------------------
// core/injector.h
// -----------------------------------------------------------------------------
// M4：远程线程 DLL 注入（CreateRemoteThread + LoadLibraryW 经典四件套）。
//
// 【在沙箱里，注入不是"攻击"，是"植入拦截垫片"】
//   前面 M0~M3 我们是"沙箱设计者"，把 target 关起来。M4 换一个视角：broker
//   主动往 target 里注入一个 DLL，这个 DLL 在 target 内部 Hook 住敏感 API
//   （如 CreateFileW），把 target 的调用重定向到策略检查 / broker 代劳。
//
//   这正是 Chromium sandbox 的做法——target 启动时 broker 注入一层 hook
//   （它叫 "interception"），target 对敏感 API 的调用被无感知地拦截转发。
//   M4 的注入 + Hook 是 M3 IPC 的自然延伸：M3 是 target 主动请broker 代劳，
//   M4 是 target 被hook 后"自动"把敏感调用交出去（target 不用改代码）。
//
// 【远程线程注入四件套（本文件实现的核心）】
//   目标：让 target 进程加载我们指定的 sandbox_hook.dll。
//   思路：借用 target 自己的线程去调 LoadLibraryW(L"sandbox_hook.dll")。
//
//   1. VirtualAllocEx(target, ...)          在 target 地址空间分配一块内存
//   2. WriteProcessMemory(target, ...)      把 DLL 路径字符串写进那块内存
//   3. GetProcAddress(kernel32, "LoadLibraryW")  拿 LoadLibraryW 的地址
//      —— 关键：kernel32.dll 在所有进程里加载基址相同（同一 session内），
//         所以 broker 里取到的 LoadLibraryW 地址在 target 里同样有效。这是
//         这套注入手法能成立的前提。
//   4. CreateRemoteThread(target, ..., LoadLibraryW, remote_path_addr)
//      在 target 里起一个线程，入口就是 LoadLibraryW，参数是第 2 步写进去
//      的路径地址。等价于 target 自己执行了 LoadLibraryW(L"...\sandbox_hook.dll")。
//   5. 等远程线程结束 —— 它的退出码就是 LoadLibraryW 的返回值（DLL 的
//      HMODULE 低 32 位），非0 表示加载成功。
//
// 【为什么 AppContainer target 注不进去（M4 精简版的边界）】
//   VirtualAllocEx / WriteProcessMemory / CreateRemoteThread 都需要 broker
//   对 target 有 PROCESS_VM_OPERATION / PROCESS_VM_WRITE / PROCESS_CREATE_
//   THREAD 权限。broker 是 target 的父进程、且 IL 更高时通常有这些权限。但
//   若 target 是 AppContainer + 强 mitigation（如 PROHIBIT_DYNAMIC_CODE /
//   BLOCK_NON_MICROSOFT_BINARIES），注入会被拦。所以 M4 精简版用普通 Low IL
//   target 演示注入骨架，不叠加 AppContainer。生产做法是 broker 起target
//   时就通过 STARTUPINFOEX 预置 hook（更早、更可靠），M4 后续再演进。
// -----------------------------------------------------------------------------
#pragma once

#include <windows.h>

#include <string>
#include <system_error>

namespace sandbox {

class Injector {
 public:
    // 用远程线程注入法，让 target_process 加载 dll_path 指定的 DLL。
    //   target_process：需具备 PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
    //     PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION 权限的句柄。
    //   dll_path：要注入的 DLL 的**绝对路径**（远程 LoadLibraryW 按此路径找）。
    //   wait_ms：等远程线程（即 LoadLibraryW）完成的超时。
    //
    // 成功返回 error_code{}；失败返回对应 Win32 错误。
    static std::error_code InjectDll(HANDLE target_process, const std::wstring& dll_path,
                                     DWORD wait_ms = 5000);
};

}  // namespace sandbox
