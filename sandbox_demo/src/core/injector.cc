// -----------------------------------------------------------------------------
// core/injector.cc
// -----------------------------------------------------------------------------
#include "core/injector.h"

#include "common/logger.h"
#include "common/scoped_handle.h"
#include "common/win_error.h"

namespace sandbox {

std::error_code Injector::InjectDll(HANDLE target_process, const std::wstring& dll_path,
                                    DWORD wait_ms) {
    if (!target_process || target_process == INVALID_HANDLE_VALUE)
        return MakeWinError(ERROR_INVALID_HANDLE);
    if (dll_path.empty())
        return MakeWinError(ERROR_INVALID_PARAMETER);

    // 路径连结尾 L'\0' 一起写进 target，方便远程 LoadLibraryW 直接用。
    const SIZE_T path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);

    // ---- 第 1 步：在 target 地址空间分配内存 ----
    // MEM_COMMIT | MEM_RESERVE + PAGE_READWRITE：只需可读写存字符串，不需可执行。
    LPVOID remote_mem = ::VirtualAllocEx(target_process, nullptr, path_bytes,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        LOG_ERROR << L"Injector: VirtualAllocEx 失败: " << DescribeError(LastError()).c_str();
        return LastError();
    }
    // 失败路径要VirtualFreeEx 释放；用 RAII 兜底。
    struct RemoteMemGuard {
        HANDLE proc;
        LPVOID addr;
        ~RemoteMemGuard() {
            if (addr)
                ::VirtualFreeEx(proc, addr, 0, MEM_RELEASE);
        }
    } mem_guard{target_process, remote_mem};

    // ---- 第 2 步：把 DLL 路径字符串写进那块内存 ----
    SIZE_T written = 0;
    if (!::WriteProcessMemory(target_process, remote_mem, dll_path.c_str(), path_bytes, &written) ||
        written != path_bytes) {
        LOG_ERROR << L"Injector: WriteProcessMemory 失败: " << DescribeError(LastError()).c_str();
        return LastError();
    }

    // ---- 第 3 步：取 LoadLibraryW 地址 ----
    // kernel32.dll 在同一 session 的所有进程里加载基址相同，所以 broker 里
    // 取到的 LoadLibraryW 地址在 target 里同样有效——这是本注入手法的前提。
    HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
    if (!k32)
        return LastError();
    auto load_library =
        reinterpret_cast<LPTHREAD_START_ROUTINE>(::GetProcAddress(k32, "LoadLibraryW"));
    if (!load_library) {
        LOG_ERROR << L"Injector: 取 LoadLibraryW 地址失败";
        return MakeWinError(ERROR_PROC_NOT_FOUND);
    }

    // ---- 第 4 步：在 target 里起远程线程，入口 = LoadLibraryW，参数 = 路径地址 ----
    // 等价于 target 自己执行了 LoadLibraryW(L"...\\sandbox_hook.dll")。
    DWORD remote_tid = 0;
    HANDLE remote_thread =
        ::CreateRemoteThread(target_process, nullptr, 0, load_library, remote_mem, 0, &remote_tid);
    if (!remote_thread) {
        LOG_ERROR << L"Injector: CreateRemoteThread 失败: " << DescribeError(LastError()).c_str();
        return LastError();
    }
    ScopedHandle thread_guard(remote_thread);
    LOG_INFO << L"Injector: 远程线程已起 tid=" << remote_tid << L" 入口=LoadLibraryW 路径="
             << dll_path.c_str();

    // ---- 第 5 步：等远程线程（LoadLibraryW）完成 ----
    DWORD wait = ::WaitForSingleObject(remote_thread, wait_ms);
    if (wait == WAIT_TIMEOUT) {
        LOG_WARN << L"Injector: 等远程线程超时";
        return MakeWinError(WAIT_TIMEOUT);
    }
    if (wait != WAIT_OBJECT_0) {
        return LastError();
    }
    // 远程线程退出码 = LoadLibraryW 返回值的低 32 位（HMODULE）。0 表示加载失败。
    DWORD exit_code = 0;
    ::GetExitCodeThread(remote_thread, &exit_code);
    if (exit_code == 0) {
        LOG_ERROR << L"Injector: 远程 LoadLibraryW 返回 NULL（DLL 加载失败——路径错/依赖缺/"
                     L"被 mitigation 拦）";
        return MakeWinError(ERROR_MOD_NOT_FOUND);
    }

    LOG_INFO << L"Injector: DLL 注入成功（远程 LoadLibraryW 返回非空 HMODULE 低位=0x" << std::hex
             << exit_code << std::dec << L"）";
    return {};
}

}  // namespace sandbox
