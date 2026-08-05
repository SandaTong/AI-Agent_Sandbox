// unsigned_probe.dll —— 一个"非微软签名"的探测 DLL，用来验证 M1的
// BLOCK_NON_MICROSOFT_BINARIES 策略是否生效。
//
// 用途：
//   - 基线 / M0：能被 LoadLibraryW 成功加载（我们本地编译的，未签名）
//   - M1：LoadLibraryW 返回 nullptr，GetLastError()==577 (ERROR_INVALID_IMAGE_HASH)
//     —— 内核在做映像哈希校验时发现签名不是微软根，直接拒绝加载
//
// 为什么用真 DLL 而不是 exe：
//   LoadLibraryW 加载 exe 时 Windows 会因为 "已经作为主映像映射过一次" 走
//   特殊快速路径，绕过部分校验，导致基线组结果失真。用一个独立编译的真 DLL
//   才能干净地演示 mitigation 的拦截点。

#include <windows.h>

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    (void)reason;
    return TRUE;
}

// 导出一个符号，避免链接器优化掉整个 DLL。
extern "C" __declspec(dllexport) int unsigned_probe_marker() {
    return 0x600D;
}
