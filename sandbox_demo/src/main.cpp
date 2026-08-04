#include "sandbox.h"
#include <iostream>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: sandbox_demo <exe_path> [cmdline]\n";
        std::wcout << L"Example: sandbox_demo C:\\Windows\\System32\\notepad.exe\n";
        return 1;
    }

    std::wstring exe = argv[1];
    std::wstring cmdline = (argc >= 3) ? argv[2] : L"";

    Sandbox sandbox;
    auto ec = sandbox.launch(exe, cmdline);

    if (ec) {
        std::cout << "[-] Failed: " << ec.message() << " (code=" << ec.value() << ")\n";
        return ec.value();
    }

    std::wcout << L"[+] Done!\n";
    return 0;
}