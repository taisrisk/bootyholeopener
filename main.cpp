#include <Windows.h>
#include <iostream>
#include "hijack.h"

int main()
{
    DWORD pid = GetPID("RobloxPlayerBeta.exe");
    if (pid == 0) {
        std::cout << "nigler not running boblox" << "\n";
        std::cin.get();
        return 1;
    }
    std::cout << "pid: " << pid << "\n";
    HANDLE hijacked = HijackExistingHandle(pid);

    if (IsHandleValid(hijacked)) {
        std::cout << "handle: 0x" << std::hex << (ULONG_PTR)hijacked << "\n";

        // now use this handle for rpm wpm or whatever da fuck u want

    }
    else {
        std::cout << "not able to hijack handle" << "\n";
    }

    std::cin.get();
    return 0;
}