// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// External Remote Hooking (DLL-less) for VALORANT (vgk.sys emulation)
#pragma once

#include <windows.h>
#include <string>

namespace cg_whuq {
namespace external_hook {

    // Oyunun process ID'sini (PID) bulur
    DWORD FindTargetProcess(const std::wstring& processName);

    // Dışarıdan oyunun hafızasına sızıp CreateFileW ve DeviceIoControl 
    // fonksiyonlarına makine kodu (shellcode) yaması (trampoline) uygular
    bool ApplyHooks(DWORD pid);

    // RiotClientServices.exe'nin hafızasına sızıp WinVerifyTrust (TLS) kontrolünü bypass eder.
    bool ApplyRiotClientHooks(DWORD pid);

} // namespace external_hook
} // namespace cg_whuq
