// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// External Remote Hooking (DLL-less) for VALORANT (vgk.sys emulation)

#include "external_hook.h"
#include <iostream>
#include <TlHelp32.h>
#include <vector>

#define OBF_STR(x) (x)
#define FAKE_VGK_HANDLE ((HANDLE)0x1337BEEF)

namespace cg_whuq {
namespace external_hook {

    // Helper: Oyunun PID'sini bulur
    DWORD FindTargetProcess(const std::wstring& processName) {
        DWORD pid = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (!_wcsicmp(pe.szExeFile, processName.c_str())) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        return pid;
    }

    // Helper: Uzak process'teki (kernel32.dll) bir fonksiyonun adresini alir
    // Not: Windows 64-bit'te kernel32.dll cogu zaman ayni base adrese yuklenir.
    // Eger ASLR farklilik gosterirse daha gelismis bir GetRemoteProcAddress gerekir.
    // Basitlik adina mevcut process'teki adresi kullaniyoruz (ASLR bypass via shared mapping).
    FARPROC GetRemoteProcAddress(HANDLE hProcess, const char* moduleName, const char* funcName) {
        HMODULE hMod = GetModuleHandleA(moduleName);
        if (!hMod) hMod = LoadLibraryA(moduleName);
        return GetProcAddress(hMod, funcName);
    }

    // Helper: 64-bit relative jump (E9) limitini asmamak icin (±2GB),
    // Codecave'i hedefe yakin bir adreste tahsis eder (Allocate).
    void* AllocateNear(HANDLE hProc, void* targetAddr, size_t size) {
        DWORD_PTR target = (DWORD_PTR)targetAddr;
        void* pMem = NULL;
        
        // Geriye dogru ara (Target - 2GB'a kadar)
        for (DWORD_PTR addr = target - 0x10000; addr > target - 0x70000000; addr -= 0x10000) {
            pMem = VirtualAllocEx(hProc, (void*)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pMem) return pMem;
        }
        
        // Ileriye dogru ara (Target + 2GB'a kadar)
        for (DWORD_PTR addr = target + 0x10000; addr < target + 0x70000000; addr += 0x10000) {
            pMem = VirtualAllocEx(hProc, (void*)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pMem) return pMem;
        }
        
        return NULL; // Yakinlarda bos yer bulunamadi (Cok nadir)
    }

    bool ApplyHooks(DWORD pid) {
        HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
        if (!hProc) {
            std::cerr << OBF_STR("[EXTERNAL-HOOK] OpenProcess basarisiz. Admin yetkisi kontrol edin. Hata: ") << GetLastError() << std::endl;
            return false;
        }

        void* pCreateFileW = (void*)GetRemoteProcAddress(hProc, "kernelbase.dll", "CreateFileW");
        void* pDeviceIoControl = (void*)GetRemoteProcAddress(hProc, "kernelbase.dll", "DeviceIoControl");

        if (!pCreateFileW || !pDeviceIoControl) {
            std::cerr << OBF_STR("[EXTERNAL-HOOK] Fonksiyon adresleri bulunamadi!") << std::endl;
            CloseHandle(hProc);
            return false;
        }

        std::cout << OBF_STR("[EXTERNAL-HOOK] VALORANT yakalandi. PID: ") << pid << std::endl;
        std::cout << OBF_STR("[EXTERNAL-HOOK] Injecting SMART shellcode into kernel32.dll...\n");

        // Orijinal 5 byte'lari yedekle (Trampoline icin)
        BYTE origCreateFile[5];
        ReadProcessMemory(hProc, pCreateFileW, origCreateFile, 5, NULL);
        
        BYTE origDeviceIo[5];
        ReadProcessMemory(hProc, pDeviceIoControl, origDeviceIo, 5, NULL);

        void* pCodecave = AllocateNear(hProc, pCreateFileW, 0x1000);
        if (!pCodecave) {
            std::cerr << OBF_STR("[EXTERNAL-HOOK] VirtualAllocEx basarisiz!\n");
            CloseHandle(hProc);
            return false;
        }

        // ======================================================================
        // SMART CreateFileW Hook (Sadece \\.\vgk erisimlerini keser)
        // ======================================================================
        BYTE shellcode_CreateFile[] = {
            // Offset 0x00
            0x50,                               // push rax
            // Offset 0x01
            0x48, 0x85, 0xC9,                   // test rcx, rcx (lpFileName null mu?)
            // Offset 0x04
            0x74, 0x24,                         // je original (jump to 0x2A)
            
            // Offset 0x06 (WCHAR '\\' (0x5C), '\\' (0x5C), '.' (0x2E), '\\' (0x5C) atlanir)
            0x66, 0x81, 0x79, 0x08, 0x76, 0x00, // cmp word ptr [rcx+8], 0x76 ('v')
            // Offset 0x0C
            0x75, 0x1C,                         // jne original
            
            // Offset 0x0E
            0x66, 0x81, 0x79, 0x0A, 0x67, 0x00, // cmp word ptr [rcx+10], 0x67 ('g')
            // Offset 0x14
            0x75, 0x14,                         // jne original
            
            // Offset 0x16
            0x66, 0x81, 0x79, 0x0C, 0x6B, 0x00, // cmp word ptr [rcx+12], 0x6B ('k')
            // Offset 0x1C
            0x75, 0x0C,                         // jne original
            
            // Offset 0x1E: "vgk" ile eslesti -> Sahte Handle don
            0x58,                               // pop rax
            // Offset 0x1F
            0x48, 0xB8, 0xEF, 0xBE, 0x37, 0x13, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x1337BEEF
            // Offset 0x29
            0xC3,                               // ret
            
            // --- ORIGINAL TRAMPOLINE ---
            // Offset 0x2A (42 dec): original
            0x58,                               // pop rax
            // Offset 0x2B (43 dec): Orijinal 5 byte buraya kopyalanacak
            0x90, 0x90, 0x90, 0x90, 0x90,
            // Offset 0x30 (48 dec): jmp back
            0xE9, 0x00, 0x00, 0x00, 0x00        
        };
        
        // Orijinal bytelari shellcode icine kopyala (Offset 0x2B)
        memcpy(&shellcode_CreateFile[0x2B], origCreateFile, 5);
        
        // JMP geri donus adresini hesapla (CreateFileW + 5)
        // Codecave basi + 0x30'da JMP komutu basliyor. JMP komutu 5 byte. Sonrasi Codecave + 0x35
        DWORD_PTR retAddrCF = (DWORD_PTR)pCreateFileW + 5;
        DWORD_PTR caveEndCF = (DWORD_PTR)pCodecave + 0x30 + 5; 
        DWORD relJmpCF = (DWORD)(retAddrCF - caveEndCF);
        // JMP adresini yaz (Offset 0x31)
        memcpy(&shellcode_CreateFile[0x31], &relJmpCF, 4);

        WriteProcessMemory(hProc, pCodecave, shellcode_CreateFile, sizeof(shellcode_CreateFile), NULL);

        // Orijinal CreateFileW'yi JMP (Codecave'e gidis) ile yamala
        BYTE jmpInst[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
        DWORD relHookCF = (DWORD)((DWORD_PTR)pCodecave - ((DWORD_PTR)pCreateFileW + 5));
        memcpy(&jmpInst[1], &relHookCF, 4);

        DWORD oldProtect;
        VirtualProtectEx(hProc, pCreateFileW, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(hProc, pCreateFileW, jmpInst, 5, NULL);
        VirtualProtectEx(hProc, pCreateFileW, 5, oldProtect, &oldProtect);

        std::cout << OBF_STR("[EXTERNAL-HOOK] CreateFileW AKILLI kancalandi. (Sadece vgk engelleniyor)\n");

        // ======================================================================
        // SMART DeviceIoControl Hook (Sadece sahte handle olan 0x1337BEEF'i keser)
        // ======================================================================
        BYTE shellcode_DeviceIo[] = {
            // Offset 0x00
            0x48, 0x81, 0xF9, 0xEF, 0xBE, 0x37, 0x13, // cmp rcx, 0x1337BEEF
            // Offset 0x07
            0x75, 0x06,                               // jne original (jump 6 bytes -> to 0x0F)
            
            // Offset 0x09: Sahte handle ile eslesti -> TRUE don (Basarili)
            0xB8, 0x01, 0x00, 0x00, 0x00,             // mov eax, 1 (TRUE)
            // Offset 0x0E
            0xC3,                                     // ret
            
            // --- ORIGINAL TRAMPOLINE ---
            // Offset 0x0F: original
            0x90, 0x90, 0x90, 0x90, 0x90,             // orig 5 bytes
            // Offset 0x14: jmp back
            0xE9, 0x00, 0x00, 0x00, 0x00              
        };

        void* pCodecave_Io = (void*)((DWORD_PTR)pCodecave + 0x100);
        
        // Orijinal bytelari shellcode icine kopyala (Offset 0x0F)
        memcpy(&shellcode_DeviceIo[0x0F], origDeviceIo, 5);
        
        // JMP geri donus adresini hesapla
        DWORD_PTR retAddrIO = (DWORD_PTR)pDeviceIoControl + 5;
        DWORD_PTR caveEndIO = (DWORD_PTR)pCodecave_Io + 0x14 + 5;
        DWORD relJmpIO = (DWORD)(retAddrIO - caveEndIO);
        memcpy(&shellcode_DeviceIo[0x15], &relJmpIO, 4);

        WriteProcessMemory(hProc, pCodecave_Io, shellcode_DeviceIo, sizeof(shellcode_DeviceIo), NULL);
        
        // Orijinal DeviceIoControl'u JMP ile yamala
        DWORD relHookIO = (DWORD)((DWORD_PTR)pCodecave_Io - ((DWORD_PTR)pDeviceIoControl + 5));
        memcpy(&jmpInst[1], &relHookIO, 4);

        VirtualProtectEx(hProc, pDeviceIoControl, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(hProc, pDeviceIoControl, jmpInst, 5, NULL);
        VirtualProtectEx(hProc, pDeviceIoControl, 5, oldProtect, &oldProtect);

        std::cout << OBF_STR("[EXTERNAL-HOOK] DeviceIoControl AKILLI kancalandi.\n");

        CloseHandle(hProc);
        return true;
    }

    // ======================================================================
    // RIOT CLIENT HOOKS (VAN-79 / VAN-81 BYPASS)
    // ======================================================================
    // Injects shellcode into RiotClientServices.exe to bypass WinVerifyTrust 
    // or Schannel certificate validation, forcing it to accept our spoofed TLS cert.
    bool ApplyRiotClientHooks(DWORD pid) {
        HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
        if (!hProc) {
            std::cerr << OBF_STR("[EXTERNAL-HOOK] OpenProcess (Riot Client) basarisiz. Hata: ") << GetLastError() << std::endl;
            return false;
        }

        // WinVerifyTrust (Wintrust.dll) is the primary API used to validate certificates.
        // We force it to always return ERROR_SUCCESS (0).
        void* pWinVerifyTrust = (void*)GetRemoteProcAddress(hProc, "wintrust.dll", "WinVerifyTrust");
        if (!pWinVerifyTrust) {
            std::cerr << OBF_STR("[EXTERNAL-HOOK] WinVerifyTrust bulunamadi!") << std::endl;
            CloseHandle(hProc);
            return false;
        }

        std::cout << OBF_STR("[EXTERNAL-HOOK] Riot Client yakalandi. PID: ") << pid << std::endl;
        std::cout << OBF_STR("[EXTERNAL-HOOK] Injecting TLS bypass shellcode (WinVerifyTrust)...\n");

        void* pCodecave = AllocateNear(hProc, pWinVerifyTrust, 0x1000);
        if (!pCodecave) {
            CloseHandle(hProc);
            return false;
        }

        // Shellcode: xor eax, eax (0 = ERROR_SUCCESS) | ret
        BYTE shellcode_Trust[] = {
            0x31, 0xC0, // xor eax, eax
            0xC3        // ret
        };
        
        WriteProcessMemory(hProc, pCodecave, shellcode_Trust, sizeof(shellcode_Trust), NULL);

        BYTE jmpInst[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
        DWORD_PTR relativeOffset = (DWORD_PTR)pCodecave - ((DWORD_PTR)pWinVerifyTrust + 5);
        memcpy(&jmpInst[1], &relativeOffset, 4);

        DWORD oldProtect;
        VirtualProtectEx(hProc, pWinVerifyTrust, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(hProc, pWinVerifyTrust, jmpInst, 5, NULL);
        VirtualProtectEx(hProc, pWinVerifyTrust, 5, oldProtect, &oldProtect);

        std::cout << OBF_STR("[EXTERNAL-HOOK] WinVerifyTrust basariyla kancalandi. (VAN-81/79 Bypass Aktif)") << std::endl;

        CloseHandle(hProc);
        return true;
    }

} // namespace external_hook
} // namespace cg_whuq
