#pragma once
#include <windows.h>
#include <cstdint>

// Bu fonksiyon eger bir DLL yazip dogrudan VALORANT veya Riot Client 
// icine inject ediyorsan (Internal Hook) kullanilmalidir. 
// External P/Invoke (WriteProcessMemory) kullanmaz, dogrudan process hafizasina isler.

inline bool InstallVgkHook() {
    HMODULE hKer = GetModuleHandleA("kernelbase.dll");
    if (!hKer) return false;

    void* pCreateFileW = (void*)GetProcAddress(hKer, "CreateFileW");
    if (!pCreateFileW) return false;

    // 1. x64 Mimarisi icin 2GB (Relative JMP) kuralina uyan bir Code Cave bul
    void* pCodecave = nullptr;
    for (DWORD_PTR addr = (DWORD_PTR)pCreateFileW + 0x10000; addr < (DWORD_PTR)pCreateFileW + 0x70000000; addr += 0x10000) {
        pCodecave = VirtualAlloc((void*)addr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pCodecave) break;
    }
    
    // Yakinlarda alan bulunamadiysa absolute JMP (FF 25) gerektirir ama bu senaryoda relative kullaniyoruz.
    if (!pCodecave) return false; 

    // 2. Shellcode hazirla: \\.\vgk sorgularini kes ve 0x1337BEEF (Sahte handle) don
    uint8_t shellcode[] = {
        0x50,                               // push rax
        0x48, 0x85, 0xC9,                   // test rcx, rcx
        0x74, 0x24,                         // je original (0x2A'ya atla)
        
        0x66, 0x81, 0x79, 0x08, 0x76, 0x00, // cmp word ptr [rcx+8], 'v'
        0x75, 0x1C,                         // jne original
        0x66, 0x81, 0x79, 0x0A, 0x67, 0x00, // cmp word ptr [rcx+10], 'g'
        0x75, 0x14,                         // jne original
        0x66, 0x81, 0x79, 0x0C, 0x6B, 0x00, // cmp word ptr [rcx+12], 'k'
        0x75, 0x0C,                         // jne original
        
        0x58,                               // pop rax
        0x48, 0xB8, 0xEF, 0xBE, 0x37, 0x13, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x1337BEEF
        0xC3,                               // ret
        
        // --- ORIGINAL TRAMPOLINE ---
        // Offset 0x2A
        0x58,                               // pop rax
        // Offset 0x2B (Orijinal 5 byte buraya gelecek)
        0x90, 0x90, 0x90, 0x90, 0x90,       
        // Offset 0x30 (E9 JMP komutu)
        0xE9, 0x00, 0x00, 0x00, 0x00        
    };

    // 3. Orijinal fonksiyonun ilk 5 byte'ini shellcode icine kopyala
    // Senin istedigin gibi tam 0x2B ofsetine yaziyoruz.
    memcpy(&shellcode[0x2B], pCreateFileW, 5);

    // 4. Shellcode'dan CreateFileW'nin devamina (pCreateFileW + 5) yapilacak donus JMP'ini hesapla
    // JMP komutu (0xE9) Codecave'in 0x30. offsetinde basliyor. 
    // JMP sonrasi (Instruction Pointer) = Codecave + 0x35
    int32_t relJmpBack = (int32_t)((intptr_t)pCreateFileW + 5 - ((intptr_t)pCodecave + 0x35));
    *(int32_t*)(&shellcode[0x31]) = relJmpBack; // 0x31 -> JMP displacement alani

    // 5. Shellcode'u Codecave'e yaz
    memcpy(pCodecave, shellcode, sizeof(shellcode));

    // 6. Orijinal CreateFileW'yi kancala (Hook)
    DWORD oldProtect;
    VirtualProtect(pCreateFileW, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    // *(uint8_t*)pCreateFileW = 0xE9; 
    // *(int32_t*)((uint8_t*)pCreateFileW+1) = (intptr_t)pCodecave - (intptr_t)pCreateFileW - 5;
    uint8_t* pFunc = (uint8_t*)pCreateFileW;
    pFunc[0] = 0xE9; // JMP opcode
    *(int32_t*)(&pFunc[1]) = (int32_t)((intptr_t)pCodecave - ((intptr_t)pCreateFileW + 5));

    VirtualProtect(pCreateFileW, 5, oldProtect, &oldProtect);

    // 7. Instruction Cache'i temizle (CPU pipelinelarindaki eski kodlari temizler, crash onler)
    FlushInstructionCache(GetCurrentProcess(), pCreateFileW, 5);

    return true;
}
