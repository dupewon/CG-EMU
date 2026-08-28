// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for main.cpp
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <iostream>
#include <windows.h>
#include <thread>
#include "hwid_spoof.h"
#include "pipe_emu.h"
#include "tls_spoofer.h"
#include "heartbeat_manager.h"
#include "security_spoof.h"
#include "external_hook.h"

#ifndef OBF_STR
template <size_t N>
struct XorString {
    char data[N];
    constexpr XorString(const char* str) : data{} {
        for (size_t i = 0; i < N; ++i) data[i] = str[i] ^ 0x33;
    }
    const char* decrypt() const {
        static char decrypted[N];
        for (size_t i = 0; i < N; ++i) decrypted[i] = data[i] ^ 0x33;
        decrypted[N-1] = '\0';
        return decrypted;
    }
};
#define OBF_STR(s) (XorString<sizeof(s)>(s).decrypt())
#endif

using namespace cg_whuq;

// Arkaplanda VALORANT oyununu izleyip kancalari (shellcode) basacak döngü
DWORD WINAPI GameWatcherLoop(LPVOID lpParam) {
    bool hooked = false;
    while (!hooked) {
        DWORD pid = cg_whuq::external_hook::FindTargetProcess(L"VALORANT-Win64-Shipping.exe");
        if (pid != 0) {
            std::cout << OBF_STR("\n[WATCHER] Oyun tespit edildi! Shellcode enjeksiyonu basliyor...\n");
            if (cg_whuq::external_hook::ApplyHooks(pid)) {
                hooked = true; 
            }
        }
        Sleep(2000); 
    }
    return 0;
}

bool SpoofSCM() {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        std::cerr << "[SCM] OpenSCManager failed: " << GetLastError() << "\n";
        return false;
    }

    // acik vgc servisi kalmasin sil at
    SC_HANDLE hOld = OpenServiceA(hScm, "vgc", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (hOld) {
        SERVICE_STATUS ss = {};
        ControlService(hOld, SERVICE_CONTROL_STOP, &ss);
        // Wait up to 5 seconds for it to stop
        for (int i = 0; i < 10; ++i) {
            if (QueryServiceStatus(hOld, &ss) && ss.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(500);
        }
        DeleteService(hOld);
        CloseServiceHandle(hOld);
        Sleep(300); // Let SCM process the deletion
    }

    // Register our exe as the vgc service
    std::string binPath = std::string("\"") + exePath + "\" --service";
    SC_HANDLE hSvc = CreateServiceA(
        hScm, "vgc", "Vanguard",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        binPath.c_str(),
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hSvc) {
        DWORD err = GetLastError();
        std::cerr << "[SCM] CreateService failed: " << err << "\n";
        CloseServiceHandle(hScm);
        return false;
    }

    // Start the service
    StartServiceA(hSvc, 0, NULL);

    // Wait up to 5 seconds for SERVICE_RUNNING
    SERVICE_STATUS ss = {};
    for (int i = 0; i < 10; ++i) {
        if (QueryServiceStatus(hSvc, &ss) && ss.dwCurrentState == SERVICE_RUNNING) {
            std::cout << "[SCM] Vanguard service registered and running.\n";
            break;
        }
        Sleep(500);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return true;
}

// Probes known vgk device paths to check if the driver is already resident
// in the kernel (loaded by a previous run or real Vanguard).
// Returns true if ANY device path opens successfully — driver is alive.
static bool IsVgkKernelAlive() {
    // Vanguard's kernel driver exposes one or more of these device nodes
    static const char* kDevicePaths[] = {
        "\\\\.\\vgk",
        "\\\\.\\vgkdrvr",
        "\\\\.\\vgk0",
    };
    for (auto& path : kDevicePaths) {
        HANDLE h = CreateFileA(path, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            std::cout << "[VGK] Kernel device alive at: " << path << "\n";
            return true;
        }
        // ERROR_ACCESS_DENIED (5) still means the device EXISTS — driver is loaded
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            std::cout << "[VGK] Kernel device present (access denied) at: " << path
                      << " — driver is loaded.\n";
            return true;
        }
    }
    return false;
}

// ── Spoofed VGK Service (Kernel Driver Emulator) ──────────────────────────
// Riot Client expects the vgk service to be running. Since we removed the DLL
// and are injecting directly into the usermode, we still need to trick the SCM.
bool LoadVgkDriver() {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        std::cerr << "[VGK] OpenSCManager failed: " << GetLastError() << "\n";
        return false;
    }

    // Acik vgk servisi kalmasin sil at
    SC_HANDLE hOld = OpenServiceA(hScm, "vgk", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (hOld) {
        SERVICE_STATUS ss = {};
        ControlService(hOld, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 10; ++i) {
            if (QueryServiceStatus(hOld, &ss) && ss.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(500);
        }
        DeleteService(hOld);
        CloseServiceHandle(hOld);
        Sleep(300); // Let SCM process the deletion
    }

    // Register our exe as the vgk service (Spoofed)
    std::string binPath = std::string("\"") + exePath + "\" --service";
    SC_HANDLE hSvc = CreateServiceA(
        hScm, "vgk", "Vanguard Kernel",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, // Fake it as a Win32 service instead of KERNEL_DRIVER so it actually starts
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        binPath.c_str(),
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hSvc) {
        DWORD err = GetLastError();
        std::cerr << "[VGK] CreateService failed: " << err << "\n";
        CloseServiceHandle(hScm);
        return false;
    }

    // Start the spoofed service
    StartServiceA(hSvc, 0, NULL);

    // Wait up to 5 seconds for SERVICE_RUNNING
    SERVICE_STATUS ss = {};
    for (int i = 0; i < 10; ++i) {
        if (QueryServiceStatus(hSvc, &ss) && ss.dwCurrentState == SERVICE_RUNNING) {
            std::cout << "[VGK] Fake Vanguard Kernel (vgk) service registered and running.\n";
            break;
        }
        Sleep(500);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return true;
}

// League of Legends queries HKLM\Services\vgk BEFORE connecting to the pipe.
// If this key is absent or malformed, VAN-81 fires before any pipe communication happens.
void SpoofVgkRegistry() {
    struct RegEntry {
        const char* key;
        const char* name;
        DWORD type;
        const void* data;
        DWORD size;
    };

    // vgk — kernel driver entry
    const DWORD vgkType  = 1;  // SERVICE_KERNEL_DRIVER
    const DWORD vgkStart = 1;  // SERVICE_SYSTEM_START
    const DWORD vgkErr   = 1;  // SERVICE_ERROR_NORMAL
    const char* vgkImg   = "\\SystemRoot\\system32\\drivers\\vgk.sys";
    const char* vgkDisp  = "vgk";

    HKEY hKey = NULL;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                        "SYSTEM\\CurrentControlSet\\Services\\vgk",
                        0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "Type",         0, REG_DWORD,      (BYTE*)&vgkType,  sizeof(DWORD));
        RegSetValueExA(hKey, "Start",        0, REG_DWORD,      (BYTE*)&vgkStart, sizeof(DWORD));
        RegSetValueExA(hKey, "ErrorControl", 0, REG_DWORD,      (BYTE*)&vgkErr,   sizeof(DWORD));
        RegSetValueExA(hKey, "ImagePath",    0, REG_EXPAND_SZ,  (BYTE*)vgkImg,    (DWORD)strlen(vgkImg) + 1);
        RegSetValueExA(hKey, "DisplayName",  0, REG_SZ,         (BYTE*)vgkDisp,   (DWORD)strlen(vgkDisp) + 1);
        RegCloseKey(hKey);
        std::cout << OBF_STR("[WHUQ-REG] vgk kernel driver registry spoofed.") << std::endl;
    } else {
        std::cerr << OBF_STR("[WHUQ-REG] Failed to write vgk registry: ") << GetLastError() << std::endl;
    }

    // vgk\Security sub-key (Vanguard validates presence of this)
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                        "SYSTEM\\CurrentControlSet\\Services\\vgk\\Security",
                        0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
}

void CleanupVgkRegistry() {
    RegDeleteTreeA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vgk");
}

void SpoofVanguardInstallation() {
    std::cout << OBF_STR("\n[INSTALL-EXPLOIT] Spoofing Vanguard Installation Registry...\n");
    HKEY hKey;
    
    // 1. Windows Uninstall key
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Riot Vanguard", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        const char* disp = "Riot Vanguard";
        const char* loc = "C:\\Program Files\\Riot Vanguard";
        const char* pub = "Riot Games, Inc";
        RegSetValueExA(hKey, "DisplayName", 0, REG_SZ, (BYTE*)disp, (DWORD)strlen(disp)+1);
        RegSetValueExA(hKey, "InstallLocation", 0, REG_SZ, (BYTE*)loc, (DWORD)strlen(loc)+1);
        RegSetValueExA(hKey, "Publisher", 0, REG_SZ, (BYTE*)pub, (DWORD)strlen(pub)+1);
        RegCloseKey(hKey);
    }

    // 2. Riot Games Vanguard key
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Riot Games\\Vanguard", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        const char* loc = "C:\\Program Files\\Riot Vanguard";
        const char* ver = "1.0.0.0"; // fake version
        RegSetValueExA(hKey, "InstallDir", 0, REG_SZ, (BYTE*)loc, (DWORD)strlen(loc)+1);
        RegSetValueExA(hKey, "Version", 0, REG_SZ, (BYTE*)ver, (DWORD)strlen(ver)+1);
        RegCloseKey(hKey);
    }
    std::cout << OBF_STR("  [OK] Riot Client now thinks Vanguard is installed.\n");
}

void BypassRestartRequirement() {
    std::cout << OBF_STR("\n[RESTART-EXPLOIT] Applying system restart bypass...\n");

    // 1. Clear Vanguard's own restart flag
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Riot Games\\Vanguard", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "RequiresRestart");
        RegDeleteValueA(hKey, "RebootRequired");
        RegCloseKey(hKey);
    }

    // 2. Backdate vgk.sys to 2 days ago to bypass uptime/creation time heuristics
    char sysroot[MAX_PATH] = {};
    GetSystemDirectoryA(sysroot, MAX_PATH);
    std::string vgkPath = std::string(sysroot) + "\\drivers\\vgk.sys";

    HANDLE hFile = CreateFileA(vgkPath.c_str(), FILE_WRITE_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        FILETIME ftNow, ftSpoofed;
        GetSystemTimeAsFileTime(&ftNow);
        
        ULARGE_INTEGER uli;
        uli.LowPart = ftNow.dwLowDateTime;
        uli.HighPart = ftNow.dwHighDateTime;
        
        // Subtract 2 days (in 100-nanosecond intervals)
        // 1 sec = 10,000,000 | 1 day = 86,400,000,000,000
        const ULONGLONG twoDays = 2ULL * 86400ULL * 10000000ULL;
        uli.QuadPart -= twoDays;
        
        ftSpoofed.dwLowDateTime = uli.LowPart;
        ftSpoofed.dwHighDateTime = uli.HighPart;
        
        // Set CreationTime, LastAccessTime, LastWriteTime
        SetFileTime(hFile, &ftSpoofed, &ftSpoofed, &ftSpoofed);
        CloseHandle(hFile);
        std::cout << OBF_STR("  [OK] vgk.sys timestamp backdated to bypass boot-time check.\n");
    }
}

// Starts the real vgc.exe (from our exe's directory) as the vgc SCM service.
// This handles the actual Vanguard pipe protocol correctly.
// Our pipe emulator runs alongside for interception/fallback.
static std::string g_exeDir;

std::string GetExeDir() {
    if (!g_exeDir.empty()) return g_exeDir;
    char path[MAX_PATH] = {};
    GetModuleFileNameA(NULL, path, MAX_PATH);
    g_exeDir = path;
    auto pos = g_exeDir.find_last_of("\\/");
    if (pos != std::string::npos) g_exeDir = g_exeDir.substr(0, pos);
    return g_exeDir;
}

bool StartRealVgc() {
    std::string vgcPath = GetExeDir() + "\\vgc.exe";

    if (GetFileAttributesA(vgcPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cout << "[VGC] vgc.exe not found in exe dir, skipping real service.\n";
        return false;
    }
    std::cout << "[VGC] Found vgc.exe at: " << vgcPath << "\n";

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) { std::cerr << "[VGC] OpenSCManager failed: " << GetLastError() << "\n"; return false; }

    // Stop and remove any existing vgc service
    SC_HANDLE hOld = OpenServiceA(hScm, "vgc", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (hOld) {
        SERVICE_STATUS ss = {};
        ControlService(hOld, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 10; ++i) {
            if (QueryServiceStatus(hOld, &ss) && ss.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(400);
        }
        DeleteService(hOld);
        CloseServiceHandle(hOld);
        Sleep(300);
    }

    // Register real vgc.exe as the vgc service
    SC_HANDLE hSvc = CreateServiceA(
        hScm, "vgc", "Vanguard",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        vgcPath.c_str(), NULL, NULL, NULL, NULL, NULL
    );

    if (!hSvc) {
        std::cerr << "[VGC] CreateService failed: " << GetLastError() << "\n";
        CloseServiceHandle(hScm);
        return false;
    }

    BOOL svcStarted = StartServiceA(hSvc, 0, NULL);
    DWORD svcStartErr = GetLastError();
    if (!svcStarted && svcStartErr != ERROR_SERVICE_ALREADY_RUNNING) {
        std::cerr << "[VGC] StartService failed: " << svcStartErr << "\n";
        std::cerr << "[VGC] Note: vgc.exe must call StartServiceCtrlDispatcher to run as SCM service.\n";
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return false;
    }

    // Wait up to 10s for SERVICE_RUNNING — vgc.exe may take a moment to init
    SERVICE_STATUS ss = {};
    bool running = false;
    for (int i = 0; i < 20; ++i) {
        if (!QueryServiceStatus(hSvc, &ss)) break;
        if (ss.dwCurrentState == SERVICE_RUNNING) {
            running = true;
            break;
        }
        // SERVICE_START_PENDING (2) is normal — keep waiting
        if (ss.dwCurrentState != SERVICE_START_PENDING &&
            ss.dwCurrentState != SERVICE_STOPPED) {
            break; // unexpected state, bail early
        }
        Sleep(500);
    }

    if (running) {
        std::cout << "[VGC] Real vgc.exe service started successfully.\n";
    } else {
        std::cerr << "[VGC] vgc.exe service failed to reach RUNNING state: "
                  << ss.dwCurrentState
                  << " (Win32Err: " << ss.dwWin32ExitCode << ")\n";
        std::cerr << "[VGC] This is expected if vgc.exe is not a proper SCM service binary.\n";
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return running;
}

// Spoof registry-level HWIDs that Vanguard reads at startup.
// vgk.sys uses WMI/registry for some identifiers — spoofing these
// ensures the fake identity propagates through the kernel driver.
void SpoofRegistryHwid(const std::string& uuid, const std::string& mac) {
    // 1. MachineGuid — primary machine fingerprint used by Vanguard
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "MachineGuid", 0, REG_SZ,
                       (BYTE*)uuid.c_str(), (DWORD)uuid.size() + 1);
        RegCloseKey(hKey);
        std::cout << "  [HWID-REG] MachineGuid -> " << uuid << "\n";
    } else {
        std::cerr << "  [HWID-REG] MachineGuid write failed: " << GetLastError() << "\n";
    }

    // 2. ComputerHardwareId (Windows Setup GUID, secondary fingerprint)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "ComputerHardwareId", 0, REG_SZ,
                       (BYTE*)uuid.c_str(), (DWORD)uuid.size() + 1);
        RegCloseKey(hKey);
        std::cout << "  [HWID-REG] ComputerHardwareId -> " << uuid << "\n";
    }

    std::cout << "[HWID-REG] Registry identity spoofed.\n";
}

SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    if (CtrlCode == SERVICE_CONTROL_STOP) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerA("vgc", ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    while (g_ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(1000);
    }
}

void CreateFakeVanguardMutex() {
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\RiotVanguardMutex");
    if (hMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << OBF_STR("[WHUQ-EMU] Warning: Fake Vanguard Mutex already exists or failed.") << std::endl;
    } else {
        std::cout << OBF_STR("[WHUQ-EMU] Fake Vanguard Mutex established.") << std::endl;
    }
}

void CreateFakeVanguardSharedMemory() {
    HANDLE hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, "Global\\vgc_shared_memory");
    if (hMapFile != NULL && GetLastError() != ERROR_ALREADY_EXISTS) {
        std::cout << OBF_STR("[WHUQ-EMU] Fake Vanguard Shared Memory established.") << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--service") {
        SERVICE_TABLE_ENTRYA ServiceTable[] = {
            { (LPSTR)"vgc", (LPSERVICE_MAIN_FUNCTIONA)ServiceMain },
            { (LPSTR)"vgk", (LPSERVICE_MAIN_FUNCTIONA)ServiceMain },
            { NULL, NULL }
        };
        StartServiceCtrlDispatcherA(ServiceTable);
        return 0;
    }

    SetConsoleTitleA(OBF_STR("CG EMU - VALORANT HWID SPOOFER"));
    
    std::cout << OBF_STR("\n")
              << OBF_STR("       made by whuq  |  CheatGlobal.COM\n")
              << OBF_STR("  CheatGlobal kullanicilari icin ozel olarak kodlanmistir.\n")
              << OBF_STR("\n") << std::endl;

    // ── Step 0: Security Feature Registry Spoof ────────────────────────────────
    std::cout << OBF_STR("\n[STEP 0] Spoofing Vanguard security feature registry keys...\n");
    uint32_t secMask = cg_whuq::security_spoof::SpoofAllSecurityFeatures();
    std::cout << OBF_STR("  [OK] Security features spoofed. Mask: 0x") << std::hex << secMask << std::dec << "\n";

    std::cout << OBF_STR("[+] Initializing Dynamic Ghost Engine...") << std::endl;

    hwid::HwidSpoofer spoofer;
    if (!spoofer.Initialize()) {
        std::cerr << OBF_STR("[-] Failed to initialize cryptographic provider.") << std::endl;
        return 1;
    }

    spoofer.GenerateNewIdentity();
    std::cout << OBF_STR("[GHOST] Dynamic Identity Generated:") << std::endl;
    std::cout << OBF_STR("  [-] MAC: ") << spoofer.GetSpoofedMac() << std::endl;
    std::cout << OBF_STR("  [-] Disk Serial: ") << spoofer.GetSpoofedDiskSerial() << std::endl;
    std::cout << OBF_STR("  [-] SMBIOS UUID: ") << spoofer.GetSpoofedSmbiosUuid() << std::endl;

    std::cout << OBF_STR("\n=========================================\n");
    std::cout << OBF_STR("  [+] CG EMU - LAUNCHING COMPONENTS\n");
    std::cout << OBF_STR("=========================================\n");

    // ── Step 1: Install Spoof ──────────────────────────────────────────────────
    SpoofVanguardInstallation();

    // ── Step 1.5: Restart Requirement Bypass ───────────────────────────────────
    BypassRestartRequirement();

    // ── Step 2: Registry HWID Spoof ────────────────────────────────────────────
    std::cout << OBF_STR("\n[STEP 2] Spoofing registry-level HWID...\n");
    SpoofRegistryHwid(spoofer.GetSpoofedSmbiosUuid(), spoofer.GetSpoofedMac());

    // ── Step 3: vgk Registry Keys (Spoofs Kernel Driver Presence) ──────────────
    std::cout << OBF_STR("\n[STEP 3] Writing vgk registry entries...\n");
    SpoofVgkRegistry();

    // ── Step 4: Emulated VGC and VGK Services ──────────────────────────────────
    std::cout << OBF_STR("\n[STEP 4] Registering internal vgc and spoofed vgk services...\n");
    SpoofSCM();
    LoadVgkDriver(); // Start fake vgk!

    // ── Step 5: Mutex + Shared Memory ─────────────────────────────────────────
    std::cout << OBF_STR("\n[STEP 5] Establishing Vanguard presence objects...\n");
    CreateFakeVanguardMutex();
    CreateFakeVanguardSharedMemory();

    // ── Step 6: TLS Proxy ─────────────────────────────────────────────────────
    std::cout << OBF_STR("\n[STEP 6] Starting SChannel TLS proxy on :51820...\n");
    if (InitializeTLSSpoofer()) {
        std::cout << OBF_STR("  [OK] TLS proxy active - VAN-81/79 TLS bypass.\n");
    }

    // ── Step 7: Pipe Emulator (always runs for interception) ──────────────────
    std::cout << OBF_STR("\n[STEP 7] Starting pipe emulator (\\\\.\\pipe\\vgc)...\n");
    pipe_emu::VgcPipeServer pipeServer(spoofer);
    if (!pipeServer.Start()) {
        std::cerr << OBF_STR("  [!!] Pipe server failed to start.\n");
    } else {
        std::cout << OBF_STR("  [OK] Pipe emulator active.\n");
    }

    std::cout << OBF_STR("\n=========================================\n");
    std::cout << OBF_STR("  [READY] ALL SYSTEMS GO. PLAY NOW.\n");
    std::cout << OBF_STR("  Fake MAC   : ") << spoofer.GetSpoofedMac() << "\n";
    std::cout << OBF_STR("  Fake Serial: ") << spoofer.GetSpoofedDiskSerial() << "\n";
    std::cout << OBF_STR("  Fake UUID  : ") << spoofer.GetSpoofedSmbiosUuid() << "\n";
    std::cout << OBF_STR("=========================================\n") << std::endl;

    // ── Step 7.5: Fake Service Start ──────────────────────────
    std::cout << OBF_STR("\n[WHUQ] vgc (Riot Vanguard) baslatiliyor...\n");
    system("sc start vgc >nul 2>&1");
    system("sc start vgk >nul 2>&1");

    // ── Step 8: Riot Client Watcher (TLS Bypass Injector) ─────────────────────
    std::cout << OBF_STR("\n[STEP 8] Starting Riot Client watcher thread...\n");
    CreateThread(NULL, 0, [](LPVOID lpParam) -> DWORD {
        bool rcHooked = false;
        
        while (true) {
            // Hook Riot Client to bypass TLS certificate pinning (VAN-79 / 81)
            // Bu kanca hala GEREKLI, cunku Riot Client'in bizim sahte sertifikamizi kabul etmesi lazim
            if (!rcHooked) {
                DWORD rcPid = cg_whuq::external_hook::FindTargetProcess(L"RiotClientServices.exe");
                if (rcPid != 0) {
                    if (cg_whuq::external_hook::ApplyRiotClientHooks(rcPid)) {
                        rcHooked = true;
                    }
                }
            }

            // NOT: Oyun kancasi (VALORANT-Win64-Shipping.exe) tamamen KALDIRILDI!
            // Cünkü pipe_emu.cpp icerisindeki Protobuf manipulasyonu sayesinde oyuna
            // "Driver yüklü degil, Kernel mode kapali" dedik. Oyun artik vgk.sys'yi aramiyor!
            // Bu sayede oyunun icine shellcode basarak Anti-Cheat'in radarına girmekten kurtulduk.

            Sleep(2000); 
        }
        return 0;
    }, NULL, 0, NULL);

    // Ana thread uykuda kalsin, donguye sokmaya gerek yok (CPU yormasin). 1 saat bekle.
    Sleep(3600000); 

    pipeServer.Stop();
    ShutdownTLSSpoofer();
    
    // NOT: sc stop ve sc delete komutlari inanilmaz derecede Event Log (olay gunlugu) olusturur.
    // Riot Vanguard bu loglari okuyup hileyi aninda flagleyebilir (ban sebebi). Kaldirildi.
    
    return 0;
}
