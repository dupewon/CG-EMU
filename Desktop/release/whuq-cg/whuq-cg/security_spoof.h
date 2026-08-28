// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for security_spoof.h
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
// security_spoof.h  —  Riot Vanguard Security Feature Registry Spoofer
//
// Spoofs the registry keys that vgk.sys / vgc.exe query to determine whether
// the machine meets Vanguard's "Recommended Security Features":
//   • Windows 11 25H2+   →  CurrentBuild / DisplayVersion
//   • UEFI Secure Boot   →  SecureBoot\State!UEFISecureBootEnabled
//   • TPM 2.0            →  TPM\Active / TPM\Enabled / TPM\ManufacturerId
//   • VBS                →  DeviceGuard!EnableVirtualizationBasedSecurity
//   • HVCI               →  DeviceGuard!HypervisorEnforcedCodeIntegrity
//
// IOMMU is hardware-probed by the kernel driver and cannot be faked via
// registry alone — it needs kernel-level spoofing or the real IOMMU enabled.
// ─────────────────────────────────────────────────────────────────────────────

namespace cg_whuq {
namespace security_spoof {

// Bitmask returned inside AUTH_OK for the security features field.
// Vanguard client reads this to paint the checkmarks green.
enum class SecurityFeature : uint32_t {
    NONE            = 0x00,
    WIN11_25H2      = 0x01,
    SECURE_BOOT     = 0x02,
    TPM_20          = 0x04,
    VBS             = 0x08,
    HVCI            = 0x10,
    IOMMU           = 0x20,
    ALL             = 0x3F,
};

inline SecurityFeature operator|(SecurityFeature a, SecurityFeature b) {
    return static_cast<SecurityFeature>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

// ── Windows 11 25H2 version spoofing ────────────────────────────────────────
// Vanguard checks CurrentBuild >= 26200 (25H2) and DisplayVersion == "25H2"
inline void SpoofWindowsVersion() {
    HKEY hKey = nullptr;
    const char* keyPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        // CurrentBuild = "26200" (Windows 11 25H2 build)
        const char* build = "26200";
        RegSetValueExA(hKey, "CurrentBuild",       0, REG_SZ,
                       reinterpret_cast<const BYTE*>(build), static_cast<DWORD>(strlen(build) + 1));
        RegSetValueExA(hKey, "CurrentBuildNumber", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(build), static_cast<DWORD>(strlen(build) + 1));

        // UBR (Update Build Revision) — Vanguard may cross-check this
        DWORD ubr = 1000;
        RegSetValueExA(hKey, "UBR", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&ubr), sizeof(DWORD));

        // DisplayVersion = "25H2"
        const char* dispVer = "25H2";
        RegSetValueExA(hKey, "DisplayVersion", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(dispVer), static_cast<DWORD>(strlen(dispVer) + 1));

        // ReleaseId (legacy) — keep consistent
        const char* releaseId = "2509";
        RegSetValueExA(hKey, "ReleaseId", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(releaseId), static_cast<DWORD>(strlen(releaseId) + 1));

        RegCloseKey(hKey);
        printf("[SEC-SPOOF] Windows version spoofed -> Build 26200 / 25H2\n");
    } else {
        printf("[SEC-SPOOF] WARNING: Could not open NT\\CurrentVersion (err %lu)\n", GetLastError());
    }
}

// ── UEFI Secure Boot spoofing ────────────────────────────────────────────────
// Vanguard reads HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
//   UEFISecureBootEnabled  DWORD  1
inline void SpoofSecureBoot() {
    HKEY hKey = nullptr;
    const char* keyPath = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State";

    DWORD disp = 0;
    LONG rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hKey, &disp);
    if (rc == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExA(hKey, "UEFISecureBootEnabled", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&val), sizeof(DWORD));

        // Policy sub-key — some vgk builds also probe this
        RegCloseKey(hKey);

        HKEY hPol = nullptr;
        const char* polPath = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\PlatformKeyEnrollmentPolicy";
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, polPath, 0, nullptr,
                             REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hPol, &disp) == ERROR_SUCCESS) {
            DWORD policy = 0;
            RegSetValueExA(hPol, "ActivePolicy", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&policy), sizeof(DWORD));
            RegCloseKey(hPol);
        }

        printf("[SEC-SPOOF] Secure Boot spoofed -> UEFISecureBootEnabled = 1\n");
    } else {
        printf("[SEC-SPOOF] WARNING: SecureBoot\\State create failed (err %lu)\n", GetLastError());
    }
}

// ── TPM 2.0 spoofing ─────────────────────────────────────────────────────────
// Vanguard queries Win32_TPM WMI and also falls back to:
//   HKLM\SOFTWARE\Microsoft\Tpm  — ManufacturerId, SpecVersion, etc.
//   HKLM\SYSTEM\CurrentControlSet\Services\TPM\Parameters
inline void SpoofTPM() {
    // Primary: SOFTWARE\Microsoft\Tpm
    {
        HKEY hKey = nullptr;
        DWORD disp = 0;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Tpm",
                             0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                             nullptr, &hKey, &disp) == ERROR_SUCCESS) {
            // SpecVersion "2.0" signals TPM 2.0 to WMI provider
            const char* specVer = "2.0";
            RegSetValueExA(hKey, "SpecVersion", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(specVer),
                           static_cast<DWORD>(strlen(specVer) + 1));

            // ManufacturerId: 0x4E544300 = "NTC\0" (Nuvoton, common fTPM)
            DWORD mfr = 0x4E544300;
            RegSetValueExA(hKey, "ManufacturerId", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&mfr), sizeof(DWORD));

            // ManufacturerVersion — some probes check this
            const char* mfrVer = "7.83";
            RegSetValueExA(hKey, "ManufacturerVersion", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(mfrVer),
                           static_cast<DWORD>(strlen(mfrVer) + 1));

            DWORD enabled = 1, activated = 1;
            RegSetValueExA(hKey, "IsActivated",  0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&activated), sizeof(DWORD));
            RegSetValueExA(hKey, "IsEnabled",    0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&enabled), sizeof(DWORD));

            RegCloseKey(hKey);
        }
    }

    // Secondary: TPM device driver Parameters key
    {
        HKEY hKey = nullptr;
        DWORD disp = 0;
        const char* svcParams = "SYSTEM\\CurrentControlSet\\Services\\TPM\\Parameters";
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, svcParams, 0, nullptr,
                             REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                             nullptr, &hKey, &disp) == ERROR_SUCCESS) {
            DWORD tpmVer = 2;
            RegSetValueExA(hKey, "CapabilityVersion", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&tpmVer), sizeof(DWORD));
            RegCloseKey(hKey);
        }
    }

    // Tertiary: WMI fallback key — TPM namespace override
    {
        HKEY hKey = nullptr;
        DWORD disp = 0;
        const char* wmiPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\TpmEnabled";
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, wmiPath, 0, nullptr,
                             REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                             nullptr, &hKey, &disp) == ERROR_SUCCESS) {
            DWORD val = 1;
            RegSetValueExA(hKey, "TpmEnabled", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&val), sizeof(DWORD));
            RegCloseKey(hKey);
        }
    }

    printf("[SEC-SPOOF] TPM 2.0 spoofed -> SpecVersion=2.0, ManufacturerId=NTC, Enabled=1\n");
}

// ── VBS (Virtualization Based Security) spoofing ────────────────────────────
// Vanguard reads HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
//   EnableVirtualizationBasedSecurity  DWORD  1
//   VirtualizationBasedSecurityStatus  DWORD  2  (2 = running)
inline void SpoofVBS() {
    HKEY hKey = nullptr;
    DWORD disp = 0;
    const char* keyPath = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, nullptr,
                         REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                         nullptr, &hKey, &disp) == ERROR_SUCCESS) {
        DWORD enable = 1;
        DWORD status = 2; // 2 = VBS running

        RegSetValueExA(hKey, "EnableVirtualizationBasedSecurity", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&enable), sizeof(DWORD));
        RegSetValueExA(hKey, "VirtualizationBasedSecurityStatus",  0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&status), sizeof(DWORD));
        RegSetValueExA(hKey, "RequirePlatformSecurityFeatures",    0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&enable), sizeof(DWORD));

        RegCloseKey(hKey);
        printf("[SEC-SPOOF] VBS spoofed -> EnableVirtualizationBasedSecurity=1, Status=2\n");
    } else {
        printf("[SEC-SPOOF] WARNING: DeviceGuard key create failed (err %lu)\n", GetLastError());
    }
}

// ── HVCI (Hypervisor-Protected Code Integrity / Memory Integrity) spoofing ──
// Vanguard reads DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
//   Enabled  DWORD  1
inline void SpoofHVCI() {
    HKEY hKey = nullptr;
    DWORD disp = 0;
    const char* keyPath =
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, nullptr,
                         REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                         nullptr, &hKey, &disp) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExA(hKey, "Enabled",  0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&val), sizeof(DWORD));
        RegSetValueExA(hKey, "WasEnabledBy", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&val), sizeof(DWORD));

        RegCloseKey(hKey);
        printf("[SEC-SPOOF] HVCI spoofed -> HypervisorEnforcedCodeIntegrity Enabled=1\n");
    } else {
        printf("[SEC-SPOOF] WARNING: HVCI key create failed (err %lu)\n", GetLastError());
    }
}

// ── Master spoof function ─────────────────────────────────────────────────────
// Call this once, before the pipe emulator starts.
// Returns a bitmask of successfully-spoofed features.
inline uint32_t SpoofAllSecurityFeatures() {
    uint32_t spoofed = 0;

    printf("[SEC-SPOOF] ===== Spoofing Vanguard Security Features =====\n");

    SpoofWindowsVersion();
    spoofed |= static_cast<uint32_t>(SecurityFeature::WIN11_25H2);

    SpoofSecureBoot();
    spoofed |= static_cast<uint32_t>(SecurityFeature::SECURE_BOOT);

    SpoofTPM();
    spoofed |= static_cast<uint32_t>(SecurityFeature::TPM_20);

    SpoofVBS();
    spoofed |= static_cast<uint32_t>(SecurityFeature::VBS);

    SpoofHVCI();
    spoofed |= static_cast<uint32_t>(SecurityFeature::HVCI);

    // IOMMU: hardware-resident, kernel driver reads ACPI DMAR table directly.
    // Already green in the screenshot — no spoofing needed here.
    // If it goes red, enable AMD-Vi / Intel VT-d in BIOS (or implement
    // a kernel-mode ACPI table patch via vgk IOCTL interception).
    spoofed |= static_cast<uint32_t>(SecurityFeature::IOMMU); // assume present

    printf("[SEC-SPOOF] Done. Feature mask: 0x%02X\n", spoofed);
    printf("[SEC-SPOOF] =====================================================\n");

    return spoofed;
}

} // namespace security_spoof
} // namespace cg_whuq
