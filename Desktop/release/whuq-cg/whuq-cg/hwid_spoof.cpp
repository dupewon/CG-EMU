// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for hwid_spoof.cpp
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "hwid_spoof.h"
#include <windows.h>
#include <bcrypt.h>
#include <sstream>
#include <iomanip>
#include <random>

#pragma comment(lib, "bcrypt.lib")

namespace cg_whuq {
namespace hwid {

    HwidSpoofer::HwidSpoofer() : hAlgProvider_(nullptr) {}

    HwidSpoofer::~HwidSpoofer() {
        if (hAlgProvider_) {
            BCryptCloseAlgorithmProvider(hAlgProvider_, 0);
        }
    }

    bool HwidSpoofer::Initialize() {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgProvider_, BCRYPT_RNG_ALGORITHM, NULL, 0);
        return NT_SUCCESS(status);
    }

    std::vector<uint8_t> HwidSpoofer::GenerateRandomBytes(size_t length) const {
        std::vector<uint8_t> buffer(length);
        if (hAlgProvider_) {
            BCryptGenRandom(hAlgProvider_, buffer.data(), (ULONG)buffer.size(), 0);
        } else {
            // BCrypt patlarsa burdan devam
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint16_t> dis(0, 255);
            for (size_t i = 0; i < length; ++i) {
                buffer[i] = static_cast<uint8_t>(dis(gen));
            }
        }
        return buffer;
    }

    std::string HwidSpoofer::BytesToHex(const std::vector<uint8_t>& bytes) const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t b : bytes) {
            ss << std::setw(2) << static_cast<int>(b);
        }
        return ss.str();
    }

    void HwidSpoofer::GenerateNewIdentity() {
        // 1. MAC Address (Format: XX-XX-XX-XX-XX-XX)
        auto macBytes = GenerateRandomBytes(6);
        // fake mac icin bitleri ayarliyoruz
        macBytes[0] = (macBytes[0] & 0xFC) | 0x02; 
        
        std::stringstream macStream;
        macStream << std::hex << std::uppercase << std::setfill('0');
        for(size_t i=0; i<6; ++i) {
            macStream << std::setw(2) << static_cast<int>(macBytes[i]);
            if(i < 5) macStream << "-";
        }
        spoofedMac_ = macStream.str();

        // 2. Disk Serial (Random 8 character hex)
        auto diskBytes = GenerateRandomBytes(4);
        spoofedDiskSerial_ = BytesToHex(diskBytes);
        for (auto & c: spoofedDiskSerial_) c = toupper(c);

        // 3. SMBIOS UUID (Format: 8-4-4-4-12 hex characters)
        auto uuidBytes = GenerateRandomBytes(16);
        // version 4 yapalim random sallasin
        uuidBytes[6] = (uuidBytes[6] & 0x0F) | 0x40;
        // variant 1 (RFC4122 standardi)
        uuidBytes[8] = (uuidBytes[8] & 0x3F) | 0x80;

        std::string hexUuid = BytesToHex(uuidBytes);
        spoofedSmbiosUuid_ = hexUuid.substr(0, 8) + "-" + 
                             hexUuid.substr(8, 4) + "-" + 
                             hexUuid.substr(12, 4) + "-" + 
                             hexUuid.substr(16, 4) + "-" + 
                             hexUuid.substr(20, 12);
    }

    std::string HwidSpoofer::GetSpoofedMac() const { return spoofedMac_; }
    std::string HwidSpoofer::GetSpoofedDiskSerial() const { return spoofedDiskSerial_; }
    std::string HwidSpoofer::GetSpoofedSmbiosUuid() const { return spoofedSmbiosUuid_; }

    std::string HwidSpoofer::GenerateVanguardSessionKey() const {
        // Riot un uyduruk session keyi genelde 64 hex karakteri olur (32 byte)
        auto keyBytes = GenerateRandomBytes(32);
        return BytesToHex(keyBytes);
    }

} // namespace hwid
} // namespace cg_whuq

