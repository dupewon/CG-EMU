// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for hwid_spoof.h
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#pragma once

#include <string>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace cg_whuq {
namespace hwid {

    class HwidSpoofer {
    public:
        HwidSpoofer();
        ~HwidSpoofer();

        // Initialize the BCrypt provider
        bool Initialize();

        // Generate a completely new identity for this session
        void GenerateNewIdentity();

        // Getters for the spoofed data
        std::string GetSpoofedMac() const;
        std::string GetSpoofedDiskSerial() const;
        std::string GetSpoofedSmbiosUuid() const;
        
        // Generates a random cryptographic session key for Vanguard Heartbeat
        std::string GenerateVanguardSessionKey() const;

    private:
        std::string spoofedMac_;
        std::string spoofedDiskSerial_;
        std::string spoofedSmbiosUuid_;

        void* hAlgProvider_; // BCrypt handle

        std::vector<uint8_t> GenerateRandomBytes(size_t length) const;
        std::string BytesToHex(const std::vector<uint8_t>& bytes) const;
    };

} // namespace hwid
} // namespace cg_whuq

