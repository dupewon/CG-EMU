// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for pipe_emu.h
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "heartbeat_manager.h"
#include "hwid_spoof.h"

namespace cg_whuq {
namespace pipe_emu {

    enum class VgcOpcode : uint32_t {
        AUTH_REQ      = 0x64,  // vanguard.AuthenticationRequest
        AUTH_OK       = 0x65,  // vanguard.TokenResponse
        HEARTBEAT_REQ = 0x66,  // vanguard.HeartbeatRequest
        HEARTBEAT_OK  = 0x67,  // vanguard.HeartbeatResponse
        ECHO          = 0x68,
        RAW_ECHO      = 0x69
    };

    class VgcPipeServer {
    public:
        VgcPipeServer(hwid::HwidSpoofer& spoofer);
        ~VgcPipeServer();

        bool Start();
        void Stop();

    private:
        HANDLE hPipe_;
        HANDLE hThread_;
        bool running_;
        
        hwid::HwidSpoofer& spoofer_;
        network::HeartbeatManager heartbeat_;

        static DWORD WINAPI PipeThread(LPVOID lpParam);
        void HandleClient();
        void HandlePacket(const std::vector<uint8_t>& buffer, DWORD bytesRead);

        void ProcessAuthReq(const uint8_t* body, size_t len);
        void ProcessHeartbeat(const uint8_t* body, size_t len);

        void SendTokenResponse(const std::string& access_token);
        void SendFrame(uint32_t opcode, const std::vector<uint8_t>& proto_body);
        void SendRaw(const uint8_t* data, DWORD len);

        // Legacy compat
        void SendPacket(uint32_t opcode, const std::vector<uint8_t>& payload);
    };

} // namespace pipe_emu
} // namespace cg_whuq

