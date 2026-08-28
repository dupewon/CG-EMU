// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for heartbeat_manager.h
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#pragma once

#include <string>
#include <vector>
#include <windows.h>

namespace cg_whuq {
namespace network {

    class HeartbeatManager {
    public:
        HeartbeatManager();
        ~HeartbeatManager();

        // Starts the automated background heartbeat and gateway sync thread
        void StartHeartbeat();
        void StopHeartbeat();
        bool SendHeartbeatHTTP(const std::string& jwt);

        // Sets the JWT token received from the Pipe auth request
        void SetJWT(const std::string& jwt);

    private:
        std::string puuid_;
        std::string currentJwt_;
        CRITICAL_SECTION jwtLock_;
        uint32_t beatCount_;

        bool running_;
        HANDLE hThread_;

        static DWORD WINAPI HeartbeatLoopThread(LPVOID lpParam);
        void Loop();

        // Build vanguard.HeartbeatRequest protobuf payload
        std::vector<uint8_t> BuildHeartbeatRequest(const std::string& jwt);
        std::vector<uint8_t> BuildTaskResultRequest(const std::string& jwt, const std::vector<uint64_t>& task_ids);

        // Random jitter delay ~4 minutes (Vanguard interval)
        void JitterDelay();
    };

} // namespace network
} // namespace cg_whuq

