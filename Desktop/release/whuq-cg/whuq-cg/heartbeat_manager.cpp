// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for heartbeat_manager.cpp
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "heartbeat_manager.h"
#include <iostream>
#include <random>
#include <winhttp.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")

#define OBF_STR(x) (x)


namespace cg_whuq {

// ── Minimal protobuf encoder (no external deps) ─────────────────────────────
namespace protobuf {

    const uint64_t WIRE_VARINT = 0;
    const uint64_t WIRE_64BIT  = 1;
    const uint64_t WIRE_LEN    = 2;
    const uint64_t WIRE_32BIT  = 5;


static size_t EncodeVarint(uint8_t* buf, uint64_t v) {
    size_t n = 0;
    do {
        uint8_t b = v & 0x7F; v >>= 7;
        if (v) b |= 0x80;
        buf[n++] = b;
    } while (v);
    return n;
}

static void AppendField(std::vector<uint8_t>& out, uint32_t field, uint8_t wire,
                        const uint8_t* data, size_t dlen) {
    uint8_t tag[10]; size_t tl = EncodeVarint(tag, (uint64_t(field) << 3) | wire);
    out.insert(out.end(), tag, tag + tl);
    if (wire == 2) { // boyut belirtilmis (length-delimited)
        uint8_t vl[10]; size_t ll = EncodeVarint(vl, dlen);
        out.insert(out.end(), vl, vl + ll);
    }
    out.insert(out.end(), data, data + dlen);
}

static void AppendString(std::vector<uint8_t>& out, uint32_t field, const std::string& s) {
    AppendField(out, field, 2, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

static void AppendVarint(std::vector<uint8_t>& out, uint32_t field, uint64_t val) {
    uint8_t tag[10]; size_t tl = EncodeVarint(tag, (uint64_t(field) << 3) | 0);
    out.insert(out.end(), tag, tag + tl);
    uint8_t v[10]; size_t vl = EncodeVarint(v, val);
    out.insert(out.end(), v, v + vl);
}

static uint64_t DecodeVarint(const uint8_t*& ptr, const uint8_t* end) {
    uint64_t out_val = 0;
    int shift = 0;
    while (ptr < end) {
        uint8_t b = *(ptr++);
        out_val |= (static_cast<uint64_t>(b & 0x7F) << shift);
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift >= 64) break;
    }
    return out_val;
}

} // namespace protobuf

namespace network {

HeartbeatManager::HeartbeatManager() : running_(false), hThread_(nullptr), beatCount_(0) {
    InitializeCriticalSection(&jwtLock_);
}

HeartbeatManager::~HeartbeatManager() {
    StopHeartbeat();
    DeleteCriticalSection(&jwtLock_);
}

void HeartbeatManager::StartHeartbeat() {
    if (running_) return;
    running_  = true;
    beatCount_ = 0;
    hThread_  = CreateThread(nullptr, 0, HeartbeatLoopThread, this, 0, nullptr);
    std::cout << OBF_STR("[HB] Vanguard Heartbeat started (eu.vg.ac.pvp.net)") << std::endl;
}

void HeartbeatManager::StopHeartbeat() {
    if (!running_) return;
    running_ = false;
    if (hThread_) {
        WaitForSingleObject(hThread_, 3000);
        CloseHandle(hThread_);
        hThread_ = nullptr;
    }
    std::cout << OBF_STR("[HB] Heartbeat stopped. Total beats: ") << beatCount_ << std::endl;
}

void HeartbeatManager::SetJWT(const std::string& jwt) {
    EnterCriticalSection(&jwtLock_);
    currentJwt_ = jwt;
    LeaveCriticalSection(&jwtLock_);
    std::cout << OBF_STR("[HB] JWT registered (len=") << jwt.size() << OBF_STR(")") << std::endl;
}

DWORD WINAPI HeartbeatManager::HeartbeatLoopThread(LPVOID lpParam) {
    static_cast<HeartbeatManager*>(lpParam)->Loop();
    return 0;
}

// ── Build vanguard.HeartbeatRequest protobuf ────────────────────────────────
// field 1 (string): access_token   — the JWT from AuthenticationRequest
// field 2 (message): additional_requested_tasks — empty repeated field (no tasks)
std::vector<uint8_t> HeartbeatManager::BuildHeartbeatRequest(const std::string& jwt) {
    std::vector<uint8_t> proto;
    // 1. alan access_token
    protobuf::AppendString(proto, 1, jwt);
    // Field 2: additional_requested_tasks — omit (empty repeated = valid)
    // (Vanguard fills this with scan tasks when it wants the client to do something)
    
    // YENI EKLENEN: Vanguard'in bekledigi field 12 (Modules) ve field 16 (Tasks/State)
    // Eger bu alanlar bos olursa sunucu (val 5) yasaklamasi veya 429 atabilir.
    // Biz buraya sahte module listeleri ve state flag'leri (tamami temiz) basacagiz.
    
    // Field 12: Modules (sahte vgc.exe, vgk.sys ve temel windows dll'leri)
    // DUZELTME: Vanguard sunucusu Field 12'yi basit bir string dizisi olarak beklemez.
    // Her bir eleman bir Module Struct (message) olmalidir:
    // field 1: mod_name (string)
    // field 2: base_addr (uint64)
    // field 3: image_size (uint32)
    
    // vgc.exe
    std::vector<uint8_t> mod1;
    protobuf::AppendString(mod1, 1, "vgc.exe");
    protobuf::AppendVarint(mod1, 2, 0x140000000ULL);
    protobuf::AppendVarint(mod1, 3, 0x1A0000);
    protobuf::AppendField(proto, 12, 2, mod1.data(), mod1.size());

    // vgk.sys
    std::vector<uint8_t> mod2;
    protobuf::AppendString(mod2, 1, "vgk.sys");
    protobuf::AppendVarint(mod2, 2, 0xFFFFF80112340000ULL); // Kernel space addr
    protobuf::AppendVarint(mod2, 3, 0x480000);
    protobuf::AppendField(proto, 12, 2, mod2.data(), mod2.size());

    // ntdll.dll
    std::vector<uint8_t> mod3;
    protobuf::AppendString(mod3, 1, "ntdll.dll");
    protobuf::AppendVarint(mod3, 2, 0x7FFA8F9B0000ULL);
    protobuf::AppendVarint(mod3, 3, 0x200000);
    protobuf::AppendField(proto, 12, 2, mod3.data(), mod3.size());
    
    // Field 16: State/Task Status (her sey temiz = 0 veya 1)
    std::vector<uint8_t> state_msg;
    protobuf::AppendVarint(state_msg, 1, 1); // 1 = Secure/Running
    protobuf::AppendVarint(state_msg, 2, 0); // 0 = No threats detected
    protobuf::AppendField(proto, 16, 2, state_msg.data(), state_msg.size());

    return proto;
}

// ── Build vanguard.TaskResultRequest (sent if HeartbeatResponse has tasks) ──
// field 1 (string): access_token
// field 2 (repeated message): completed task results
std::vector<uint8_t> HeartbeatManager::BuildTaskResultRequest(const std::string& jwt, const std::vector<uint64_t>& task_ids) {
    std::vector<uint8_t> proto;
    protobuf::AppendString(proto, 1, jwt);
    
    // Her bir task ID icin onay paketi (TaskResult) olusturalim
    for (uint64_t t_id : task_ids) {
        std::vector<uint8_t> tr_msg;
        // field 1: task_id (uint64)
        protobuf::AppendVarint(tr_msg, 1, t_id);
        // field 2: status (uint32) = 0 (Success)
        protobuf::AppendVarint(tr_msg, 2, 0);
        // field 3: payload (opsiyonel) = bos birakabiliriz veya kucuk bi buffer atabiliriz
        
        // Bu TaskResult message'ini ana protoya (field 2) ekle
        protobuf::AppendField(proto, 2, 2, tr_msg.data(), tr_msg.size());
    }
    
    return proto;
}

// ── HTTP send with retry ─────────────────────────────────────────────────────
bool HeartbeatManager::SendHeartbeatHTTP(const std::string& jwt) {
    bool success = false;

    // vgc.exe yi dinlerken buldugumuz Vanguard gateway endpointleri
    struct {
        const wchar_t* host;
        INTERNET_PORT  port;
        const wchar_t* path;
    } endpoints[] = {
        { L"eu.vg.ac.pvp.net",  443, L"/vanguard/v1/gateway" },
        { L"na.vg.ac.pvp.net",  443, L"/vanguard/v1/gateway" },
        { L"ap.vg.ac.pvp.net",  443, L"/vanguard/v1/gateway" },
    };

    // protobuf payloadini burda hazirliyoz
    std::vector<uint8_t> payload = BuildHeartbeatRequest(jwt);

    // TLS i dinleyip cektigimiz headerlar:
    //   Content-Type: application/x-protobuf
    //   X-VG-1: 1        (vanguard protocol version)
    //   Accept: application/x-protobuf
    std::wstring wjwt(jwt.begin(), jwt.end());
    std::wstring headers =
        L"Content-Type: application/x-protobuf\r\n"
        L"Accept: application/x-protobuf\r\n"
        L"X-VG-1: 1\r\n"
        L"X-VG-Auth: " + wjwt + L"\r\n"
        L"User-Agent: RiotClient/0.0.0.0 vanguard-ares/1.0\r\n";

    HINTERNET hSession = WinHttpOpen(
        L"RiotClient/0.0.0.0 vanguard-ares/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) {
        std::cerr << OBF_STR("[HB] WinHttpOpen failed: ") << GetLastError() << std::endl;
        return false;
    }

    // once ana endpointe bi istek atalim
    HINTERNET hConn = WinHttpConnect(hSession, endpoints[0].host, endpoints[0].port, 0);
    if (hConn) {
        HINTERNET hReq = WinHttpOpenRequest(
            hConn,
            L"POST",
            endpoints[0].path,
            L"HTTP/1.1",
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );
        if (hReq) {
            // Ignore certificate errors for bypass context
            DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));

            BOOL sent = WinHttpSendRequest(
                hReq,
                headers.c_str(), static_cast<DWORD>(-1),
                payload.data(), static_cast<DWORD>(payload.size()),
                static_cast<DWORD>(payload.size()),
                0
            );
            if (sent && WinHttpReceiveResponse(hReq, nullptr)) {
                DWORD status = 0, sz = sizeof(status);
                WinHttpQueryHeaders(hReq,
                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX,
                    &status, &sz, WINHTTP_NO_HEADER_INDEX);

                if (status == 200 || status == 204) {
                    beatCount_++;
                    success = true;
                    std::cout << OBF_STR("[HB] Beat #") << beatCount_
                              << OBF_STR(" OK (HTTP ") << status << OBF_STR(")") << std::endl;
                              
                    // Eger status 200 ise (204 degilse), response body icinde additional_requested_tasks olabilir
                    if (status == 200) {
                        DWORD bytesAvailable = 0;
                        if (WinHttpQueryDataAvailable(hReq, &bytesAvailable) && bytesAvailable > 0) {
                            std::vector<uint8_t> respBuffer(bytesAvailable);
                            DWORD bytesRead = 0;
                            if (WinHttpReadData(hReq, respBuffer.data(), bytesAvailable, &bytesRead)) {
                                // Gelen protobuf yanitini (HeartbeatResponse) parse et
                                // field 2 -> additional_requested_tasks (repeated Task)
                                std::vector<uint64_t> task_ids;
                                const uint8_t* ptr = respBuffer.data();
                                const uint8_t* end = ptr + bytesRead;
                                
                                while (ptr < end) {
                                    uint64_t tag = protobuf::DecodeVarint(ptr, end);
                                    uint32_t fieldNum = tag >> 3;
                                    uint32_t wireType = tag & 7;

                                    if (fieldNum == 2 && wireType == protobuf::WIRE_LEN) {
                                        uint64_t msgLen = protobuf::DecodeVarint(ptr, end);
                                        const uint8_t* msgEnd = ptr + msgLen;
                                        
                                        while (ptr < msgEnd) {
                                            uint64_t innerTag = protobuf::DecodeVarint(ptr, msgEnd);
                                            uint32_t innerField = innerTag >> 3;
                                            uint32_t innerWire = innerTag & 7;
                                            
                                            if (innerField == 1 && innerWire == protobuf::WIRE_VARINT) {
                                                uint64_t taskId = protobuf::DecodeVarint(ptr, msgEnd);
                                                task_ids.push_back(taskId);
                                            } else if (innerWire == protobuf::WIRE_VARINT) {
                                                protobuf::DecodeVarint(ptr, msgEnd);
                                            } else if (innerWire == protobuf::WIRE_64BIT) {
                                                ptr += 8;
                                            } else if (innerWire == protobuf::WIRE_LEN) {
                                                uint64_t skipLen = protobuf::DecodeVarint(ptr, msgEnd);
                                                ptr += skipLen;
                                            } else if (innerWire == protobuf::WIRE_32BIT) {
                                                ptr += 4;
                                            }
                                        }
                                        ptr = msgEnd;
                                    } else {
                                        if (wireType == protobuf::WIRE_VARINT) protobuf::DecodeVarint(ptr, end);
                                        else if (wireType == protobuf::WIRE_64BIT) ptr += 8;
                                        else if (wireType == protobuf::WIRE_LEN) {
                                            uint64_t skipLen = protobuf::DecodeVarint(ptr, end);
                                            ptr += skipLen;
                                        } else if (wireType == protobuf::WIRE_32BIT) ptr += 4;
                                    }
                                }

                                if (!task_ids.empty()) {
                                    std::cout << OBF_STR("[HB] Sunucudan ") << task_ids.size() << OBF_STR(" ek gorev geldi. Sahte TaskResultRequest (Success) hazirlaniyor...") << std::endl;
                                    for (uint64_t t_id : task_ids) {
                                        std::cout << OBF_STR("  -> Gorev ID: ") << t_id << OBF_STR(" onaylandi.") << std::endl;
                                    }
                                    
                                    // TaskResultRequest'i hemen gonderelim ki sunucu kudurmasin (timeout atmasin)
                                    std::vector<uint8_t> trq = BuildTaskResultRequest(jwt, task_ids);
                                    
                                    // Simdi yollayalim 
                                    HINTERNET hTaskReq = WinHttpOpenRequest(
                                        hConn,
                                        L"POST",
                                        endpoints[0].path, // ayni endpoint
                                        L"HTTP/1.1",
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE
                                    );
                                    if (hTaskReq) {
                                        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                                                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                                                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                                                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
                                        WinHttpSetOption(hTaskReq, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
                                        
                                        if (WinHttpSendRequest(hTaskReq, headers.c_str(), static_cast<DWORD>(-1),
                                                               trq.data(), static_cast<DWORD>(trq.size()),
                                                               static_cast<DWORD>(trq.size()), 0)) {
                                            if (WinHttpReceiveResponse(hTaskReq, nullptr)) {
                                                std::cout << OBF_STR("[HB] Sahte TaskResultRequest basariyla sunucuya yedirildi.") << std::endl;
                                            }
                                        }
                                        WinHttpCloseHandle(hTaskReq);
                                    }
                                }
                            }
                        }
                    }
                } else if (status == 429) {
                    std::cout << OBF_STR("[HB] Rate limited (429) — backing off 60s") << std::endl;
                    Sleep(60000);
                } else if (status == 401 || status == 403) {
                    std::cout << OBF_STR("[HB] Auth rejected (") << status
                              << OBF_STR(") — JWT may be expired") << std::endl;
                } else {
                    std::cout << OBF_STR("[HB] Gateway returned ") << status << std::endl;
                }
            } else {
                std::cout << OBF_STR("[HB] SendRequest failed: ") << GetLastError() << std::endl;
            }
            WinHttpCloseHandle(hReq);
        }
        WinHttpCloseHandle(hConn);
    }
    WinHttpCloseHandle(hSession);
    return success;
}

// ── Jitter delay (Vanguard uses ~4 minute intervals with ±20s jitter) ────────
void HeartbeatManager::JitterDelay() {
    std::mt19937 gen(static_cast<uint32_t>(GetTickCount64()));
    std::uniform_int_distribution<> d(220000, 260000); // 3:40 – 4:20 range
    int total = d(gen), slept = 0;
    while (running_ && slept < total) {
        Sleep(1000);
        slept += 1000;
    }
}

// ── Main heartbeat loop ───────────────────────────────────────────────────────
void HeartbeatManager::Loop() {
    // Initial delay to let auth complete
    Sleep(3000);

    while (running_) {
        std::string token;
        EnterCriticalSection(&jwtLock_);
        token = currentJwt_;
        LeaveCriticalSection(&jwtLock_);

        if (!token.empty()) {
            SendHeartbeatHTTP(token);
        } else {
            std::cout << OBF_STR("[HB] No JWT yet, waiting...") << std::endl;
            Sleep(5000);
            continue;
        }

        JitterDelay();
    }
}

} // namespace network
} // namespace cg_whuq
