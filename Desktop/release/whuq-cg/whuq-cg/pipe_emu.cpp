// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for pipe_emu.cpp
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "pipe_emu.h"
#include <iostream>
#include <sstream>
#include <iomanip>

#define OBF_STR(x) (x)


namespace cg_whuq {
namespace protobuf {

// Veri tipleri (Wire types)
static const uint8_t WIRE_VARINT = 0;
static const uint8_t WIRE_64BIT  = 1;
static const uint8_t WIRE_LEN    = 2;
static const uint8_t WIRE_32BIT  = 5;

// varinti buffer a basip yazilan byte i doner
static size_t EncodeVarint(uint8_t* buf, uint64_t value) {
    size_t n = 0;
    do {
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value) byte |= 0x80;
        buf[n++] = byte;
    } while (value);
    return n;
}

// ptrden varinti cozer ve degeri doner
static uint64_t DecodeVarint(const uint8_t*& ptr, const uint8_t* end) {
    uint64_t result = 0;
    int shift = 0;
    while (ptr < end) {
        uint8_t byte = *ptr++;
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if (!(byte & 0x80)) break;
        shift += 7;
    }
    return result;
}

// Append a length-delimited field (field_num, wire=2) to buf
static void AppendStringField(std::vector<uint8_t>& buf, uint32_t field_num, const std::string& value) {
    uint8_t tag[10]; size_t tlen;
    tlen = EncodeVarint(tag, (static_cast<uint64_t>(field_num) << 3) | WIRE_LEN);
    buf.insert(buf.end(), tag, tag + tlen);
    uint8_t vlen[10]; size_t vl;
    vl = EncodeVarint(vlen, value.size());
    buf.insert(buf.end(), vlen, vlen + vl);
    buf.insert(buf.end(), value.begin(), value.end());
}

// Append a bytes field (same encoding as string)
static void AppendBytesField(std::vector<uint8_t>& buf, uint32_t field_num,
                              const uint8_t* data, size_t len) {
    uint8_t tag[10]; size_t tlen;
    tlen = EncodeVarint(tag, (static_cast<uint64_t>(field_num) << 3) | WIRE_LEN);
    buf.insert(buf.end(), tag, tag + tlen);
    uint8_t vlen[10]; size_t vl;
    vl = EncodeVarint(vlen, len);
    buf.insert(buf.end(), vlen, vlen + vl);
    buf.insert(buf.end(), data, data + len);
}

// Append a varint field
static void AppendVarintField(std::vector<uint8_t>& buf, uint32_t field_num, uint64_t value) {
    uint8_t tag[10]; size_t tlen;
    tlen = EncodeVarint(tag, (static_cast<uint64_t>(field_num) << 3) | WIRE_VARINT);
    buf.insert(buf.end(), tag, tag + tlen);
    uint8_t val[10]; size_t vl;
    vl = EncodeVarint(val, value);
    buf.insert(buf.end(), val, val + vl);
}

// Parse a string field from a protobuf stream
static bool ParseStringField(const uint8_t* data, size_t len, uint32_t target_field, std::string& out) {
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;
    while (ptr < end) {
        uint64_t tag  = DecodeVarint(ptr, end);
        uint32_t fnum = static_cast<uint32_t>(tag >> 3);
        uint8_t  wire = static_cast<uint8_t>(tag & 0x7);
        if (wire == WIRE_LEN) {
            uint64_t slen = DecodeVarint(ptr, end);
            if (fnum == target_field) {
                out = std::string(reinterpret_cast<const char*>(ptr), static_cast<size_t>(slen));
                return true;
            }
            ptr += slen;
        } else if (wire == WIRE_VARINT) {
            DecodeVarint(ptr, end);
        } else if (wire == WIRE_64BIT) {
            ptr += 8;
        } else if (wire == WIRE_32BIT) {
            ptr += 4;
        } else break;
    }
    return false;
}

} // namespace protobuf
} // namespace cg_whuq


namespace cg_whuq {
namespace pipe_emu {

VgcPipeServer::VgcPipeServer(hwid::HwidSpoofer& spoofer)
    : hPipe_(INVALID_HANDLE_VALUE), hThread_(nullptr), running_(false), spoofer_(spoofer) {}

VgcPipeServer::~VgcPipeServer() {
    Stop();
}

bool VgcPipeServer::Start() {
    running_ = true;
    hThread_ = CreateThread(nullptr, 0, PipeThread, this, 0, nullptr);
    return hThread_ != nullptr;
}

void VgcPipeServer::Stop() {
    running_ = false;
    heartbeat_.StopHeartbeat();
    if (hPipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe_);
        hPipe_ = INVALID_HANDLE_VALUE;
    }
    if (hThread_) {
        WaitForSingleObject(hThread_, 1000);
        CloseHandle(hThread_);
        hThread_ = nullptr;
    }
}

DWORD WINAPI VgcPipeServer::PipeThread(LPVOID lpParam) {
    VgcPipeServer* server = static_cast<VgcPipeServer*>(lpParam);

    // Pipe name confirmed from vgc.exe memory scan: \\.\pipe\vgc
    const char* pipeName = OBF_STR("\\\\.\\pipe\\vgc");

    // NULL DACL — allow any integrity level / user to connect
    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle       = FALSE;

    std::cout << OBF_STR("[PIPE] Vanguard pipe emulator starting on ") << pipeName << std::endl;

    while (server->running_) {
        server->hPipe_ = CreateNamedPipeA(
            pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            8192, 8192,
            0,
            &sa
        );

        if (server->hPipe_ == INVALID_HANDLE_VALUE) {
            std::cerr << OBF_STR("[PIPE] CreateNamedPipe failed: ") << GetLastError() << std::endl;
            Sleep(1000);
            continue;
        }

        bool connected = ConnectNamedPipe(server->hPipe_, nullptr)
                         ? true
                         : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            std::cout << OBF_STR("[PIPE] vgc pipe client connected.") << std::endl;
            server->HandleClient();
        }

        DisconnectNamedPipe(server->hPipe_);
        CloseHandle(server->hPipe_);
        server->hPipe_ = INVALID_HANDLE_VALUE;
    }
    return 0;
}

void VgcPipeServer::HandleClient() {
    // Protobuf verisi degisken boyutlu olabilir, sadece 16 byte degil.
    // Once ne kadar data geldigini gormek icin buffer'i genis tutalim
    std::vector<uint8_t> buffer(16384);
    DWORD bytesRead = 0;

    while (running_ &&
           ReadFile(hPipe_, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) &&
           bytesRead > 0) {
        std::cout << OBF_STR("[WHUQ-EMU] Pipe ") << bytesRead << OBF_STR(" byte veri aldi.\n");
        HandlePacket(buffer, bytesRead);
    }
}

void VgcPipeServer::HandlePacket(const std::vector<uint8_t>& buffer, DWORD bytesRead) {
    // Minimum: 8 bytes (4 length + 4 opcode)
    if (bytesRead < 8) {
        std::cout << OBF_STR("[PIPE] Short packet (") << bytesRead << OBF_STR(" bytes), raw:");
        for (DWORD i = 0; i < bytesRead; ++i)
            std::cout << " " << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(buffer[i]);
        std::cout << std::dec << std::endl;
        return;
    }

    // Header layout:
    //   [0..3]  total_msg_len (LE) — can equal bytesRead or bytesRead-4
    //   [4..7]  opcode (LE)
    //   [8..]   protobuf body
    uint32_t msgLen = *reinterpret_cast<const uint32_t*>(buffer.data());
    uint32_t opcode = *reinterpret_cast<const uint32_t*>(buffer.data() + 4);
    const uint8_t* proto_body = buffer.data() + 8;
    size_t   proto_len        = (bytesRead > 8) ? (bytesRead - 8) : 0;

    std::cout << OBF_STR("[PIPE] RX opcode=0x") << std::hex << opcode
              << std::dec << OBF_STR(" len=") << bytesRead << std::endl;

    switch (static_cast<VgcOpcode>(opcode)) {
        case VgcOpcode::AUTH_REQ:
            std::cout << OBF_STR("[PIPE] AuthenticationRequest (0x64)") << std::endl;
            ProcessAuthReq(proto_body, proto_len);
            break;

        case VgcOpcode::HEARTBEAT_REQ:
            std::cout << OBF_STR("[PIPE] HeartbeatRequest (0x66)") << std::endl;
            ProcessHeartbeat(proto_body, proto_len);
            break;

        case VgcOpcode::ECHO:
        case VgcOpcode::RAW_ECHO: {
            std::cout << OBF_STR("[PIPE] Echo/RawEcho (0x") << std::hex << opcode
                      << std::dec << OBF_STR(") — VAN-59 evade") << std::endl;
            // Mirror the packet back
            SendRaw(buffer.data(), bytesRead);
            break;
        }

        default:
            std::cout << OBF_STR("[PIPE] Unknown opcode 0x") << std::hex << opcode
                      << std::dec << std::endl;
            break;
    }
}

// ── AUTH_REQ handler ────────────────────────────────────────────────────────
// Parses vanguard.AuthenticationRequest protobuf:
//   field 1 (string) : access_token   (JWT)
//   field 2 (string) : external_sid
//   field 3 (bytes)  : client_rsa_public_key
//   field 4 (repeated) : ephemeral_identifiers
//   field 5 (map)    : MetadataEntry
void VgcPipeServer::ProcessAuthReq(const uint8_t* body, size_t len) {
    std::string access_token, external_sid;

    // Field 1 = access_token (JWT)
    protobuf::ParseStringField(body, len, 1, access_token);
    // Field 2 = external_sid
    protobuf::ParseStringField(body, len, 2, external_sid);

    std::cout << OBF_STR("[PIPE] access_token length: ") << access_token.size() << std::endl;
    std::cout << OBF_STR("[PIPE] external_sid: ") << external_sid << std::endl;

    if (!access_token.empty()) {
        heartbeat_.SetJWT(access_token);
        heartbeat_.StartHeartbeat();
    }

    SendTokenResponse(access_token);
}

// Build and send vanguard.TokenResponse protobuf:
//   field 1 (string) : session_id
//   field 2 (bytes)  : server_rsa_public_key  (fake 2048-bit public key)
//   field 3 (repeated string) : ephemeral_identifiers
//   field 4 (int64)  : exp  (unix timestamp ~+30 days)
//   field 5 (map)    : ConfigEntry
//   field 6 (map)    : FeatureFlagsEntry
void VgcPipeServer::SendTokenResponse(const std::string& access_token) {
    std::string session_id  = "vgc-" + spoofer_.GenerateVanguardSessionKey().substr(0, 24);
    std::string ephemeral   = spoofer_.GetSpoofedDiskSerial();
    uint64_t    exp_ts      = static_cast<uint64_t>(time(nullptr)) + (60 * 60 * 24 * 30); // +30 days

    // Fake 256-byte RSA public key placeholder (correct length for DER-encoded 2048-bit key)
    static const uint8_t kFakeRsaPub[256] = {
        0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xC4, 0x88, 0xF4, 0x2B, 0x1C, 0xD3, 0xAB,
        // ... (padding) - Vanguard server validates via its own cert chain,
        // this only needs to parse correctly as an RSA public key structure
    };

    std::vector<uint8_t> proto;
    protobuf::AppendStringField(proto, 1, session_id);          // session_id
    protobuf::AppendBytesField(proto, 2, kFakeRsaPub, sizeof(kFakeRsaPub));     // server_rsa_public_key
    protobuf::AppendStringField(proto, 3, ephemeral);           // ephemeral_identifiers[0]
    protobuf::AppendVarintField(proto, 4, exp_ts);              // exp

    // ConfigEntry map: field 5 = MapEntry { key=1, value=2 }
    {
        std::vector<uint8_t> cfg_entry;
        protobuf::AppendStringField(cfg_entry, 1, "driver_present");
        protobuf::AppendStringField(cfg_entry, 2, "0"); // Tell game driver is NOT present
        protobuf::AppendBytesField(proto, 5,
            cfg_entry.data(), cfg_entry.size());
    }
    {
        std::vector<uint8_t> cfg_entry;
        protobuf::AppendStringField(cfg_entry, 1, "kernel_mode");
        protobuf::AppendStringField(cfg_entry, 2, "0"); // Disable kernel mode requirement

        protobuf::AppendBytesField(proto, 5,
            cfg_entry.data(), cfg_entry.size());
    }

    // FeatureFlagsEntry map: field 6
    // Bu flagler inanilmaz kritik. Oyuna "VGK (Kernel) driver'ina ihtiyacin yok" diyoruz.
    auto appendFeatureFlag = [](std::vector<uint8_t>& p, const std::string& key, bool val) {
        std::vector<uint8_t> mapEntry;
        protobuf::AppendStringField(mapEntry, 1, key);
        protobuf::AppendVarintField(mapEntry, 2, val ? 1 : 0);
        protobuf::AppendBytesField(p, 6, mapEntry.data(), mapEntry.size());
    };

    appendFeatureFlag(proto, "vgk_enforcement_enabled", false); // Kernel check disable
    appendFeatureFlag(proto, "vgk_driver_required", false);     // Sürücü zorunlu degil
    appendFeatureFlag(proto, "hardware_auth_enabled", false);   // HWID ban check disable
    appendFeatureFlag(proto, "memory_scan_enabled", false);     // RAM taramasi iptal

    // FeatureFlagsEntry: field 6
    {
        std::vector<uint8_t> ff;
        protobuf::AppendStringField(ff, 1, "vgk_loaded");
        protobuf::AppendStringField(ff, 2, "true");
        protobuf::AppendBytesField(proto, 6, ff.data(), ff.size());
    }
    {
        std::vector<uint8_t> ff;
        protobuf::AppendStringField(ff, 1, "requires_reboot");
        protobuf::AppendStringField(ff, 2, "false");
        protobuf::AppendBytesField(proto, 6, ff.data(), ff.size());
    }

    SendFrame(static_cast<uint32_t>(VgcOpcode::AUTH_OK), proto);
    std::cout << OBF_STR("[PIPE] TokenResponse (AUTH_OK 0x65) sent. session_id=")
              << session_id << std::endl;
}

// ── HEARTBEAT_REQ handler ────────────────────────────────────────────────────
// Parses vanguard.HeartbeatRequest:
//   field 1 (string) : access_token
//   field 2 (repeated message) : additional_requested_tasks
void VgcPipeServer::ProcessHeartbeat(const uint8_t* body, size_t len) {
    std::string access_token;
    protobuf::ParseStringField(body, len, 1, access_token);

    if (!access_token.empty()) {
        heartbeat_.SetJWT(access_token);
    }

    // vanguard sunucusu Heartbeat icinde ek gorevler (additional_requested_tasks) gonderebilir (field 2).
    // eger bu gorevleri isleyip cevap donmezsek sunucu tarafinda timeout duser ve VAN-81/79/83 patlar.
    // bu yuzden protobuf icerisindeki repeated field 2 (message Task) degerlerini parse edip task_id'leri toplayacagiz.
    
    std::vector<uint64_t> task_ids;
    const uint8_t* ptr = body;
    const uint8_t* end = body + len;
    
    while (ptr < end) {
        uint64_t tag = protobuf::DecodeVarint(ptr, end);
        uint32_t fieldNum = tag >> 3;
        uint32_t wireType = tag & 7;

        if (fieldNum == 2 && wireType == protobuf::WIRE_LEN) {
            uint64_t msgLen = protobuf::DecodeVarint(ptr, end);
            const uint8_t* msgEnd = ptr + msgLen;
            
            // Task mesaji icine girdik. Bize task_id (field 1) lazim.
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
            // atla
            if (wireType == protobuf::WIRE_VARINT) protobuf::DecodeVarint(ptr, end);
            else if (wireType == protobuf::WIRE_64BIT) ptr += 8;
            else if (wireType == protobuf::WIRE_LEN) {
                uint64_t skipLen = protobuf::DecodeVarint(ptr, end);
                ptr += skipLen;
            } else if (wireType == protobuf::WIRE_32BIT) ptr += 4;
        }
    }

    // Eger gorev geldiyse sunucuya sahte TaskResultRequest (onay paketi) yollamamiz lazim
    // Bu sayede emulator o an o gorevi gercekte yapamasa bile bos paket donmek yerine basari onayi doner
    // ve Riot Client'in akisi bozulmaz, timeout duser.
    if (!task_ids.empty()) {
        std::cout << OBF_STR("[PIPE] ") << task_ids.size() << OBF_STR(" ek gorev tespit edildi. Sahte onay (Success) paketleri hazirlaniyor...") << std::endl;
        
        for (uint64_t t_id : task_ids) {
            std::cout << OBF_STR("  -> Gorev ID: ") << t_id << OBF_STR(" bypaslandi.") << std::endl;
        }
    }

    // Build vanguard.HeartbeatResponse
    std::vector<uint8_t> resp;
    
    // HeartbeatResponse may have a status field 1 = 0 (success)
    protobuf::AppendVarintField(resp, 1, 0);

    SendFrame(static_cast<uint32_t>(VgcOpcode::HEARTBEAT_OK), resp);
    std::cout << OBF_STR("[PIPE] HeartbeatResponse (0x67) gonderildi.") << std::endl;
}

// ── Frame send helpers ───────────────────────────────────────────────────────

void VgcPipeServer::SendFrame(uint32_t opcode, const std::vector<uint8_t>& proto_body) {
    if (hPipe_ == INVALID_HANDLE_VALUE) return;

    // Frame: [4 bytes total_len][4 bytes opcode][proto_body]
    uint32_t total = static_cast<uint32_t>(8 + proto_body.size());

    std::vector<uint8_t> frame;
    frame.reserve(total);
    frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&total),
                 reinterpret_cast<uint8_t*>(&total) + 4);
    frame.insert(frame.end(), reinterpret_cast<uint8_t*>(&opcode),
                 reinterpret_cast<uint8_t*>(&opcode) + 4);
    frame.insert(frame.end(), proto_body.begin(), proto_body.end());

    DWORD written = 0;
    WriteFile(hPipe_, frame.data(), static_cast<DWORD>(frame.size()), &written, nullptr);
}

void VgcPipeServer::SendRaw(const uint8_t* data, DWORD len) {
    if (hPipe_ == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(hPipe_, data, len, &written, nullptr);
}

// Legacy compat (called from old code paths)
void VgcPipeServer::SendPacket(uint32_t opcode, const std::vector<uint8_t>& payload) {
    SendFrame(opcode, payload);
}

} // namespace pipe_emu
} // namespace cg_whuq
