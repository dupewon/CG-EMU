// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for tls_spoofer.cpp
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include "tls_spoofer.h"
#include <iostream>
#include <vector>
#include <thread>
#include <wincrypt.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")

// ─────────────────────────────────── Globals ────────────────────────────────
static bool           g_tlsShutdown  = false;
static SOCKET         g_listenSocket = INVALID_SOCKET;
static std::thread    g_tlsThread;
static CredHandle     g_hCred        = {};
static bool           g_credValid    = false;
static PCCERT_CONTEXT g_pCert        = NULL;

// ─────────────────────────────── Cert Generation ────────────────────────────
static PCCERT_CONTEXT CreatePhantomCert() {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY  hKey  = 0;
    const char* kContainer = "WHUQTLSv2Container";

    // Nuke stale container from any previous run
    CryptAcquireContextA(&hProv, kContainer, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
    hProv = 0;

    if (!CryptAcquireContextA(&hProv, kContainer, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        std::cerr << "[WHUQ-TLS] CryptAcquireContext failed: 0x"
                  << std::hex << GetLastError() << std::dec << "\n";
        return NULL;
    }

    // AT_SIGNATURE — required by CertCreateSelfSignCertificate when passing raw HCRYPTPROV
    if (!CryptGenKey(hProv, AT_SIGNATURE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey)) {
        std::cerr << "[WHUQ-TLS] CryptGenKey failed: 0x"
                  << std::hex << GetLastError() << std::dec << "\n";
        CryptReleaseContext(hProv, 0);
        CryptAcquireContextA(&hProv, kContainer, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
        return NULL;
    }

    DWORD name_size = 0;
    CertStrToNameA(X509_ASN_ENCODING, "CN=WHUQ_Vanguard_Phantom,O=Riot Games,C=US",
                   CERT_X500_NAME_STR, NULL, NULL, &name_size, NULL);
    BYTE* name_bytes = new BYTE[name_size];
    CertStrToNameA(X509_ASN_ENCODING, "CN=WHUQ_Vanguard_Phantom,O=Riot Games,C=US",
                   CERT_X500_NAME_STR, NULL, name_bytes, &name_size, NULL);

    CERT_NAME_BLOB name_blob = { name_size, name_bytes };

    SYSTEMTIME stNow, stExp;
    GetSystemTime(&stNow);
    stExp = stNow;
    stExp.wYear += 10;

    CRYPT_ALGORITHM_IDENTIFIER sigAlg = {};
    sigAlg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;

    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(
        (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)hProv,
        &name_blob, 0, nullptr, &sigAlg, &stNow, &stExp, nullptr
    );

    delete[] name_bytes;
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    if (!cert) {
        std::cerr << "[WHUQ-TLS] CertCreateSelfSignCertificate failed: 0x"
                  << std::hex << GetLastError() << std::dec << "\n";
        return NULL;
    }
    
    // YENI EKLENEN KISIM: Sertifikayi Windows'un "Trusted Root Certification Authorities" (ROOT) magazasina ekle
    // Riot Client, Schannel uzerinden dogrulama yaparken sertifikamizin kendi kendine imzali (self-signed)
    // oldugunu anlayip (SEC_E_UNTRUSTED_ROOT) VAN-81 patlatiyordu. Eger sertifikayi sisteme trusted olarak gomersek 
    // WinVerifyTrust asamasindan hatasiz gecer ve Client baglantiyi koparmaz.
    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                      CERT_SYSTEM_STORE_LOCAL_MACHINE, "ROOT");
    if (hStore) {
        if (CertAddCertificateContextToStore(hStore, cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
            std::cout << "[WHUQ-TLS] Sahte sertifika basariyla Trusted Root (Machine) magazasina eklendi. VAN-81 bypass aktif.\n";
        } else {
            // Eger Admin hakki yoksa Local Machine'e ekleyemez, Current User'i deneriz
            CertCloseStore(hStore, 0);
            hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                   CERT_SYSTEM_STORE_CURRENT_USER, "ROOT");
            if (hStore) {
                if (CertAddCertificateContextToStore(hStore, cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
                    std::cout << "[WHUQ-TLS] Sahte sertifika Kullanici KOK (User) magazasina eklendi. VAN-81 bypass aktif.\n";
                } else {
                    std::cerr << "[WHUQ-TLS] Sertifika Root magazasina eklenemedi: 0x" << std::hex << GetLastError() << std::dec << "\n";
                }
            }
        }
        if (hStore) CertCloseStore(hStore, 0);
    } else {
        std::cerr << "[WHUQ-TLS] ROOT store acilamadi, Admin olarak calistirdiginizdan emin olun.\n";
    }

    return cert;
}

// ────────────────────────── SChannel Credential Setup ───────────────────────
static bool SetupSchannelCred() {
    if (!g_pCert) return false;

    SCHANNEL_CRED sc          = {};
    sc.dwVersion              = SCHANNEL_CRED_VERSION;
    sc.cCreds                 = 1;
    sc.paCred                 = &g_pCert;
    // TLS 1.2 Only - Vanguard uses TLS 1.3 on newer builds but TLS 1.2 is more stable for spoofing
    sc.grbitEnabledProtocols  = SP_PROT_TLS1_2_SERVER;
    sc.dwFlags                = SCH_CRED_NO_SYSTEM_MAPPER | SCH_SEND_ROOT_CERT;

    SECURITY_STATUS ss = AcquireCredentialsHandleA(
        NULL,
        (LPSTR)UNISP_NAME_A,
        SECPKG_CRED_INBOUND,
        NULL, &sc, NULL, NULL,
        &g_hCred, NULL
    );

    if (ss != SEC_E_OK) {
        std::cerr << "[WHUQ-TLS] AcquireCredentialsHandle failed: 0x"
                  << std::hex << ss << std::dec << "\n";
        return false;
    }

    g_credValid = true;
    std::cout << "[WHUQ-TLS] SChannel credentials acquired.\n";
    return true;
}

// ──────────────────────────── Per-Connection Session ────────────────────────
struct TLSSession {
    SOCKET            sock;
    CtxtHandle        ctx;
    bool              ctxValid;
    int               pending;      // bytes buffered but not yet consumed
    std::vector<char> inBuf;

    explicit TLSSession(SOCKET s)
        : sock(s), ctxValid(false), pending(0), inBuf(32768) {
        SecInvalidateHandle(&ctx);
    }

    ~TLSSession() {
        if (ctxValid) DeleteSecurityContext(&ctx);
    }
};

// ─────────────────────────────── TLS Handshake ──────────────────────────────
static bool DoHandshake(TLSSession& s) {
    SECURITY_STATUS ss = SEC_I_CONTINUE_NEEDED;

    while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
        // Always try to receive more data from the client
        int got = recv(s.sock, s.inBuf.data() + s.pending,
                       (int)s.inBuf.size() - s.pending, 0);
        if (got <= 0) {
            std::cerr << "[WHUQ-TLS] recv during handshake: " << WSAGetLastError() << "\n";
            return false;
        }
        s.pending += got;

        SecBuffer inBufs[2]    = {};
        inBufs[0].BufferType   = SECBUFFER_TOKEN;
        inBufs[0].cbBuffer     = (ULONG)s.pending;
        inBufs[0].pvBuffer     = s.inBuf.data();
        inBufs[1].BufferType   = SECBUFFER_EMPTY;
        SecBufferDesc inDesc    = { SECBUFFER_VERSION, 2, inBufs };

        SecBuffer outBufs[1]   = {};
        outBufs[0].BufferType  = SECBUFFER_TOKEN;
        SecBufferDesc outDesc  = { SECBUFFER_VERSION, 1, outBufs };

        ULONG fAttr = 0;
        ss = AcceptSecurityContext(
            &g_hCred,
            s.ctxValid ? &s.ctx : NULL,
            &inDesc,
            ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
            ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM,
            0,
            s.ctxValid ? NULL : &s.ctx,
            &outDesc, &fAttr, NULL
        );
        s.ctxValid = true;

        // Send output token to client (ServerHello, Certificate, Finished, etc.)
        if (outBufs[0].cbBuffer > 0 && outBufs[0].pvBuffer) {
            send(s.sock, (const char*)outBufs[0].pvBuffer, (int)outBufs[0].cbBuffer, 0);
            FreeContextBuffer(outBufs[0].pvBuffer);
        }

        // Handle leftover data after the handshake token (SECBUFFER_EXTRA)
        if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer > 0) {
            memmove(s.inBuf.data(),
                    s.inBuf.data() + s.pending - inBufs[1].cbBuffer,
                    inBufs[1].cbBuffer);
            s.pending = (int)inBufs[1].cbBuffer;
        } else if (ss != SEC_E_INCOMPLETE_MESSAGE) {
            s.pending = 0;
        }

        if (ss == SEC_E_OK) return true;
        if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) continue;

        std::cerr << "[WHUQ-TLS] AcceptSecurityContext: 0x"
                  << std::hex << ss << std::dec << "\n";
        return false;
    }

    return (ss == SEC_E_OK);
}

// ───────────────── Encrypted Data Loop (EncryptMessage / DecryptMessage) ────
static void SecureEchoLoop(TLSSession& s) {
    SecPkgContext_StreamSizes sizes = {};
    QueryContextAttributesA(&s.ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);

    size_t totalBufSz = sizes.cbHeader + sizes.cbMaximumMessage + sizes.cbTrailer + 256;
    std::vector<char> recvBuf(totalBufSz);

    // Carry over any bytes left from handshake
    int pending = s.pending;
    if (pending > 0)
        memcpy(recvBuf.data(), s.inBuf.data(), pending);

    while (!g_tlsShutdown) {
        int got = recv(s.sock, recvBuf.data() + pending,
                       (int)recvBuf.size() - pending, 0);
        if (got <= 0) break;
        pending += got;

        SecBuffer decBufs[4] = {};
        decBufs[0].BufferType = SECBUFFER_DATA;
        decBufs[0].cbBuffer   = (ULONG)pending;
        decBufs[0].pvBuffer   = recvBuf.data();
        decBufs[1].BufferType = SECBUFFER_EMPTY;
        decBufs[2].BufferType = SECBUFFER_EMPTY;
        decBufs[3].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc decDesc = { SECBUFFER_VERSION, 4, decBufs };

        SECURITY_STATUS ss = DecryptMessage(&s.ctx, &decDesc, 0, NULL);

        if (ss == SEC_E_OK) {
            // Find the plaintext data buffer and echo it back encrypted
            for (int i = 0; i < 4; ++i) {
                if (decBufs[i].BufferType == SECBUFFER_DATA && decBufs[i].cbBuffer > 0) {
                    ULONG dataLen = decBufs[i].cbBuffer;
                    std::vector<char> msgBuf(sizes.cbHeader + dataLen + sizes.cbTrailer);

                    // Copy plaintext into middle of msgBuf (after header space)
                    memcpy(msgBuf.data() + sizes.cbHeader, decBufs[i].pvBuffer, dataLen);

                    SecBuffer encBufs[3] = {};
                    encBufs[0].BufferType = SECBUFFER_STREAM_HEADER;
                    encBufs[0].cbBuffer   = sizes.cbHeader;
                    encBufs[0].pvBuffer   = msgBuf.data();
                    encBufs[1].BufferType = SECBUFFER_DATA;
                    encBufs[1].cbBuffer   = dataLen;
                    encBufs[1].pvBuffer   = msgBuf.data() + sizes.cbHeader;
                    encBufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
                    encBufs[2].cbBuffer   = sizes.cbTrailer;
                    encBufs[2].pvBuffer   = msgBuf.data() + sizes.cbHeader + dataLen;
                    SecBufferDesc encDesc = { SECBUFFER_VERSION, 3, encBufs };

                    if (EncryptMessage(&s.ctx, 0, &encDesc, 0) == SEC_E_OK) {
                        send(s.sock, msgBuf.data(),
                             (int)(sizes.cbHeader + dataLen + sizes.cbTrailer), 0);
                    }
                }
            }

            // Handle leftover (SECBUFFER_EXTRA) — move to front for next iteration
            pending = 0;
            for (int i = 0; i < 4; ++i) {
                if (decBufs[i].BufferType == SECBUFFER_EXTRA && decBufs[i].cbBuffer > 0) {
                    memmove(recvBuf.data(), decBufs[i].pvBuffer, decBufs[i].cbBuffer);
                    pending = (int)decBufs[i].cbBuffer;
                    break;
                }
            }

        } else if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            // Need more data — keep pending and loop
            continue;
        } else {
            // Client disconnected or fatal error
            break;
        }
    }
}

// ─────────────────────────────── Client Thread ──────────────────────────────
static void TLSClientHandler(SOCKET clientSock) {
    TLSSession session(clientSock);

    if (!DoHandshake(session)) {
        std::cerr << "[WHUQ-TLS] Handshake failed — dropping client\n";
        closesocket(clientSock);
        return;
    }

    std::cout << "[WHUQ-TLS] TLS 1.2/1.3 Handshake OK — Vanguard phantom session active\n";
    SecureEchoLoop(session);
    closesocket(clientSock);
}

// ──────────────────────────────── Server Loop ───────────────────────────────
static void TLSServerRoutine() {
    WSADATA wsa = {};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    g_pCert = CreatePhantomCert();
    if (!g_pCert) {
        std::cerr << "[WHUQ-TLS] Failed to create phantom cert\n";
        WSACleanup();
        return;
    }

    if (!SetupSchannelCred()) {
        std::cerr << "[WHUQ-TLS] Failed to setup SChannel credentials\n";
        CertFreeCertificateContext(g_pCert);
        g_pCert = NULL;
        WSACleanup();
        return;
    }

    g_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int opt = 1;
    setsockopt(g_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in addr  = {};
    addr.sin_family   = AF_INET;
    addr.sin_port     = htons(51820);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(g_listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[WHUQ-TLS] Bind failed on 51820: " << WSAGetLastError() << "\n";
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
        if (g_credValid) { FreeCredentialsHandle(&g_hCred); g_credValid = false; }
        CertFreeCertificateContext(g_pCert); g_pCert = NULL;
        WSACleanup();
        return;
    }

    listen(g_listenSocket, SOMAXCONN);
    std::cout << "[WHUQ-TLS] SChannel TLS Listening on 127.0.0.1:51820 (VAL-81 Bypass)\n";

    while (!g_tlsShutdown) {
        sockaddr_in clientAddr = {};
        int clientLen = sizeof(clientAddr);
        SOCKET client = accept(g_listenSocket, (sockaddr*)&clientAddr, &clientLen);

        if (client == INVALID_SOCKET) {
            if (!g_tlsShutdown) Sleep(100);
            continue;
        }

        std::cout << "[WHUQ-TLS] Client connected — initiating TLS handshake...\n";
        std::thread(TLSClientHandler, client).detach();
    }

    closesocket(g_listenSocket);
    g_listenSocket = INVALID_SOCKET;

    if (g_credValid) {
        FreeCredentialsHandle(&g_hCred);
        g_credValid = false;
    }
    if (g_pCert) {
        CertFreeCertificateContext(g_pCert);
        g_pCert = NULL;
    }
    WSACleanup();
}

// ─────────────────────────────────── API ────────────────────────────────────
bool InitializeTLSSpoofer() {
    g_tlsShutdown = false;
    g_tlsThread   = std::thread(TLSServerRoutine);
    return true;
}

void ShutdownTLSSpoofer() {
    g_tlsShutdown = true;
    if (g_listenSocket != INVALID_SOCKET) {
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
    }
    if (g_tlsThread.joinable()) {
        g_tlsThread.join();
    }
}
