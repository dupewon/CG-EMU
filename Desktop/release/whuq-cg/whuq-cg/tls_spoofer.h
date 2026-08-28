// ==============================================================================
// GITHUB: DUPEWON
// CHEATGLOBAL: WHUQ
// ===========
// Core logic handling for tls_spoofer.h
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

extern bool g_tlsShutdown;

// Initializes the TLS Spoofer background thread
bool InitializeTLSSpoofer();
void ShutdownTLSSpoofer();

