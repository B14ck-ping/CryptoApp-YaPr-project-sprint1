#include "crypto_guard_ctx.h"
#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#define IN_BUFFER_SIZE 4096
#define OUT_BUFFER_SIZE 4096

#define PrintSSLErrorString(msg) std::string(msg) + std::string(" Error: ") + ERR_error_string(ERR_get_error(), nullptr)

namespace CryptoGuard {
using CipherCtxDeleter = void (*)(EVP_CIPHER_CTX *);
using CipherCtxUniquePtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;
struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

// Define the nested Impl class
class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::istream &input, std::ostream &output, std::string_view password) {
        auto params = CreateCipherParamsFromPassword(password);
        params.encrypt = 1;
        CipherCtxUniquePtr ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

        // Инициализируем cipher
        auto result =
            EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        if (result == 0) {
            throw std::runtime_error{PrintSSLErrorString("Failed to initialize cipher.")};
        }

        std::vector<unsigned char> outBuf(OUT_BUFFER_SIZE);
        std::vector<unsigned char> inBuf(IN_BUFFER_SIZE);
        int outLen;
        while (input) {
            // Обрабатываем N символов
            input.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            std::streamsize bytesRead = input.gcount();
            result = EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead));
            if (result == 0) {
                throw std::runtime_error{PrintSSLErrorString("Cipher update error.")};
            }
            if (outLen > 0) {
                output.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
            } else if (!output) {
                throw std::runtime_error{"Output stream error."};
            }
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
        if (result == 0) {
            throw std::runtime_error{PrintSSLErrorString("Cipher final error.")};
        }
        if (outLen > 0) {
            output.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        } else if (!output) {
            throw std::runtime_error{"Output stream error."};
        }
    }

    void DecryptFile(std::istream &input, std::ostream &output, std::string_view password) {
        auto params = CreateCipherParamsFromPassword(password);
        params.encrypt = 0;
        CipherCtxUniquePtr ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

        // Инициализируем cipher
        auto result =
            EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        if (result == 0) {
            throw std::runtime_error{std::string("Failed to initialize cipher: ")};
        }

        std::vector<unsigned char> outBuf(OUT_BUFFER_SIZE);
        std::vector<unsigned char> inBuf(IN_BUFFER_SIZE);
        int outLen;
        while (input) {
            // Обрабатываем N символов
            input.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            std::streamsize bytesRead = input.gcount();
            result = EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead));
            if (result == 0) {
                throw std::runtime_error{PrintSSLErrorString("Cipher update error.")};
            }
            if (outLen > 0 && output) {
                output.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
            } else if (!output) {
                throw std::runtime_error{"Output stream error."};
            }
        }

        // Заканчиваем работу с cipher
        result = EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
        if (result == 0) {
            throw std::runtime_error{PrintSSLErrorString("Cipher final error.")};
        }
        if (outLen > 0 && output) {
            output.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        } else if (!output) {
            throw std::runtime_error{"Output stream error."};
        }
    }

    std::string CalculateChecksum(std::istream &input) {
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;

        using EVP_MD_Deleter = void (*)(EVP_MD_CTX *);
        using EVP_MD_CTX_UniquePtr = std::unique_ptr<EVP_MD_CTX, EVP_MD_Deleter>;
        EVP_MD_CTX_UniquePtr mdctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};

        if (mdctx.get() == NULL) {
            throw std::runtime_error{PrintSSLErrorString("Message digest create failed. Error: ")};
        }

        if (!EVP_DigestInit_ex2(mdctx.get(), EVP_sha256(), NULL)) {
            throw std::runtime_error{PrintSSLErrorString("Message digest initialization failed. Error: ")};
        }

        std::vector<unsigned char> buffer(IN_BUFFER_SIZE);
        while (input) {
            input.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
            std::streamsize bytesRead = input.gcount();
            if (bytesRead > 0) {
                if (!EVP_DigestUpdate(mdctx.get(), buffer.data(), static_cast<size_t>(bytesRead))) {
                    throw std::runtime_error{PrintSSLErrorString("Message digest update failed. Error: ")};
                }
            }
        }

        if (!EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len)) {
            throw std::runtime_error{PrintSSLErrorString("Message digest finalization failed. Error: ")};
        }
        std::ostringstream oss;
        for (unsigned int i = 0; i < md_len; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
        }
        std::string checksum = oss.str();

        return checksum;
    }

    AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{PrintSSLErrorString("Failed to create a key from password")};
        }

        return params;
    }
};

// Now the destructor can see the full definition of Impl
CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &input, std::ostream &output, std::string_view password) {
    pImpl_->EncryptFile(input, output, password);
}

void CryptoGuardCtx::DecryptFile(std::istream &input, std::ostream &output, std::string_view password) {
    pImpl_->DecryptFile(input, output, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &input) { return pImpl_->CalculateChecksum(input); }

}  // namespace CryptoGuard
