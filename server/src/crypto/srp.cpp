#include "srp.h"
#include <iostream>

namespace SRP {

    void print_bn(std::string name, BIGNUM* bn)
    {
        char* bn_hex_str = BN_bn2hex(bn);
        if (bn_hex_str) {
            std::cout << name << " : " << bn_hex_str << std::endl;
        } else {
            std::cerr << "Ошибка преобразования BIGNUM в hex" << std::endl;
        }

        OPENSSL_free(bn_hex_str);
    }

    void sha256(const unsigned char* data, size_t length, unsigned char* out) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, data, length) != 1 ||
            EVP_DigestFinal_ex(ctx, out, nullptr) != 1) {
            std::cerr << "Ошибка SHA-256: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            exit(1);
        }
        EVP_MD_CTX_free(ctx);
    }

    BIGNUM* hash_to_bn(const std::string& input) {
        unsigned char hash[SHA256_SIZE];
        sha256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
        return BN_bin2bn(hash, SHA256_SIZE, nullptr);
    }
}
