#ifndef SRP_H
#define SRP_H

#include <cstring>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

namespace SRP {
    const size_t SHA256_SIZE = 32;
    const size_t SALT_SIZE = 16;

    const std::string N_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3";
    const std::string g_hex = "02";
    
    const std::string v_hex = "A621519256C1F4C2DC2B6DC53623F7E9995B9ACCE6111506BFB2E466DC45667FEF1B688159F45AC71A8C346F2D9D39D9BB326C59284A8BE441DE336B0D9E58F0A19BC1C1BB0BF42AD1C6BE36E0A4D237FB3425B194D58FC6F27BDDEA09E631AC358CDB09D5C1740A46E72A7149BA12D3DD8DCFC7EECED032AB27814F708EA982";
    const std::string I = "alice";
    const std::string s = "0123456789abcdef";



    void print_bn(std::string name, BIGNUM* bn);


    void sha256(const unsigned char* data, size_t length, unsigned char* out);
    BIGNUM* hash_to_bn(const std::string& input);

}


#endif SRP_H 