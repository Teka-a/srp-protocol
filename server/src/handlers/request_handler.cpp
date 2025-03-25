#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include "handlers/request_handler.h"

namespace RequestHandler
{
    std::string convertStreamBufferToString(boost::asio::streambuf& buf)
    {
        return {boost::asio::buffers_begin(buf.data()), 
                boost::asio::buffers_end(buf.data())};
    }

    std::vector<std::string> split(std::string& str, std::string delimiter) 
    {
        std::vector<std::string> items;
        size_t pos = 0;
        std::string item;
        while ((pos = str.find(delimiter)) != std::string::npos) {
            item = str.substr(0, pos);
            items.push_back(item);
            str.erase(0, pos + delimiter.length());
        }
        items.push_back(str);

        return items;
    }

    std::string handleRawIncomeRequest(boost::asio::streambuf& requestBuffer)
    {
        std::string request = convertStreamBufferToString(requestBuffer);
        request.pop_back();
        std::cout << "Request: " << request << "\n";
        std::vector<std::string> items = split(request, "&");

        std::cout << "Splitted: " << items.size() << "\n";
        std::string responce = "";
        if (items[0] == "add") {
            int num = std::stoi(items[1]);
            num += 2;
            std::string res = std::to_string(num);
            responce += "added&" + res;
        } else if (items[0] == "auth_init") {
            std::cout << "Auth init!\n";
            std::string authStatus = acceptAuthentication(items[1], items[2]);
            responce += "auth_init&" + authStatus;
        } else if (items[0] == "auth_conf") {
            std::cout << "Auth confirmation request!\n";
            std::string confStatus = confirmAuthentication(items[1]);
            responce += "auth_conf&" + confStatus;
        } else {
            responce = "Sorry, cannot satisfy your request.";
        }

        responce += "\n";
        return responce;
    }

    std::string acceptAuthentication(std::string username, std::string A_hex)
    {
        if (username != SRP::I) {
            std::cout << "No such user!\n";
            return "failed";
        }

        BN_CTX* ctx = BN_CTX_new();

        std::cout << "Init params for SRP: \n";
        BIGNUM* N = BN_new();
        BN_hex2bn(&N, SRP::N_hex.c_str());
        SRP::print_bn("N", N);

        BIGNUM* g =  BN_new();
        BN_hex2bn(&g, SRP::g_hex.c_str());
        SRP::print_bn("g", g);

        std::cout << "Computations for B: \n";
        BIGNUM* B = BN_new();

        BIGNUM* k = SRP::hash_to_bn((SRP::N_hex + SRP::g_hex).c_str());
        SRP::print_bn("k", k);
        
        BIGNUM* v =  BN_new();
        BN_hex2bn(&v, SRP::v_hex.c_str());
        
        SRP::print_bn("v", v);

        BIGNUM* kv = BN_new();
        BN_mul(kv, k, v, ctx);
        SRP::print_bn("kv", kv);

        BIGNUM* b = BN_new();
        BN_rand(b, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        SRP::print_bn("b", b);

        BIGNUM* gb = BN_new();
        BN_mod_exp(gb, g, b, N, ctx);
        SRP::print_bn("gb", gb);

        BN_add(B, kv, gb);

        SRP::print_bn("B", B);

        std::cout << "\n";

        std::cout << "A hex " << A_hex << std::endl;
        std::string B_hex = BN_bn2hex(B);
        std::cout << "B hex: " << B_hex << std::endl;
        std::cout << "Hash for u of: " << (A_hex + B_hex).c_str() << std::endl;
        BIGNUM* u = SRP::hash_to_bn((A_hex + B_hex).c_str());
        SRP::print_bn("u", u);

        BIGNUM* S = BN_new();
        BIGNUM* vu = BN_new();
        BN_mod_exp(vu, v, u, N, ctx);
        SRP::print_bn("vu", vu);

        BIGNUM* A = BN_new();
        BN_hex2bn(&A, A_hex.c_str());

        BIGNUM* Avu = BN_new();
        BN_mul(Avu, A, vu, ctx);
        SRP::print_bn("Avu", Avu);

        BN_mod_exp(S, Avu, b, N, ctx);
        SRP::print_bn("S", S);

        std::string S_hex = BN_bn2hex(S);
        BIGNUM* key = SRP::hash_to_bn(S_hex);
        std::string key_hex = BN_bn2hex(key);

        std::cout << "Server Key: " << key_hex << std::endl;

        std::string openKey = BN_bn2hex(B);
        std::string responce = "success&" + SRP::s + "&" + openKey + "&";

        return responce;
    }

    std::string confirmAuthentication(std::string M_hex)
    {
        std::cout << "Here to confirm!";


    }

    std::string BN_xor(const BIGNUM* a, const BIGNUM* b) 
    {
        int size_a = BN_num_bytes(a);
        int size_b = BN_num_bytes(b);
        int size_max = std::max(size_a, size_b);

        std::vector<unsigned char> buf_a(size_max, 0);
        std::vector<unsigned char> buf_b(size_max, 0);
        std::vector<unsigned char> buf_res(size_max, 0);

        
        BN_bn2binpad(a, buf_a.data(), size_max);
        BN_bn2binpad(b, buf_b.data(), size_max);

        for (int i = 0; i < size_max; i++) {
            buf_res[i] = buf_a[i] ^ buf_b[i];
        }

        BIGNUM* res = BN_bin2bn(buf_res.data(), size_max, NULL);

        char* res_str = BN_bn2hex(res);
        std::string result(res_str);

        BN_free(res);
        OPENSSL_free(res_str);

        return result;
    }
}