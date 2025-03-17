#include <iostream>
#include <cstring>
#include <string>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

const size_t SHA256_SIZE = 32;
const size_t SALT_SIZE = 16;

// SRP параметры (N и g)
const std::string N_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3";
const std::string g_hex = "02";

BIGNUM* N;
BIGNUM* g;

// Инициализация SRP параметров
void init_srp_params() {
    N = BN_new();
    g = BN_new();
    if (!N || !g || !BN_hex2bn(&N, N_hex.c_str()) || !BN_hex2bn(&g, g_hex.c_str())) {
        std::cerr << "Ошибка инициализации N и g" << std::endl;
        exit(1);
    }
}

// Функция хеширования SHA-256
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

// Функция вычисления BIGNUM-хеша
BIGNUM* hash_to_bn(const std::string& input) {
    unsigned char hash[SHA256_SIZE];
    sha256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    return BN_bin2bn(hash, SHA256_SIZE, nullptr);
}

// Функция вычисления x = H(salt | H(username | ":" | password))
BIGNUM* calculate_x(const std::string& username, const std::string& password, const unsigned char* salt, size_t salt_len) {
    std::string inner = username + ":" + password;
    BIGNUM* inner_hash_bn = hash_to_bn(inner);

    std::string x_data(reinterpret_cast<const char*>(salt), salt_len);
    x_data.append(BN_bn2hex(inner_hash_bn));

    BN_free(inner_hash_bn);
    return hash_to_bn(x_data);
}

// Функция вычисления верификатора v = g^x % N
BIGNUM* calculate_v(BIGNUM* x, BN_CTX* ctx) {
    BIGNUM* v = BN_new();
    if (!v || BN_mod_exp(v, g, x, N, ctx) == 0) {
        std::cerr << "Ошибка вычисления v" << std::endl;
        BN_free(v);
        return nullptr;
    }
    return v;
}

// Структура пользователя
struct User {
    std::string username;
    std::string password;
    unsigned char salt[SALT_SIZE];
    BIGNUM* v;

    User(const std::string& user, const std::string& pass) : username(user), password(pass), v(nullptr) {
        RAND_bytes(salt, SALT_SIZE);
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* x = calculate_x(username, password, salt, SALT_SIZE);
        v = calculate_v(x, ctx);
        BN_free(x);
        BN_CTX_free(ctx);
    }

    ~User() { BN_free(v); }
};

// Клиент SRP
class SRPClient {
public:
    std::string username;
    BIGNUM* a;
    BIGNUM* A;
    BIGNUM* S;
    unsigned char K[SHA256_SIZE];


    SRPClient(const std::string& user) : username(user), a(BN_new()), A(BN_new()), S(nullptr) {
        BN_rand(a, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        BN_CTX* ctx = BN_CTX_new();
        BN_mod_exp(A, g, a, N, ctx);
        BN_CTX_free(ctx);
    }

    BIGNUM* get_A() { return A; }

    void compute_S(BIGNUM* B, BIGNUM* x, BN_CTX* ctx) {
        //BIGNUM* u = hash_to_bn(BN_bn2hex(A) + BN_bn2hex(B));
        std::string A_hex = BN_bn2hex(A);
        std::string B_hex = BN_bn2hex(B);
        BIGNUM* u = hash_to_bn((A_hex + B_hex).c_str());

        BIGNUM* ux = BN_new();
        BIGNUM* a_plus_ux = BN_new();
        S = BN_new();

        BN_mul(ux, u, x, ctx);
        BN_add(a_plus_ux, a, ux);
        BN_mod_exp(S, B, a_plus_ux, N, ctx);

        int s_len = BN_num_bytes(S);
        std::string s_data(s_len, 0);
        BN_bn2bin(S, reinterpret_cast<unsigned char*>(&s_data[0]));
        sha256(reinterpret_cast<const unsigned char*>(s_data.data()), s_data.size(), K);

        BN_free(u);
        BN_free(ux);
        BN_free(a_plus_ux);
    }

    ~SRPClient() {
        BN_free(a);
        BN_free(A);
        BN_free(S);
    }
};

// Сервер SRP
class SRPServer {
public:
User* user;
BIGNUM* b;
BIGNUM* B;
BIGNUM* S;
unsigned char K[SHA256_SIZE];
    SRPServer(User* u) : user(u), b(BN_new()), B(BN_new()), S(nullptr) {
        BN_CTX* ctx = BN_CTX_new();
        //BIGNUM* k = hash_to_bn(BN_bn2hex(N) + BN_bn2hex(g));
        std::string N_hex = BN_bn2hex(N);
        std::string g_hex = BN_bn2hex(g);
        BIGNUM* k = hash_to_bn((N_hex + g_hex).c_str());

        BN_rand(b, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        BIGNUM* gb = BN_new();
        BN_mod_exp(gb, g, b, N, ctx);
        BN_mod_exp(B, k, user->v, N, ctx);
        BN_add(B, B, gb);
        BN_mod(B, B, N, ctx);

        BN_free(k);
        BN_free(gb);
        BN_CTX_free(ctx);
    }

    BIGNUM* get_B() { return B; }

    void compute_S(BIGNUM* A, BN_CTX* ctx) {
        std::string A_hex = BN_bn2hex(A);
        std::string B_hex = BN_bn2hex(B);
        BIGNUM* u = hash_to_bn((A_hex + B_hex).c_str());
        //BIGNUM* u = hash_to_bn(BN_bn2hex(A) + BN_bn2hex(B));
        S = BN_new();
        BIGNUM* vu = BN_new();
        BN_mod_exp(vu, user->v, u, N, ctx);
        BN_mod_exp(S, A, b, N, ctx);

        int s_len = BN_num_bytes(S);
        std::string s_data(s_len, 0);
        BN_bn2bin(S, reinterpret_cast<unsigned char*>(&s_data[0]));
        sha256(reinterpret_cast<const unsigned char*>(s_data.data()), s_data.size(), K);

        BN_free(vu);
        BN_free(u);
    }

    ~SRPServer() {
        BN_free(b);
        BN_free(B);
        BN_free(S);
    }
};


int main() {
    // 1️⃣ Инициализируем параметры SRP
    init_srp_params();

    // 2️⃣ Создаем пользователя с логином и паролем
    std::string username = "Alice";
    std::string password = "securepassword";
    User user(username, password);

    // 3️⃣ Сервер создает `B`
    SRPServer server(&user);

    // 4️⃣ Клиент создает `A`
    SRPClient client(username);

    // 5️⃣ Сервер передает `B`, клиент передает `A`
    BIGNUM* A = client.get_A();
    BIGNUM* B = server.get_B();
    

    // 6️⃣ Вычисляем `x` (только на клиенте)
    BIGNUM* x = calculate_x(username, password, user.salt, SALT_SIZE);

    // 7️⃣ Клиент вычисляет `S`
    BN_CTX* ctx = BN_CTX_new();
    client.compute_S(B, x, ctx);

    // 8️⃣ Сервер вычисляет `S`
    server.compute_S(A, ctx);

    // 9️⃣ Проверяем совпадение хешей ключа K
    unsigned char client_K[SHA256_SIZE], server_K[SHA256_SIZE];
    memcpy(client_K, client.K, SHA256_SIZE);
    memcpy(server_K, server.K, SHA256_SIZE);

    if (memcmp(client_K, server_K, SHA256_SIZE) == 0) {
        std::cout << "✅ Аутентификация успешна: ключи совпадают!" << std::endl;
    } else {
        std::cerr << "❌ Ошибка: ключи не совпадают!" << std::endl;
    }

    //  🔄 Освобождаем память
    BN_free(x);
    BN_CTX_free(ctx);

    return 0;
}

