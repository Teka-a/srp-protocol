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


void print_bn(std::string name, BIGNUM* bn)
{
    char* bn_hex_str = BN_bn2hex(bn);
    if (bn_hex_str) {
        std::cout << name << ": " << bn_hex_str << std::endl;
    } else {
        std::cerr << "Ошибка преобразования BIGNUM в hex" << std::endl;
    }

    OPENSSL_free(bn_hex_str);
}

void init_srp_params() {
    N = BN_new();
    g = BN_new();
    if (!N || !g || !BN_hex2bn(&N, N_hex.c_str()) || !BN_hex2bn(&g, g_hex.c_str())) {
        std::cerr << "Ошибка инициализации N и g" << std::endl;
        exit(1);
    }

    print_bn("N", N);
    print_bn("g", g);
    std::cout << "\n";
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

// Функция вычисления x = H(salt || password))
BIGNUM* calculate_x(const std::string& username, const std::string& password, const std::string& salt, size_t salt_len) {
    std::string x_to_take_hash = salt + password;
    std::cout << "Take hash of: " << x_to_take_hash << std::endl;
    BIGNUM* x = hash_to_bn(x_to_take_hash);
    

    print_bn("x", x);

    return x;
}



// Функция вычисления верификатора v = g^x % N
BIGNUM* calculate_v(BIGNUM* x, BN_CTX* ctx) {
    BN_CTX *ctx_v = BN_CTX_new(); 
    BIGNUM* v = BN_new();

    BN_mod_exp(v, g, x, N, ctx_v);

    print_bn("v", v);

    std::cout << "\n";
    
    return v;
}

// Структура пользователя
struct User {
    std::string username;
    std::string password;
    std::string salt;
    BIGNUM* v;

    User(const std::string& user, const std::string& pass) : username(user), password(pass), v(nullptr) {
        salt = "0123456789abcdef";

        BN_CTX* ctx = BN_CTX_new();
        
        BIGNUM* x = calculate_x(username, password, salt, salt.length());


        v = calculate_v(x, ctx);
        //BN_free(x);
        BN_CTX_free(ctx);
    }

    ~User() { //BN_free(v); 
        }
};

// Клиент SRP
class SRPClient {
public:
    std::string username;
    BIGNUM* a;
    BIGNUM* A;
    BIGNUM* S;
    char K[SHA256_SIZE];


    SRPClient(const std::string& user) : username(user), a(BN_new()), A(BN_new()), S(nullptr) {
        BN_rand(a, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);

        print_bn("a", a);

        //BN_hex2bn(&a, "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
        BN_CTX* ctx = BN_CTX_new();
        BN_mod_exp(A, g, a, N, ctx);
        print_bn("A", A);

        std::cout << "\n";

        //BN_CTX_free(ctx);
        
    }

    BIGNUM* get_A() { return A; }

    void compute_S(BIGNUM* B, BIGNUM* x) {        

        BN_CTX* ctx = BN_CTX_new();

        std::string A_hex = BN_bn2hex(A);
        std::string B_hex = BN_bn2hex(B);
        std::cout << "u of: " << (A_hex + B_hex).c_str() << std::endl;
        BIGNUM* u = hash_to_bn((A_hex + B_hex).c_str());
        print_bn("u", u);

        BIGNUM* ux = BN_new();
        BN_mul(ux, u, x, ctx);
        print_bn("ux", ux);


        BIGNUM* a_plus_ux = BN_new();
        BN_add(a_plus_ux, a, ux);
        print_bn("a_plus_ux", a_plus_ux);

        std::string N_hex = BN_bn2hex(N);
        std::string g_hex = BN_bn2hex(g);
        std::cout << "Hash of: " << (N_hex + g_hex).c_str() << std::endl;
        BIGNUM* k = hash_to_bn((N_hex + g_hex).c_str());
        print_bn("k", k);

        BIGNUM* gx = BN_new();
        BN_mod_exp(gx, g, x, N, ctx);
        print_bn("gx", gx);

        BIGNUM* kgx = BN_new();
        BN_mul(kgx, k, gx, ctx);
        print_bn("kgx", kgx);

        BIGNUM* B_minux_kgx = BN_new();
        BN_sub(B_minux_kgx, B, kgx);
        print_bn("B_minus_kgx", B_minux_kgx);

        S = BN_new();
        BN_mod_exp(S, B_minux_kgx, a_plus_ux, N, ctx);
        print_bn("S", S);

        std::string S_hex = BN_bn2hex(S);
        BIGNUM* key = hash_to_bn(S_hex);
        std::string key_hex = BN_bn2hex(key);

        std::cout << "Key: " << key_hex << std::endl;

        strcpy(static_cast <char*>(K), key_hex.c_str());

        std::cout << "\n";

    }

    ~SRPClient() {
       // BN_free(a);
        //BN_free(A);
        //BN_free(S);
    }
};

// Сервер SRP
class SRPServer {
public:
User* user;
BIGNUM* b;
BIGNUM* B;
BIGNUM* S;
std::string I = "alice";
char K[SHA256_SIZE];
    SRPServer(User* u) : user(u), b(BN_new()), B(BN_new()), S(nullptr) {
        BN_CTX* ctx = BN_CTX_new();
        
        std::string N_hex = BN_bn2hex(N);
        std::string g_hex = BN_bn2hex(g);
        std::cout << "Hash of: " << (N_hex + g_hex).c_str() << std::endl;
        BIGNUM* k = hash_to_bn((N_hex + g_hex).c_str());
        print_bn("k", k);
        print_bn("v", user->v);

        BIGNUM* kv = BN_new();
        BN_mul(kv, k, user->v, ctx);
        print_bn("kv", kv);

        BN_rand(b, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        print_bn("b", b);
        BIGNUM* gb = BN_new();
        BN_mod_exp(gb, g, b, N, ctx);
        print_bn("gb", gb);
        
        BN_add(B, kv, gb);

        print_bn("B", B);

        std::cout << "\n";

    }

    BIGNUM* get_B() { return B; }

    void compute_S(BIGNUM* A, BIGNUM* B, BIGNUM* v, BIGNUM* b) {
        print_bn("b", b);
        std::cout << "Here\n";

        BN_CTX* ctx = BN_CTX_new();

        std::cout << "Here2\n";        

        print_bn("A in", A);
        print_bn("B in", B);

        std::string A_hex = BN_bn2hex(A);
        std::cout << "A hex " << A_hex << std::endl;
        std::string B_hex = BN_bn2hex(B);
        std::cout << "B hex: " << B_hex << std::endl;
        std::cout << "u of: " << (A_hex + B_hex).c_str() << std::endl;
        BIGNUM* u = hash_to_bn((A_hex + B_hex).c_str());
        print_bn("u", u);

        S = BN_new();
        BIGNUM* vu = BN_new();
        BN_mod_exp(vu, v, u, N, ctx);
        print_bn("vu", vu);

        BIGNUM* Avu = BN_new();
        BN_mul(Avu, A, vu, ctx);
        print_bn("Avu", Avu);

        print_bn("b", b);

        BN_mod_exp(S, Avu, b, N, ctx);
        print_bn("S", S);

        std::string S_hex = BN_bn2hex(S);
        BIGNUM* key = hash_to_bn(S_hex);
        std::string key_hex = BN_bn2hex(key);

        std::cout << "Key: " << key_hex << std::endl;

        strcpy(static_cast <char*>(K), key_hex.c_str());

        std::cout << "\n";

        //BN_free(vu);
        //BN_free(u);
        //BN_free(key);
        //BN_CTX_free(ctx);
    }

    ~SRPServer() {
        //free
    }
};


int main() {
    // 1️⃣ Инициализируем параметры SRP
    init_srp_params();

    // 2️⃣ Создаем пользователя с логином и паролем
    std::string username = "alice";
    std::string password = "securepassword";
    User user(username, password);



    // 3️⃣ Сервер создает `B`
    SRPServer server(&user);
    BIGNUM* b = server.b;
    print_bn("b", b);
    
    

    // 4️⃣ Клиент создает `A`
    SRPClient client(username);
    

    // 5️⃣ Сервер передает `B`, клиент передает `A`
    BIGNUM* A = client.get_A();
    BIGNUM* B = server.get_B();

    print_bn("B before", B);

    

    // 6️⃣ Вычисляем `x` (только на клиенте)
    BIGNUM* x = calculate_x(username, password, user.salt, SALT_SIZE);
    print_bn("x", x);

    // 7️⃣ Клиент вычисляет `S`
    client.compute_S(B, x);

    // 8️⃣ Сервер вычисляет `S`
    server.compute_S(A, B, user.v, b);

    // 9️⃣ Проверяем совпадение хешей ключа K
    char client_K[SHA256_SIZE], server_K[SHA256_SIZE];
    memcpy(client_K, client.K, SHA256_SIZE);
    memcpy(server_K, server.K, SHA256_SIZE);

    if (memcmp(client_K, server_K, SHA256_SIZE) == 0) {
        std::cout << "Аутентификация успешна: ключи совпадают!" << std::endl;
    } else {
        std::cerr << "Ошибка: ключи не совпадают!" << std::endl;
    }

    //  🔄 Освобождаем память
    //BN_free(x);

    return 0;
}
