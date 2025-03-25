#include "client.h"
#include <termios.h>
#include <unistd.h>


Client::Client(boost::asio::io_context& ioContext)
    : socket_(ioContext),
      resolver_(ioContext)
{
    boost::asio::connect(socket_, resolver_.resolve(HOST, PORT));
    start();
}


std::string Client::convertStreamBufferToString(boost::asio::streambuf& buf)
{
    return {boost::asio::buffers_begin(buf.data()), 
            boost::asio::buffers_end(buf.data())};
}


void Client::start()
{
    //write();
    initAuthentication();
}

void Client::read()
{
    boost::asio::async_read_until(socket_, buffer_, "\n",
        [this](boost::system::error_code ec, std::size_t length)
        {
            if (!ec) {
                int sz = buffer_.size();
                //message_ = convertStreamBufferToString(buffer_);
                //std::cout << "Reply is: " << message_ << "\n";
                std::string answer = convertStreamBufferToString(buffer_);
                buffer_.consume(sz);
                handleAnswer(answer);
                //write();
            } else {
                read();
            }
        });
}


void Client::write(std::string& data)
{
    /*std::cout << "Enter message: ";
    std::getline(std::cin, message_);
    if (message_ == "quit") {
        socket_.close();
    }*/
    data += "\n";
    boost::asio::async_write(socket_, boost::asio::buffer(data),
        [this](boost::system::error_code ec, std::size_t length)
        {
            if (!ec) {
                read();
            }
        });
}


std::string Client::getPassword() {
    std::string password;
    struct termios oldt, newt;

    // Получаем текущие настройки терминала
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    // Отключаем отображение вводимых символов, но оставляем возможность читать ввод посимвольно
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::cout << "Введите пароль: ";
    
    char ch;
    while (true) {
        ch = getchar();
        
        // Если нажата клавиша Enter, завершаем ввод
        if (ch == '\n' || ch == '\r') {
            break;
        }
        // Обработка backspace (удаление символа)
        else if (ch == 127 || ch == 8) {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Стираем последний символ в консоли
            }
        }
        else {
            password.push_back(ch);
            std::cout << '*'; // Показываем * вместо символа
        }
        std::cout.flush();
    }

    // Восстанавливаем настройки терминала
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    std::cout << "\n"; // Перенос строки для чистоты вывода
    return password;
}


void Client::initAuthentication()
{
    std::cout << "Username: ";
    I = "";
    std::getline(std::cin, I);
    
    password = getPassword();
    std::cout << "Entered password: " << password << "\n";

    

    BN_CTX* ctx = BN_CTX_new();

    std::cout << "Init params for SRP: \n";
    BIGNUM* N = BN_new();
    BN_hex2bn(&N, SRP::N_hex.c_str());
    SRP::print_bn("N", N);

    BIGNUM* g =  BN_new();
    BN_hex2bn(&g, SRP::g_hex.c_str());
    SRP::print_bn("g", g);

    BIGNUM* a = BN_new();
    BN_rand(a, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    SRP::print_bn("a", a);

    a_hex = BN_bn2hex(a);

    BIGNUM* A = BN_new();
    BN_mod_exp(A, g, a, N, ctx);
    SRP::print_bn("A", A);

    A_hex = BN_bn2hex(A);

    std::string authRequest = "auth_init&" + I + "&" + A_hex + "&";

    write(authRequest);
}


std::vector<std::string> Client::split(std::string& str, std::string delimiter) 
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


void Client::handleAnswer(std::string answer)
{
    std::cout << "Request: " << answer << "\n";
    std::vector<std::string> items = split(answer, "&");

    std::cout << "Splitted: " << items.size() << "\n";
    std::string responce = "";
    if (items[0] == "auth_init") {
        if (items[1] == "success") {
            std::cout << "Here!\n";
            std::string M = continueAuthenticationRequestConfirmation(items[2], items[3]);
            responce += "confirm_auth&" + M + "&";
            write(responce);
        }
    } else if (items[0] == "auth_conf") {
        std::cout << "Confirm key!\n";

    } else {
        responce = "Sorry, cannot satisfy your request.";
    }

    responce += "\n";

    
}

std::string Client::continueAuthenticationRequestConfirmation(std::string s, std::string& B_hex)
{
    BN_CTX* ctx = BN_CTX_new();

    std::cout << "Init params for SRP: \n";
    BIGNUM* N = BN_new();
    BN_hex2bn(&N, SRP::N_hex.c_str());
    SRP::print_bn("N", N);
    BIGNUM* g =  BN_new();
    BN_hex2bn(&g, SRP::g_hex.c_str());
    SRP::print_bn("g", g);

    std::cout << "u of: " << (A_hex + B_hex).c_str() << std::endl;
    BIGNUM* u = SRP::hash_to_bn((A_hex + B_hex).c_str());
    SRP::print_bn("u", u);

    std::string x_to_take_hash = s + password;
    std::cout << "Take hash of: " << x_to_take_hash << std::endl;
    BIGNUM* x = SRP::hash_to_bn(x_to_take_hash);
    SRP::print_bn("x", x);

    BIGNUM* ux = BN_new();
    BN_mul(ux, u, x, ctx);
    SRP::print_bn("ux", ux);

    BIGNUM* a = BN_new();
    BN_hex2bn(&a, a_hex.c_str());

    BIGNUM* a_plus_ux = BN_new();
    BN_add(a_plus_ux, a, ux);
    SRP::print_bn("a_plus_ux", a_plus_ux);

    BIGNUM* k = SRP::hash_to_bn((SRP::N_hex + SRP::g_hex).c_str());
    SRP::print_bn("k", k);

    BIGNUM* gx = BN_new();
    BN_mod_exp(gx, g, x, N, ctx);
    SRP::print_bn("gx", gx);

    BIGNUM* kgx = BN_new();
    BN_mul(kgx, k, gx, ctx);
    SRP::print_bn("kgx", kgx);

    BIGNUM* B = BN_new();
    BN_hex2bn(&B, B_hex.c_str());

    BIGNUM* B_minux_kgx = BN_new();
    BN_sub(B_minux_kgx, B, kgx);
    SRP::print_bn("B_minus_kgx", B_minux_kgx);

    BIGNUM* S = BN_new();
    BN_mod_exp(S, B_minux_kgx, a_plus_ux, N, ctx);
    SRP::print_bn("S", S);

    std::string S_hex = BN_bn2hex(S);
    BIGNUM* key = SRP::hash_to_bn(S_hex);
    std::string key_hex = BN_bn2hex(key);

    std::cout << "Client Key: " << key_hex << std::endl;

    BIGNUM* HN = SRP::hash_to_bn((SRP::N_hex).c_str());
    BIGNUM* Hg = SRP::hash_to_bn((SRP::g_hex).c_str());

    std::string xored = BN_xor(HN, Hg);

    BIGNUM* HI = SRP::hash_to_bn((I).c_str());
    std::string hashI = BN_bn2hex(HI);

    std::string m = xored + hashI + s + A_hex + B_hex + key_hex;
    BIGNUM* HM = SRP::hash_to_bn((m).c_str());

    std::string M = BN_bn2hex(HM);

    return M;
}


std::string Client::BN_xor(const BIGNUM* a, const BIGNUM* b) 
{
    int size_a = BN_num_bytes(a);
    int size_b = BN_num_bytes(b);
    int size_max = std::max(size_a, size_b);

    std::vector<unsigned char> buf_a(size_max, 0);
    std::vector<unsigned char> buf_b(size_max, 0);
    std::vector<unsigned char> buf_res(size_max, 0);

    // Преобразуем BIGNUM в массив байтов (Big-endian)
    BN_bn2binpad(a, buf_a.data(), size_max);
    BN_bn2binpad(b, buf_b.data(), size_max);

    // XOR посимвольно
    for (int i = 0; i < size_max; i++) {
        buf_res[i] = buf_a[i] ^ buf_b[i];
    }

    // Конвертируем результат обратно в BIGNUM
    BIGNUM* res = BN_bin2bn(buf_res.data(), size_max, NULL);

    // Преобразуем BIGNUM в строку hex
    char* res_str = BN_bn2hex(res);
    std::string result(res_str);

    // Очистка памяти
    BN_free(res);
    OPENSSL_free(res_str);

    return result;
}