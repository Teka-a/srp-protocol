#include <iostream>
#include <boost/asio.hpp>
#include "crypto/srp.h"


using boost::asio::ip::tcp;
typedef unsigned char byte;


class Client
{
public:    
    
    Client(boost::asio::io_context&);
private:
    std::string convertStreamBufferToString(boost::asio::streambuf&);
    void start();
    
    void read();

    void write(std::string&);

    void handleAnswer(std::string answer);
    void initAuthentication();
    std::string continueAuthenticationRequestConfirmation(std::string s, std::string& B); 
    std::string getPassword(); 
    std::string BN_xor(const BIGNUM* a, const BIGNUM* b);
    std::vector<std::string> split(std::string& str, std::string delimiter);

    tcp::resolver resolver_;
    tcp::socket socket_;
    std::string message_;
    boost::asio::streambuf buffer_;

    std::string I = "";
    std::string password = "";
    std::string a_hex = "";
    std::string A_hex = "";

    byte key [16];
    byte initVect [16];
    const std::string HOST = "127.0.0.1";
    const std::string PORT = "56789";


};