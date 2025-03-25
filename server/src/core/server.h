#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include "handlers/request_handler.h"


using boost::asio::ip::tcp;



class TcpConnection
    : public std::enable_shared_from_this<TcpConnection>
{
public:
    typedef std::shared_ptr<TcpConnection> pointer;
    static pointer create(boost::asio::io_context&);
    tcp::socket& socket();
    void start();
private:
    TcpConnection(boost::asio::io_context&);
    void read();
    void write();

    tcp::socket socket_;
    std::string message_;
    boost::asio::streambuf buffer_;
    unsigned char key [16];
    unsigned char init_vect [16];
};

class TcpServer
{
public:
    TcpServer(boost::asio::io_context& io_context);
private:
    void start_accept();
    void handle_accept(TcpConnection::pointer newConnection, const boost::system::error_code& err);
    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
};