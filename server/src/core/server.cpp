#include "core/server.h"

TcpConnection::TcpConnection(boost::asio::io_context& io_context)
    : socket_(io_context)
{

}


TcpConnection::pointer TcpConnection::create(boost::asio::io_context& io_context)
{
    return pointer(new TcpConnection(io_context));
}


tcp::socket& TcpConnection::socket()
{
    return socket_;
}


void TcpConnection::start()
{
    read();
}


void TcpConnection::read()
{
    auto self(shared_from_this());
    boost::asio::async_read_until(socket_, buffer_, "\n",
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec) {
                int sz = buffer_.size();
                //std::cout << "Size:" << sz << "\n";
                message_ = RequestHandler::handleRawIncomeRequest(buffer_);
                buffer_.consume(sz);
                write();
            } else {
                read();
            }
        });
}



void TcpConnection::write()
{
    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(message_),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
            if (!ec) {
                //std::cout << "written " << length << "\n";
                read();
            }
        });
}


TcpServer::TcpServer(boost::asio::io_context& io_context)
    : io_context_(io_context),
      acceptor_(io_context, tcp::endpoint(tcp::v4(), 56789))
{
    start_accept();
}


void TcpServer::start_accept()
{
    std::cout << "Acception started!" << "\n";
    TcpConnection::pointer newConnection = TcpConnection::create(io_context_);

    acceptor_.async_accept(newConnection->socket(),
        std::bind(&TcpServer::handle_accept, this, newConnection,
          boost::asio::placeholders::error));
}


void TcpServer::handle_accept(TcpConnection::pointer newConnection,
      const boost::system::error_code& err)
{
    if (!err) {
      newConnection->start();
    }

    start_accept();
}


