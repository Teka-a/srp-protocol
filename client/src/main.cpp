#include <iostream>
#include <boost/asio.hpp>
#include "core/client.h"


int main() 
{
    try {
        boost::asio::io_context io_context;
        Client client(io_context);
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}