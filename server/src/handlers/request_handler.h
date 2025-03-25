#include "crypto/srp.h"

namespace RequestHandler
{
    std::string handleRawIncomeRequest(boost::asio::streambuf&);

    std::string convertStreamBufferToString(boost::asio::streambuf&);

    std::vector<std::string> split(std::string&, std::string);

    std::string BN_xor(const BIGNUM* a, const BIGNUM* b);

    std::string acceptAuthentication(std::string username, std::string A);
    std::string confirmAuthentication(std::string M_hex);

}