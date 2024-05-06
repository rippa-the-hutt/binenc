
#include "Base.h"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <cstdint>

const std::map<RippaSSL::Algo, size_t> RippaSSL::blockSizes
{
    {RippaSSL::Algo::AES128CBC, 16},
    {RippaSSL::Algo::AES128ECB, 16},
    {RippaSSL::Algo::AES256CBC, 16},
    {RippaSSL::Algo::AES256ECB, 16}
};
