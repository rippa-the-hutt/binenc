
#include "Mac.h"
#include "Base.h"
#include "error.h"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <cstdint>
#include <string>
#include <map>

const std::map<RippaSSL::Algo, std::string> cmacAlgoMap {
    {RippaSSL::Algo::algo_AES128CBC, "aes-128-cbc"},
    {RippaSSL::Algo::algo_AES256CBC, "aes-256-cbc"}
};

RippaSSL::Cmac::Cmac(Algo                        algo,
                     MacMode                     mode,
                     const std::vector<uint8_t>& key,
                     const uint8_t*              iv,
                     bool                        padding)
: SymCryptoBase(algo, padding)
{
    std::string fetchedMac;
    // throws std::out_of_range if algo doesn't map to a valid key!
    const std::string macAlgo {cmacAlgoMap.at(algo)};

    // fetches the required mode of operation (TODO: only CMAC supported now):
    switch (mode)
    {
        case RippaSSL::MacMode::CMAC:
            fetchedMac =  "cmac";

            break;
    }

    handle = EVP_MAC_fetch(NULL, fetchedMac.c_str(), NULL);

    // prepares the parameters to be passed to the OpenSSL init function:
    OSSL_PARAM params[] = {
                            // array element 0:
                            OSSL_PARAM_construct_utf8_string(
                                "cipher",
                                const_cast<char*>(macAlgo.c_str()),
                                0),
                            // array element 1 (ending one):
                            OSSL_PARAM_construct_end()
                          };

    if ((NULL == handle)                                           ||
        (NULL == (context = EVP_MAC_CTX_new(
                                const_cast<CmacHandle*>(handle)))) ||
        !EVP_MAC_init(context,
                      (const unsigned char *) key.data(), key.size(),
                      params)
       )
    {
        throw InputError_NULLPTR {};
    }

    if (nullptr != iv)
    {
        EVP_MAC_update(context, iv, blockSizes.at(algo));
    }
}

int RippaSSL::Cmac::update(      std::vector<uint8_t>& output,
                           const std::vector<uint8_t>& input)
{
    if (!EVP_MAC_update(context, input.data(), input.size()))
        throw OpenSSLError_CryptoUpdate {};

    alreadyUpdatedData += input.size();

    return 0;
}

RippaSSL::Cmac::~Cmac()
{
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(const_cast<CmacHandle*>(handle));
}
