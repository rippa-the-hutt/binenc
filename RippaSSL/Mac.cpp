
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

    this->handle = EVP_MAC_fetch(NULL, fetchedMac.c_str(), NULL);

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

    if ((NULL == this->handle)                                               ||
        (NULL == (this->context =
                    EVP_MAC_CTX_new(const_cast<CmacHandle*>(this->handle)))) ||
        !EVP_MAC_init(this->context,
                      (const unsigned char *) key.data(), key.size(),
                      params)
       )
    {
        throw InputError_NULLPTR {};
    }

    if (nullptr != iv)
    {
        EVP_MAC_update(this->context, iv, blockSizes.at(algo));
    }
}

int RippaSSL::Cmac::update(      std::vector<uint8_t>& output,
                           const std::vector<uint8_t>& input)
{
    // prepares output buffer. This is sufficient as the update function does
    // not apply padding:
    if ( output.size() < input.size())
    {
        output.resize(input.size());
    }

    if (!EVP_MAC_update(this->context, input.data(), input.size()))
        throw OpenSSLError_CryptoUpdate {};

    this->alreadyUpdatedData += input.size();

    return 0;
}

int RippaSSL::Cmac::finalize(      std::vector<uint8_t>& output,
                             const std::vector<uint8_t>& input)
{
    size_t finalizeLen = 0;

    if (input.size())
    {
        try {
            this->update(output, input);
        } catch (OpenSSLError_CryptoUpdate& cu) {
            throw OpenSSLError_CryptoFinalize {};
        }
    }

    if (!EVP_MAC_final(this->context,
                       output.data(), &finalizeLen, input.size()))
    {
        throw OpenSSLError_CryptoFinalize {};
    }

    return 0;
}

RippaSSL::Cmac::~Cmac()
{
    if (nullptr != this->context)
        EVP_MAC_CTX_free(this->context);
    if (nullptr != this->handle)
        EVP_MAC_free(const_cast<CmacHandle*>(this->handle));
}

RippaSSL::Cmac& RippaSSL::Cmac::operator= (Cmac&& prev)
{
    // takes the relevant data from the source object:
    this->context            = prev.context;
    this->handle             = prev.handle;
    this->currentAlgorithm   = prev.currentAlgorithm;
    this->alreadyUpdatedData = prev.alreadyUpdatedData;
    this->requirePadding     = prev.requirePadding;

    // clears the pointers used by source to handle its resources:
    prev.context = nullptr;
    prev.handle  = nullptr;

    // returns this object:
    return *this;
}
