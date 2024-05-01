
#include "cryptoprovider.h"
#include "RippaSSL/Base.h"
#include "RippaSSL/error.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <map>
#include <string>



const std::map<RippaSSL::Algo, std::string> cmacAlgoMap {
    {RippaSSL::Algo::algo_AES128CBC, "aes-128-cbc"},
    {RippaSSL::Algo::algo_AES256CBC, "aes-256-cbc"}
};

RippaSSL::Cmac::Cmac(Algo                       algo,
                     MacMode                    mode,
                     const std::vector<uint8_t> key,
                     const uint8_t*             iv,
                     bool                       padding)
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
        (NULL == &key[0])                                          ||
        (NULL == (context = EVP_MAC_CTX_new(
                                const_cast<CmacHandle*>(handle)))) ||
        !EVP_MAC_init(context,
                      (const unsigned char *) &key[0], key.size(),
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
}

RippaSSL::Cmac::~Cmac()
{
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(const_cast<CmacHandle*>(handle));
}

//TODO: CMAC part still to be done!
int RippaSSL::performCmacOp(const char*          subAlg,
                            const unsigned char* key,    size_t  keyLen,
                            const unsigned char* iv,     size_t  ivLen,
                            const unsigned char* msg,    size_t  msgLen,
                            unsigned char*       out,    size_t* outLen)
{
    int rc = 1;
    EVP_MAC_CTX* ctx = NULL;

    // fetches the CMAC mode of operation:
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "cmac", NULL);

    do
    {
        OSSL_PARAM params[] = {
                                {
                                    .key = "cipher",
                                    .data_type = OSSL_PARAM_UTF8_STRING,
                                    .data = (char*) subAlg, // we trust OpenSSL (... I hope)
                                    .data_size = 6
                                },
                                {.key = NULL}   // ending element, as required by openssl.
                              };

        if (mac == NULL                          ||
            key == NULL                          ||
            (ctx = EVP_MAC_CTX_new(mac)) == NULL ||
            !EVP_MAC_init(ctx, (const unsigned char *) key, keyLen, params)
           )
        {
            printf("Oh-oh! Init exploded (but check your key input pliz)!\n");

            rc = 1;
            break;
        }

        //TODO: check ivLen!
        if ((iv != NULL) && (ivLen != 0))
        {
            rc = EVP_MAC_update(ctx, iv, ivLen);
            if (!rc)
            {
                printf("Check your iv/iv length! Update failed!\n");
                rc = 1;
                break;
            }
        }

        //TODO: we need to assert msgLen to be % BCM_SIZE == 0!
        rc = EVP_MAC_update(ctx, msg, msgLen);
        if (!rc)
        {
            printf("error in update: %i\n", rc);
            rc = 1;
            break;
        }

        rc = EVP_MAC_final(ctx, out, outLen, msgLen);
        if (!rc)
        {
            printf("error in final: %i\n", rc);
            rc = 1;
            break;
        }

        // success!
        rc = 0;
    } while (0);

    // calling destructors:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return rc;
}
