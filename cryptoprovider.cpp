
#include "cryptoprovider.h"
#include "RippaSSL/error.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <map>
#include <string>

const std::map<RippaSSL::Algo, int> blockSizes
    {
        {RippaSSL::Algo::algo_AES128CBC, 16},
        {RippaSSL::Algo::algo_AES128ECB, 16},
        {RippaSSL::Algo::algo_AES256CBC, 16},
        {RippaSSL::Algo::algo_AES256ECB, 16}
    };

template<typename CTX, typename HND>
RippaSSL::SymCryptoBase<CTX, HND>::SymCryptoBase(bool padding)
: context {nullptr}, handle {nullptr}, requirePadding {padding}
{
    // nothing required.
}

// the abstract base class needs the definition for its pure virtual destructor:
template<typename CTX, typename HND>
RippaSSL::SymCryptoBase<CTX, HND>::~SymCryptoBase()
{
    // nothing to be done.
}

/*!
Constructor for the symmetric encryption/decryption object. It will initialise
it with proper values, so that on object instantiation, the user gets an
immediately employable entity.
*/
RippaSSL::Cipher::Cipher(Algo              algo,
                         BcmMode           mode,
                         const uint8_t*    key,
                         const uint8_t*    iv,
                         bool              padding)
: SymCryptoBase(padding)
{
    if ((NULL == key) || (NULL == (context = EVP_CIPHER_CTX_new())))
    {
        throw InputError_NULLPTR {};
    }

    if (mode == RippaSSL::BcmMode::Bcm_CBC_Encrypt ||
        mode == RippaSSL::BcmMode::Bcm_ECB_Encrypt)
    {
        FunctionPointers.cryptoInit   = EVP_EncryptInit;
        FunctionPointers.cryptoUpdate = EVP_EncryptUpdate;
        FunctionPointers.cryptoFinal  = EVP_EncryptFinal;
    }
    else if (mode == RippaSSL::BcmMode::Bcm_CBC_Decrypt ||
             mode == RippaSSL::BcmMode::Bcm_ECB_Decrypt)
    {
        FunctionPointers.cryptoInit   = EVP_DecryptInit;
        FunctionPointers.cryptoUpdate = EVP_DecryptUpdate;
        FunctionPointers.cryptoFinal  = EVP_DecryptFinal;
    }

    if (mode == RippaSSL::BcmMode::Bcm_CBC_Encrypt ||
        mode == RippaSSL::BcmMode::Bcm_CBC_Decrypt)
    {
        if (algo == RippaSSL::Algo::algo_AES128CBC)
        {
            handle = EVP_aes_128_cbc();
        }
        else
        {
            handle = EVP_aes_256_cbc();
        }
    }
    else
    {
        if (algo == RippaSSL::Algo::algo_AES128ECB)
        {
            handle = EVP_aes_128_ecb();
        }
        else
        {
            handle = EVP_aes_256_ecb();
        }
    }

    if (!FunctionPointers.cryptoInit(context, handle, key, iv))
    {
        throw OpenSSLError_CryptoInit {};
    }

    // sets the padding, as per constructor:
    EVP_CIPHER_CTX_set_padding(context, requirePadding);
}

int RippaSSL::Cipher::update(uint8_t* output,       int& outLen,
                             const uint8_t* input,  int  inLen)
{
    if(!FunctionPointers.cryptoUpdate(context, output, &outLen, input, inLen))
    {
        throw OpenSSLError_CryptoUpdate {};
    }

    return 0;
}

int RippaSSL::Cipher::finalize(uint8_t* output,       int& outLen,
                               const uint8_t* input,  int  inLen)
{
    int updateLen   = 0;
    int finalizeLen = 0;

    if (input != nullptr)
    {
        try {
            update(output, updateLen, input, inLen);
        } catch (OpenSSLError_CryptoUpdate) {
            throw OpenSSLError_CryptoFinalize {};
        }
    }

    if (!FunctionPointers.cryptoFinal(context, output, &finalizeLen))
    {
        throw OpenSSLError_CryptoFinalize {};
    }

    outLen = updateLen + finalizeLen;

    return 0;
}

/*!
The Cipher entity destructor will take care of releasing the memory for the
symmetric algorithms context. No cleaner solution could be applied as openssl's
crappy paradigm doesn't expose a lot of stuff, so only forward declaration
of pointers is available to client application.
*/
RippaSSL::Cipher::~Cipher()
{
    EVP_CIPHER_CTX_free(context);
}

std::map<RippaSSL::Algo, std::string> cmacAlgoMap {
    {RippaSSL::Algo::algo_AES128CBC, "aes-128-cbc"},
    {RippaSSL::Algo::algo_AES256CBC, "aes-256-cbc"}
};

RippaSSL::Cmac::Cmac(Algo           algo,
                     MacMode        mode,
                     const uint8_t* key,
                     const uint8_t* iv,
                     bool           padding)
: SymCryptoBase(padding)
{
    std::string fetchedMac;
    const std::string macAlgo {cmacAlgoMap[algo]};

    //TODO: we should really explode these parameters to a struct, to
    //      decrease the amount of needed switches:
    const int keyLen = ((RippaSSL::Algo::algo_AES256ECB == algo) ||
                        (RippaSSL::Algo::algo_AES256CBC == algo)) ?
                            32 : 16;

    // if supplied with a new/unrecognized key, std::map will append a new item
    // to its list, calling T's default constructor that, in the std::string
    // case, is an empty string with size 0:
    if (0 == macAlgo.size())
    {
        throw InputError_NULLPTR {};
    }

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
    // params[0] = OSSL_PARAM_construct_utf8_string(
    //                         "cipher",
    //                         const_cast<char*>(macAlgo.c_str()),
    //                         0);
    //  params[1] = OSSL_PARAM_construct_end();
    // OSSL_PARAM params[] = {
    //                         {
    //                             .key = "cipher",
    //                             .data_type = OSSL_PARAM_UTF8_STRING,
    //                             .data = (char*) subAlg, // we trust OpenSSL
    //                             .data_size = 6
    //                         },
    //                         {.key = NULL}   // ending element, as required
    //                                         // by openssl.
    //                       };


    if ((NULL == handle)                                           ||
        (NULL == key)                                              ||
        (NULL == (context = EVP_MAC_CTX_new(
                                const_cast<CmacHandle*>(handle)))) ||
        !EVP_MAC_init(context, (const unsigned char *) key, keyLen, params)
       )
    {
        throw InputError_NULLPTR {};
    }
}

RippaSSL::Cmac::~Cmac()
{
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
