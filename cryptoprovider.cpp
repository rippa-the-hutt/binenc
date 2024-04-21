
#include "cryptoprovider.h"
#include "RippaSSL/error.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <map>

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

    if (!FunctionPointers.cryptoInit(context,
                                     handle,
                                     const_cast<uint8_t*>(key),
                                     const_cast<uint8_t*>(iv)))
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

//TODO: CMAC part still to be done!
int RippaSSL::performCmacOp(const char*          subAlg,
                            const unsigned char* key,    size_t  keyLen,
                            const unsigned char* iv,     size_t  ivLen,
                            const unsigned char* msg,    size_t  msgLen,
                            unsigned char*       out,    size_t* outLen)
{
    int rc = 1;
    EVP_MAC_CTX *ctx = NULL;

    // fetches the CMAC mode of operation:
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "cmac", NULL);

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
