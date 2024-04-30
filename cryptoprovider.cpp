
#include "cryptoprovider.h"
#include "RippaSSL/error.h"
#include <openssl/evp.h>
#include <openssl/params.h>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <map>
#include <string>

template<typename CTX, typename HND>
RippaSSL::SymCryptoBase<CTX, HND>::SymCryptoBase(Algo algo, bool padding)
: context {nullptr},       handle {nullptr},
  currentAlgorithm {algo},
  alreadyUpdatedData {}, requirePadding {padding}
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
RippaSSL::Cipher::Cipher(Algo                       algo,
                         BcmMode                    mode,
                         const std::vector<uint8_t> key,
                         const uint8_t*             iv,
                         bool                       padding)
: SymCryptoBase(algo, padding)
{
    if (NULL == (context = EVP_CIPHER_CTX_new()))
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

    if (!FunctionPointers.cryptoInit(context, handle, &key[0], &iv[0]))
    {
        throw OpenSSLError_CryptoInit {};
    }

    // sets the padding, as per constructor:
    EVP_CIPHER_CTX_set_padding(context, requirePadding);
}

int RippaSSL::Cipher::update(      std::vector<uint8_t>& output,
                             const std::vector<uint8_t>  input)
{
    int outLen = 0;
    if (!FunctionPointers.cryptoUpdate(context, &output[0], &outLen,
                                                &input[0],  input.size()))
    {
        throw OpenSSLError_CryptoUpdate {};
    }

    alreadyUpdatedData += input.size();

    return outLen;
}

int RippaSSL::Cipher::finalize(      std::vector<uint8_t>& output,
                               const std::vector<uint8_t>  input)
{
    int finalizeLen = 0;

    if (input.size())
    {
        try {
            // checks whether the output vector needs more reserved space for
            // the update function to work properly:
            unsigned int requiredMemory = alreadyUpdatedData + input.size();
            requiredMemory +=
                (requirePadding) ?
                    blockSizes.at(currentAlgorithm) -
                       (input.size() % blockSizes.at(currentAlgorithm)) :
                    0;

            if (output.capacity() < requiredMemory)
            {
                output.resize(requiredMemory);
            }

            update(output, input);
        } catch (OpenSSLError_CryptoUpdate& cu) {
            throw OpenSSLError_CryptoFinalize {};
        } catch (InputError_MISALIGNED_DATA& misdata) {
            throw;
        }
    }

    if (!FunctionPointers.cryptoFinal(context, &output[0], &finalizeLen))
    {
        throw OpenSSLError_CryptoFinalize {};
    }

    return finalizeLen;
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
                           const std::vector<uint8_t>  input)
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
