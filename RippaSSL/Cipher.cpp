
#include "Base.h"
#include "Cipher.h"
#include "error.h"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <vector>
#include <cstdint>
#include <cstdint>
#include <cstdio>

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
                             const std::vector<uint8_t>& input)
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
                               const std::vector<uint8_t>& input)
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
