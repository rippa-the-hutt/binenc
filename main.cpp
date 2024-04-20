#include "binIO.h"
#include "cryptoprovider.h"
#include "RippaSSL/error.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdarg>

#include <openssl/evp.h>
#include <openssl/params.h>


int main(int argc, char* argv[])
{
    unsigned char buf[4096];
    unsigned char iv[16];
    unsigned char* iv_ptr = NULL;
    unsigned char key[32];
    RippaSSL::Algo     algo;
    RippaSSL::BcmMode  bcm;
    int msgIdx;

    if ((argc < 4) || (argc > 5))
    {
        printf("Usage: binenc MODE KEY [IV] MESSAGE\n"
               "    The key shall be provided without spaces. The same applies to the message and "
               "IV.\n"
               "    An example usage:\n"
               "    $ ./binenc AES128CBC 000102030405060708090A0B0C0D0E0F 000000000000000000000000"
               "00000000 000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F\n");
        return 1;
    }

    {
        char* myMode = argv[1];

        if (!strcmp(myMode, "AES128CBC"))
        {
            bcm  = RippaSSL::BcmMode::Bcm_CBC_Encrypt;
            algo = RippaSSL::Algo::algo_AES128CBC;
        }
        else if(!strcmp(myMode, "AES256CBC"))
        {
            bcm  = RippaSSL::BcmMode::Bcm_CBC_Encrypt;
            algo = RippaSSL::Algo::algo_AES256CBC;
        }
        else if (!strcmp(myMode, "AES128ECB"))
        {
            bcm  = RippaSSL::BcmMode::Bcm_ECB_Encrypt;
            algo = RippaSSL::Algo::algo_AES128ECB;
        }
        else if (!strcmp(myMode, "AES256ECB"))
        {
            bcm  = RippaSSL::BcmMode::Bcm_ECB_Encrypt;
            algo = RippaSSL::Algo::algo_AES256ECB;
        }
        else
        {
            printf("Check your MODE input!\nPossible values are:\n"
            "   AES128CBC, AES128ECB, AES256CBC, AES256ECB\n");
            return 1;
        }
    }

    size_t keyLen = BIO_readHexBinary(argv[2], key);
    if ((16 != keyLen) && (32 != keyLen))
    {
        printf("Wrong key length: %lu!\n", keyLen);
        exit(1);
    }

    if (argc == 5)
    {
        if (16 != BIO_readHexBinary(argv[3], iv))
        {
            printf("Wrong iv length!\n");
            exit(1);
        }

        iv_ptr = iv;
        msgIdx = 4;
    }
    else if ((algo == RippaSSL::Algo::algo_AES128CBC) ||
             (algo == RippaSSL::Algo::algo_AES256CBC))
    {
        printf("CBC modes require an IV for correct operation!\n");
        exit(1);
    }
    else
    {
        msgIdx = 3;
    }

    // reads the input message and places it into buf:
    int msgLen = BIO_readHexBinary(argv[msgIdx], buf);

    // creates the relevant object:
    try {
        RippaSSL::Cipher myCbc {algo, bcm, key, iv_ptr};
        myCbc.finalize(buf, msgLen, buf, msgLen);
    }
    catch (RippaSSL::InputError_NULLPTR) {
        printf("Error! The key pointer is invalid, or something nasty happened"
        " while calling OpenSSL's EVP_CIPHER_CTX_new()!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoInit) {
        printf("Error! OpenSSL failed to call its Init method!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoUpdate) {
        printf("Error! OpenSSL failed to call its Update method!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoFinalize) {
        printf("Error: OpenSSL failed to call its Finalize method!\n");

        return 1;
    }

    // prints the result:
    printf("Result: ");
    BIO_printHexBinary(buf, msgLen);

    return 0;
}

