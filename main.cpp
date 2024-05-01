#include "binIO.h"
#include "RippaSSL/error.h"
#include "RippaSSL/Base.h"
#include "RippaSSL/Cipher.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <vector>
#include <ios>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/params.h>


int main(int argc, char* argv[])
{
    std::vector<uint8_t> iv;
    unsigned char* iv_ptr = NULL;
    std::vector<uint8_t> key;
    RippaSSL::Algo     algo;
    RippaSSL::BcmMode  bcm;
    int msgIdx;

    if ((argc < 4) || (argc > 5))
    {
        printf("Usage: binenc MODE KEY [IV] MESSAGE\n"
               "    The key shall be provided without spaces. The same applies"
               " to the message and IV.\n"
               "    An example usage:\n"
               "    $ ./binenc AES128CBC 000102030405060708090A0B0C0D0E0F "
               "00000000000000000000000000000000 000102030405060708090A0B0C0D0E"
               "0F000102030405060708090A0B0C0D0E0F\n");
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


    BinIO::readHexBinary(key, argv[2]);
    if ((16 != key.size()) && (32 != key.size()))
    {
        printf("Wrong key length: %lu!\n", key.size());
        return 1;
    }

    if (argc == 5)
    {
        BinIO::readHexBinary(iv, argv[3]);

        if (RippaSSL::blockSizes.at(algo) != iv.size())
        {
            printf("Wrong iv length!\n");
            return 1;
        }

        iv_ptr = iv.data();
        msgIdx = 4;
    }
    else if ((algo == RippaSSL::Algo::algo_AES128CBC) ||
             (algo == RippaSSL::Algo::algo_AES256CBC))
    {
        printf("CBC modes require an IV for correct operation!\n");
        return 1;
    }
    else
    {
        msgIdx = 3;
    }

    // reads the input message and places it into buf:
    std::vector<uint8_t> msgVector;
    BinIO::readHexBinary(msgVector, argv[msgIdx]);

    // optionally prints the input message:
    //for (size_t i = 0; i < msgVector.size(); ++i)
    //{
    //    std::cout << static_cast<int>(msgVector[i]) << " ";
    //}
    //std::cout << std::endl;

    // creates the relevant object:
    try {
        RippaSSL::Cipher myCbc {algo, bcm, key, iv_ptr};
        myCbc.finalize(msgVector, msgVector);
    }
    catch (RippaSSL::InputError_NULLPTR& nullPtr) {
        printf("Error! The key pointer is invalid, or something nasty happened"
        " while calling OpenSSL's EVP_CIPHER_CTX_new()!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoInit& ci) {
        printf("Error! OpenSSL failed to call its Init method!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoUpdate& cu) {
        printf("Error! OpenSSL failed to call its Update method!\n");

        return 1;
    }
    catch (RippaSSL::OpenSSLError_CryptoFinalize& cf) {
        printf("Error: OpenSSL failed to call its Finalize method!\n");

        return 1;
    }

    // prints the result:
    printf("Result: ");
    BinIO::printHexBinary(msgVector);

    return 0;
}

