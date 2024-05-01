
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
