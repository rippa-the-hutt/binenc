
#include "binIO.h"

#include <string.h>
#include <cstdio>
#include <cstdint>

size_t BIO_readHexBinary(const char* is, unsigned char* binOut)
{
    size_t outLen = strlen(is);
    if (outLen % 2u)
    {
        printf("Wrong binOut length: %lu!\n", outLen);
        return 0;
    }

    // retrieves the actual binOut length:
    outLen /= 2u;

    // reads the binOut from inputargument. The caller is responsible to allocate enough ram:
    if (binOut != NULL)
    {
        const char* pos = is;
        for (size_t i = 0u; i < outLen; i++)
        {
            int n = sscanf(pos, "%02hhx", &(binOut[i]));
            if (1 != n)
            {
                fprintf(stderr, "No matching characters in input stream: %s.\nReturned: %i\n",
                        is, n);
                return 0;
            }

            pos += 2;
        }
    }

    return outLen;
}

int BIO_printHexBinary(const unsigned char* buf, size_t bufLen)
{
    for (size_t i = 0u; i < bufLen; i++)
        printf("%02X", buf[i]);
    printf("\n");

    return 0;
}
