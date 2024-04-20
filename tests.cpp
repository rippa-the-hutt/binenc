

#include "binIO.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    char* failString = "00010203gg05060708";
    char* goodString = "000102030405060708";
    unsigned char out[64] = {0u};

    char* teststring = failString;
    BIO_readHexBinary(teststring, out);

    teststring = goodString;
    int outLen = BIO_readHexBinary(teststring, out);
    BIO_printHexBinary(out, outLen);

    return 0;
}
