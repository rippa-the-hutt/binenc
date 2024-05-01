

#include "binIO.h"
#include <string>
#include <vector>
#include <iostream>

#include <cstdio>
#include <cstdlib>

void myAssert(bool condition, std::string errMessage) {
    if (!condition)
    {
        std::cerr << errMessage << std::endl;
    }
}

int main(int argc, char* argv[])
{
    char* failString = "00010203gg05060708";
    char* goodString = "000102030405060708";
    std::vector<uint8_t> vecArg;

    char* teststring = failString;
    int outLen = BinIO::readHexBinary(teststring, vecArg);
    myAssert(outLen == 0, "The BinIO::readHexBinary function failed to report"
                          " that the input string is not a valid HEX array!");

    teststring = goodString;
    outLen = BinIO::readHexBinary(teststring, vecArg);
    myAssert(outLen != 0, "The BinIO::readHexBinary function failed to parse"
                           " a valid HEX array!");
    //BinIO::printHexBinary(out, outLen);

    return 0;
}
