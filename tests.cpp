

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
    const char* failString01 = "00010203gg05060708";
    const char* failString02 = "";
    const char* failString03 = "0001020304050";
    const char* goodString   = "000102030405060708";
    std::vector<uint8_t> vecArg;

    char* teststring = const_cast<char*>(failString01);
    int outLen = BinIO::readHexBinary(teststring, vecArg);
    myAssert(outLen == 0, "The BinIO::readHexBinary function failed to report"
                          " that the input string is not a valid HEX array!");

    teststring = const_cast<char*>(failString02);
    outLen = BinIO::readHexBinary(teststring, vecArg);
    myAssert(outLen == 0, "The BinIO::readHexBinary function failed to report"
                          " that the input string is empty!");

    teststring = const_cast<char*>(failString03);
    outLen = BinIO::readHexBinary(teststring, vecArg);
    myAssert(outLen == 0, "The BinIO::readHexBinary function failed to report"
                          " that the input string's length is odd!");

    teststring = const_cast<char*>(goodString);
    outLen = BinIO::readHexBinary(teststring, vecArg);
    myAssert(outLen != 0, "The BinIO::readHexBinary function failed to parse"
                           " a valid HEX array!");
    //BinIO::printHexBinary(out, outLen);

    return 0;
}
