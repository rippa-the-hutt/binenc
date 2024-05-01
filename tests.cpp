

#include "binIO.h"
#include <string>
#include <vector>
#include <iostream>

#include <cstdio>
#include <cstdlib>

template <typename F>
void Assert(bool condition, std::string errMessage, F&& lambda) {
    lambda(condition, errMessage);
}

int main(int argc, char* argv[])
{
    const char* failString01 = "00010203gg05060708";
    const char* failString02 = "";
    const char* failString03 = "0001020304050";
    const char* goodString   = "000102030405060708090A0B0C0D0F101112131415";
    std::vector<uint8_t> vecArg;
    std::string stringArg;
    int failedTestsCounter = 0;
    int numberOfTests       = 0;
    auto errorHandler =
        [&failedTestsCounter](bool condition, std::string errMsg) {
            if (!condition)
            {
                std::cerr << errMsg << std::endl;
                ++failedTestsCounter;
            }
        };

    char* teststring = const_cast<char*>(failString01);
    int outLen = BinIO::readHexBinary(vecArg, teststring);
    ++numberOfTests;
    Assert(outLen == 0,
           "The BinIO::readHexBinary function failed to report"
           " that the input string is not a valid HEX array!",
           errorHandler);

    teststring = const_cast<char*>(failString02);
    outLen = BinIO::readHexBinary(vecArg, teststring);
    ++numberOfTests;
    Assert(outLen == 0,
           "The BinIO::readHexBinary function failed to report"
           " that the input string is empty!",
           errorHandler);

    teststring = const_cast<char*>(failString03);
    outLen = BinIO::readHexBinary(vecArg, teststring);
    ++numberOfTests;
    Assert(outLen == 0,
           "The BinIO::readHexBinary function failed to report"
           " that the input string's length is odd!",
           errorHandler);

    teststring = const_cast<char*>(goodString);
    outLen = BinIO::readHexBinary(vecArg, teststring);
    ++numberOfTests;
    Assert(outLen != 0,
           "The BinIO::readHexBinary function failed to parse"
           " a valid HEX array!",
           errorHandler);

    try {
        outLen = BinIO::hexBinaryToString(stringArg, vecArg);
    } catch (BinIO::InputError_IllegalConversion& ic) {
        std::cerr << "The BinIO::hexBinaryToString threw exception:\n"
                  << "    std::to_chars() failed to convert data!"
                  << std::endl;
    }
    ++numberOfTests;
    Assert(std::string {goodString} == stringArg,
           "The BinIO::hexBinaryToString function failed to reconstruct the"
           " correct vector:\nReturned:\n" + stringArg +
           "\nExpected:\n" + teststring,
           errorHandler);

    std::cout << "\nNumber of failed tests/total tests:\n"
              << failedTestsCounter << "/" << numberOfTests
              << std::endl;
    return 0;
}
