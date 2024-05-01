

#include "binIO.h"
#include "Assert.h"

#include <string>
#include <vector>
#include <iostream>

#include <cstdio>
#include <cstdlib>


int main(int argc, char* argv[])
{
    // test vectors:
    const char* failString01 = "00010203gg05060708";
    const char* failString02 = "";
    const char* failString03 = "0001020304050";
    const char* goodString   = "000102030405060708090A0B0C0D0F101112131415";

    // variables:
    std::vector<uint8_t> vecArg;
    std::string stringArg;

    // test profiling:
    int failedTestsCounter = 0;
    int numberOfTests       = 0;

    // this is the lambda that is passed to the Assert() function, and
    // determines what is the behavior of the Assert itself in case of failure:
    auto errorHandler =
        [&failedTestsCounter](std::string errMsg) {
            std::cerr << errMsg << std::endl;
            ++failedTestsCounter;
        };

    // ACTUAL TESTS

    // BinIO module ///////////////////////////////////////////////////////////

    // NEGATIVE TESTS
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

    // POSITIVE TESTS:
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

    // FINAL REPORT ///////////////////////////////////////////////////////////
    std::cout << "\nNumber of failed tests/total tests:\n"
              << failedTestsCounter << "/" << numberOfTests
              << std::endl;
    return 0;
}
