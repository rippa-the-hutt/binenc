

#include "binIO.h"
#include "Assert.h"

#include <string>
#include <vector>
#include <iostream>

#include <cstdio>
#include <cstdlib>
#include <cstring>


int main(int argc, char* argv[])
{
    // test vectors:
    struct TestVector {
        const std::string testString;
        int               expectedLen;
        const std::string errorMessage;

        TestVector(const std::string& _testString,
                   int                _expectedLen,
                   const std::string& _errorMessage)
        : testString {std::move(_testString)}, expectedLen {_expectedLen},
          errorMessage {std::move(_errorMessage)}
        {
        }
    };

    std::vector<TestVector> negativeTests;
    std::vector<TestVector> positiveTests;

    negativeTests.push_back({"00010203gg05060708", 0,
         "The BinIO::readHexBinary function failed to report"
         " that the input string is not a valid HEX array!"});

    negativeTests.push_back({"", 0,
         "The BinIO::readHexBinary function failed to report"
         " that the input string is empty!"});

    negativeTests.push_back({"0001020304050", 0,
         "The BinIO::readHexBinary function failed to report"
         " that the input string's length is odd!"});

    std::string goodString01 {"000102030405060708090A0B0C0D0F101112131415"};
    positiveTests.push_back({std::string{goodString01},
                             static_cast<int>(goodString01.length() / 2),
         "The BinIO::readHexBinary function failed to parse"
         " a valid HEX array!"});

    positiveTests.push_back({std::string{goodString01},
                             static_cast<int>(goodString01.length() / 2),
         "The BinIO::hexBinaryToString function failed to reconstruct the"
         " correct vector:"});

    // variables:
    std::vector<uint8_t> vecArg;
    std::string stringArg;

    // test profiling:
    int failedTestsCounter = 0;
    int numberOfTests      = 0;

    // this is the lambda that is passed to the Assert() function, and
    // determines what is the behavior of the Assert itself in case of failure:
    auto errorHandler =
        [&failedTestsCounter] (std::string errMsg) {
            std::cerr << errMsg << std::endl;
            ++failedTestsCounter;
        };

    // ACTUAL TESTS

    // BinIO module ///////////////////////////////////////////////////////////

    auto binIoReadHexTests =
        [&failedTestsCounter, &numberOfTests, &errorHandler]
            (const char*           teststring,
             const int             expectedLen,
             const std::string&    errorMessage) {
                std::vector<uint8_t> inputVec;
                int outLen = BinIO::readHexBinary(inputVec, teststring);
                ++numberOfTests;
                Assert(outLen == expectedLen, errorMessage, errorHandler);
        };

    auto binIoWriteStringTests =
        [binIoReadHexTests, &failedTestsCounter, &numberOfTests, &errorHandler]
            (
             const char*           teststring,
             const std::string&    errorMessage) {
            // first, builds the vector:
            std::string          outputStr;
            std::vector<uint8_t> vecArg;
            BinIO::readHexBinary(vecArg, teststring);
            // then, the actual DUT is run:
            try {
                BinIO::hexBinaryToString(outputStr, vecArg);
            } catch (BinIO::InputError_IllegalConversion& ic) {
                std::cerr << "The BinIO::hexBinaryToString threw exception:\n"
                          << "    std::to_chars() failed to convert data!"
                          << std::endl;
            }
            ++numberOfTests;
            Assert(std::string {teststring} == outputStr,
                   errorMessage +
                   "\nReturned:\n" + outputStr +
                   "\nExpected:\n" + teststring,
                   errorHandler);
        };

    // NEGATIVE TESTS
    for (auto test : negativeTests) {
        binIoReadHexTests(test.testString.data(),
                          test.expectedLen,
                          test.errorMessage);
    }

    // POSITIVE TESTS:
    for (auto test : positiveTests) {
        binIoReadHexTests(test.testString.data(),
                          test.expectedLen,
                          test.errorMessage);

        binIoWriteStringTests(test.testString.data(),
                              test.errorMessage);
    }

    // FINAL REPORT ///////////////////////////////////////////////////////////
    std::cout << "\nNumber of failed tests/total tests:\n"
              << failedTestsCounter << "/" << numberOfTests
              << std::endl;
    return 0;
}
