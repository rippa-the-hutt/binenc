
#include "binIO.h"

#include <string>
#include <vector>
#include <iostream>
#include <charconv>
#include <algorithm>

#include <cstring>
#include <cstdio>
#include <cstdint>

size_t BinIO::readHexBinary(std::vector<uint8_t>& binOut, const char* is)
{
    // builds a string outta the input char array from stdin:
    std::string argString {is};

    // consistency checks on the input: the string shall be non-empty and
    // made up of an even number of characters:
    size_t inputLen = argString.length();
    if (!inputLen || (inputLen % 2))
    {
        std::cerr << "BinIO::readHexBinary: Invalid Hex string in input - "
                     "please check that input is correctly populated and the "
                     "number of characters is even!\n"
                  << argString
                  << std::endl;

        return 0;
    }

    for (size_t i = 0; i < argString.length(); i += 2)
    {
        size_t digitNumberOfChars = 2;
        std::string argHexDigit {argString.substr(i, 2)};
        int curByte;

        try {
            curByte = stoi(argHexDigit, &digitNumberOfChars, 16);
        } catch (...) {
            std::cerr << "BinIO::readHexBinary: invalid HEX characters in input"
                         "stream!\n"
                      << argString
                      << ".\n";

            binOut.clear();
            return 0;
        }

        binOut.push_back(curByte);
    }

    return binOut.size();
}

size_t BinIO::hexBinaryToString(std::string&         outStr,
                                std::vector<uint8_t> inHex)
{
    // initializes the output to the empty string, in case the caller didn't:
    outStr = "";

    if (!inHex.size())
        return 0;

    for (size_t i = 0; i < inHex.size(); ++i)
    {
        int offset = 0;
        std::string tmp {"00"};

        // if the number is smaller than 16, we need to add a leading 0 to keep
        // a byte representation:
        // TODO: we might make this a parameter and choose whether to also offer
        //       word alignment!
        if (inHex[i] < 0x10u)
        {
            ++offset;
        }

        auto rc = std::to_chars(tmp.data() + offset,
                                tmp.data() + tmp.length(),
                                inHex[i],
                                16);

        if (std::errc::value_too_large == rc.ec)
        {
            throw InputError_IllegalConversion {};
        }

        outStr += tmp;
    }

    std::transform(outStr.begin(), outStr.end(),
                   outStr.begin(),
                   [](char c){return std::toupper(c);});

    return outStr.length();
}

int BinIO::printHexBinary(const std::vector<uint8_t>& binIn)
{
    for (auto i = 0u; i < binIn.size(); ++i)
        printf("%02X", binIn[i]);
    printf("\n");

    return 0;
}
