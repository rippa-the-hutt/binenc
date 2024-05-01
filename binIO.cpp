
#include "binIO.h"

#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#include <cstring>
#include <cstdio>
#include <cstdint>

size_t BinIO::readHexBinary(const char* is, std::vector<uint8_t>& binOut)
{
    // builds a string outta the input char array from stdin:
    std::string argString {is};

    for (size_t i = 0; i < argString.length(); i += 2)
    {
        std::istringstream strstream {argString.substr(i, 2)};
        int curByte;
        try {
            strstream >> std::hex >> curByte;
        } catch (...) {
            std::cerr << "Invalid HEX characters in input stream: " << argString
                << ".\n";

            return 0;
        }
        binOut.push_back(curByte);
    }
//
//
//    size_t outLen = strlen(is);
//    if (outLen % 2u)
//    {
//        printf("Wrong binOut length: %lu!\n", outLen);
//        return 0;
//    }
//
//    // retrieves the actual binOut length:
//    outLen /= 2u;
//
//    // reads the binOut from inputargument. The caller is responsible to
//    // allocate enough ram:
//    if (binOut != NULL)
//    {
//        const char* pos = is;
//        for (size_t i = 0u; i < outLen; i++)
//        {
//            int n = sscanf(pos, "%02hhx", &(binOut[i]));
//            if (1 != n)
//            {
//                fprintf(stderr,
//                        "No matching characters in input stream: %s.\n"
//                            "Returned: %i\n",
//                        is,
//                        n);
//                return 0;
//            }
//
//            pos += 2;
//        }
//    }

    return binOut.size();
}

int BinIO::printHexBinary(const std::vector<uint8_t>& binIn)
{
    for (auto i = 0u; i < binIn.size(); ++i)
        printf("%02X", binIn[i]);
    printf("\n");

    return 0;
}
