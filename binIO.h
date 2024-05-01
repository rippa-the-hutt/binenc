#ifndef BININPUTOUTPUT_H
#define BININPUTOUTPUT_H

#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>

namespace BinIO
{
    /*!
    Reads a hex-encoded stream of data from the NULL-terminated char buffer "is" and places its binary
    representation in binOut.
    Returns the length (in bytes) of the output binary buffer.
    */
    size_t readHexBinary(std::vector<uint8_t>& binOut, const char* is);

    size_t hexBinaryToString(std::string&         outStr,
                             std::vector<uint8_t> inHex);

    /*!
    Prints a binary array in its HEX representation.
    Returns 0 if successful.
    */
    int printHexBinary(const std::vector<uint8_t>& binIn);
}

#endif
