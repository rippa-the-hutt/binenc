#ifndef BININPUTOUTPUT_H
#define BININPUTOUTPUT_H

#include <stdio.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*!
Reads a hex-encoded stream of data from the NULL-terminated char buffer "is" and places its binary
representation in binOut.
Returns the length (in bytes) of the output binary buffer.
*/
size_t BIO_readHexBinary(const char* is, unsigned char* binOut);

/*!
Prints a binary array in its HEX representation.
Returns 0 if successful.
*/
int BIO_printHexBinary(const unsigned char* buf, size_t bufLen);

#ifdef  __cplusplus
}
#endif


#endif
