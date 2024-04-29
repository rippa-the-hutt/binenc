#ifndef RIPPASSL_ERROR_H
#define RIPPASSL_ERROR_H


namespace RippaSSL {
    // errors thrown by this
    struct InputError_NULLPTR {};
    struct InputError_MISALIGNED_DATA {};
    struct OpenSSLError_CryptoInit {};
    struct OpenSSLError_CryptoUpdate {};
    struct OpenSSLError_CryptoFinalize {};
}

#endif
