#ifndef RIPPASSL_ERROR_H
#define RIPPASSL_ERROR_H


namespace RippaSSL {
    // errors thrown by this
    struct InputError_NULLPTR {};
    struct OpenSSLError_CryptoInit {};
    struct OpenSSLError_CryptoUpdate {};
    struct OpenSSLError_CryptoFinalize {};
}

#endif
