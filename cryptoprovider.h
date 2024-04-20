#ifndef CRYPTOPROVIDER_H
#define CRYPTOPROVIDER_H

#include <openssl/evp.h>
#include <openssl/params.h>

typedef EVP_MAC_CTX     CmacCtx;
typedef EVP_MAC         CmacHandle;
typedef EVP_CIPHER_CTX  CipherCtx;
typedef EVP_CIPHER      CipherHandle;
//static void (*CTX_Free) (EVP_CIPHER_CTX* ctx) = EVP_CIPHER_CTX_free;

namespace RippaSSL {

    enum class BcmMode
    {
        Bcm_CBC_Encrypt,
        Bcm_CBC_Decrypt,
        Bcm_ECB_Encrypt,
        Bcm_ECB_Decrypt
    };

    enum class Algo
    {
        algo_AES128CBC,
        algo_AES128ECB,
        algo_AES256CBC,
        algo_AES256ECB
    };

    struct CipherFunctionPointers {
        int (*cryptoInit) (CipherCtx*           context,
                           const CipherHandle*  cipher,
                           const uint8_t*       key,
                           const uint8_t*       iv);

        int (*cryptoUpdate) (CipherCtx*         context,
                             uint8_t*           out,
                             int*               outLen,
                             const uint8_t*     in,
                             int                inLen);

        int (*cryptoFinal) (CipherCtx*          ctx,
                            uint8_t*            out,
                            int*                outLen);
    };

    template<typename CTX, typename HND>
    class SymCryptoBase {
        public:
            SymCryptoBase(bool padding);
            virtual ~SymCryptoBase() = 0;

            virtual int update(uint8_t* output, int& outLen,
                               uint8_t* input,  int  inLen) = 0;
            virtual int finalize(uint8_t* output, int& outputLen,
                                 uint8_t* input,  int  inLen) = 0;

        protected:
            CTX* context;
            const HND* handle;
            bool requirePadding;
    };

    class Cipher : public SymCryptoBase<CipherCtx, CipherHandle> {
        public:
            Cipher(Algo        algo,
                   BcmMode     mode,
                   uint8_t*    key,
                   uint8_t*    iv,
                   bool        padding = false);

            int update(uint8_t* output, int& outLen,
                       uint8_t* input,  int  inLen);
            int finalize(uint8_t* output, int& outLen,
                         uint8_t* input,  int  inLen);

            ~Cipher();

        private:
            CipherFunctionPointers FunctionPointers;
    };

    class Cmac : public SymCryptoBase<CmacCtx, CmacHandle> {
        public:
            Cmac();
            ~Cmac();

        private:
    };

    int performCmacOp(const char*          subAlg,
                      const unsigned char* key, size_t  keyLen,
                      const unsigned char* iv,  size_t  ivLen,
                      const unsigned char* msg, size_t  msgLen,
                      unsigned char*       out, size_t* outLen);

    int performSymCrytoOp(Algo       algo,
                          BcmMode    mode,
                          uint8_t*   key,
                          uint8_t*   iv,
                          uint8_t*   inData,
                          uint8_t*   outData,
                              int*   len);
}

#endif
