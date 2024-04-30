#ifndef CRYPTOPROVIDER_H
#define CRYPTOPROVIDER_H

#include <openssl/evp.h>
#include <openssl/params.h>
#include <vector>
#include <map>

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

    const std::map<RippaSSL::Algo, size_t> blockSizes
    {
        {RippaSSL::Algo::algo_AES128CBC, 16},
        {RippaSSL::Algo::algo_AES128ECB, 16},
        {RippaSSL::Algo::algo_AES256CBC, 16},
        {RippaSSL::Algo::algo_AES256ECB, 16}
    };


    enum class MacMode
    {
        CMAC
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
            SymCryptoBase(Algo algo, bool padding);
            virtual ~SymCryptoBase() = 0;

            virtual int update(      std::vector<uint8_t>& output,
                               const std::vector<uint8_t>  input) = 0;
            virtual int finalize(      std::vector<uint8_t>& output,
                                 const std::vector<uint8_t>  input) = 0;

        protected:
            CTX* context;
            const HND* handle;
            Algo currentAlgorithm;
            int alreadyUpdatedData;
            bool requirePadding;
    };

    class Cipher : public SymCryptoBase<CipherCtx, CipherHandle> {
        public:
            Cipher(Algo                          algo,
                   BcmMode                       mode,
                   const std::vector<uint8_t>    key,
                   const uint8_t*                iv,
                   bool                          padding = false);

            int update(      std::vector<uint8_t>& output,
                       const std::vector<uint8_t>  input);
            int finalize(      std::vector<uint8_t>& output,
                         const std::vector<uint8_t>  input);

            ~Cipher();

        private:
            CipherFunctionPointers FunctionPointers;
    };

    class Cmac : public SymCryptoBase<CmacCtx, CmacHandle> {
        public:
            Cmac(Algo                       algo,
                 MacMode                    mode,
                 const std::vector<uint8_t> key,
                 const uint8_t*             iv,
                 bool                       padding = false);

            int update(      std::vector<uint8_t>& output,
                       const std::vector<uint8_t>  input);

            ~Cmac();

        private:
    };

    int performCmacOp(const char*          subAlg,
                      const unsigned char* key, size_t  keyLen,
                      const unsigned char* iv,  size_t  ivLen,
                      const unsigned char* msg, size_t  msgLen,
                      unsigned char*       out, size_t* outLen);
}

#endif
