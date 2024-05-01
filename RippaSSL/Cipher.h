#ifndef RIPPASSL_CIPHER_H
#define RIPPASSL_CIPHER_H

#include "Base.h"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <vector>
#include <cstdint>
#include <cstdio>

namespace RippaSSL {
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

    class Cipher : public SymCryptoBase<CipherCtx, CipherHandle> {
        public:
            Cipher(Algo                          algo,
                   BcmMode                       mode,
                   const std::vector<uint8_t>    key,
                   const uint8_t*                iv,
                   bool                          padding = false);

            int update(      std::vector<uint8_t>& output,
                       const std::vector<uint8_t>& input);
            int finalize(      std::vector<uint8_t>& output,
                         const std::vector<uint8_t>& input);

            ~Cipher();

        private:
            CipherFunctionPointers FunctionPointers;
    };
}

#endif
