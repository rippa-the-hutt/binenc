#ifndef CRYPTOPROVIDER_H
#define CRYPTOPROVIDER_H

#include <openssl/evp.h>
#include <openssl/params.h>
#include <vector>
#include <map>


namespace RippaSSL {
    enum class MacMode
    {
        CMAC
    };

    class Cmac : public SymCryptoBase<CmacCtx, CmacHandle> {
        public:
            Cmac(Algo                       algo,
                 MacMode                    mode,
                 const std::vector<uint8_t> key,
                 const uint8_t*             iv,
                 bool                       padding = false);

            int update(      std::vector<uint8_t>& output,
                       const std::vector<uint8_t>& input);

            ~Cmac();

        private:
    };
}

#endif
