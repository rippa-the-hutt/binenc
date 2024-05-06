#ifndef RIPPASSL_BASE_H
#define RIPPASSL_BASE_H

#include <openssl/evp.h>
#include <openssl/params.h>

#include <vector>
#include <map>
#include <cstdint>
#include <cstdio>

typedef EVP_MAC_CTX     CmacCtx;
typedef EVP_MAC         CmacHandle;
typedef EVP_CIPHER_CTX  CipherCtx;
typedef EVP_CIPHER      CipherHandle;

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
        AES128CBC,
        AES128ECB,
        AES256CBC,
        AES256ECB
    };

    extern const std::map<RippaSSL::Algo, size_t> blockSizes;

    template<typename CTX, typename HND>
    class SymCryptoBase {
        public:
            SymCryptoBase(Algo algo, bool padding)
                : context {nullptr}, handle {nullptr},
                  currentAlgorithm {algo},
                  alreadyUpdatedData {}, requirePadding {padding}
            {
                // nothing required.
            }

            virtual ~SymCryptoBase() {};

            virtual int update(      std::vector<uint8_t>& output,
                               const std::vector<uint8_t>& input) = 0;
            virtual int finalize(      std::vector<uint8_t>& output,
                                 const std::vector<uint8_t>& input) = 0;

        protected:
            CTX* context;
            const HND* handle;
            Algo currentAlgorithm;
            int alreadyUpdatedData;
            bool requirePadding;

            // disables copy semantics - this class contains pointer resources,
            // and copying them might be VERY dangerous, as the bookkeeping is
            // made by OpenSSL:
            SymCryptoBase(const SymCryptoBase&)             = delete;
            SymCryptoBase& operator= (const SymCryptoBase&) = delete;

            //TODO: allows move semantics for constructor, but deletes the
            //      move assignment as per sect. 4.4.1 of C++ Move Semantics by
            //      N. Josuttis. The rationale for this comes from the
            //      constatation that the operator= is non-virtual, so the
            //      derived class' members wouldn't be handled in case of
            //      interface access!
            SymCryptoBase(SymCryptoBase&& prev) :
                context{prev.context},
                handle{prev.handle},
                currentAlgorithm{prev.currentAlgorithm},
                alreadyUpdatedData{prev.alreadyUpdatedData},
                requirePadding{prev.requirePadding}
            {
                // invalidates the previous instance's pointers:
                prev.context = nullptr;
                prev.handle  = nullptr;
            }

            SymCryptoBase& operator= (SymCryptoBase&&) = delete;
    };
}

#endif
