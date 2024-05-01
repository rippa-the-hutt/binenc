
#include "Base.h"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <cstdint>

const std::map<RippaSSL::Algo, size_t> RippaSSL::blockSizes
{
    {RippaSSL::Algo::algo_AES128CBC, 16},
    {RippaSSL::Algo::algo_AES128ECB, 16},
    {RippaSSL::Algo::algo_AES256CBC, 16},
    {RippaSSL::Algo::algo_AES256ECB, 16}
};

//template<typename CTX, typename HND>
//RippaSSL::SymCryptoBase<CTX, HND>::SymCryptoBase(Algo algo, bool padding)
//: context {nullptr}, handle {nullptr},
//  currentAlgorithm {algo},
//  alreadyUpdatedData {}, requirePadding {padding}
//{
//    // nothing required.
//}

// the abstract base class needs the definition for its pure virtual destructor:
//template<typename CTX, typename HND>
//RippaSSL::SymCryptoBase<CTX, HND>::~SymCryptoBase()
//{
//    // nothing to be done.
//}

