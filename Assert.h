#ifndef RIPPA_ASSERT_H
#define RIPPA_ASSERT_H

#include <string>

template <typename F>
void Assert(bool condition, std::string errMessage, F&& lambda) {
    if (!condition)
        lambda(errMessage);
}

#endif
