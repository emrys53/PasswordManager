//
// Created by emrys on 16.12.21.
//

#ifndef HMAC_H
#define HMAC_H


#include "sha256.h"


template<typename Callable>
std::vector<uint8_t> hmac(std::vector<uint8_t> &key, const std::vector<uint8_t> &message, Callable callable) {

    if (key.size() > SHA_256_BLOCK_SIZE) {
        key = callable(key);
    }
    if (key.size() < SHA_256_BLOCK_SIZE) {
        key.reserve(SHA_256_BLOCK_SIZE);
        while (key.size() != SHA_256_BLOCK_SIZE) {
            key.push_back(0);
        }
    }

    return std::vector<uint8_t>();
}


#endif // HMAC_H
