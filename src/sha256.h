//
// Created by emrys on 03.12.21.
//

#ifndef SHA256_H
#define SHA256_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <string_view>
#include <bitset>
#include <cstring>
#include <bit>
#include <functional>
#include "util.h"

/*
 * 1 in Bigendian required for padding.
 */
static constexpr uint8_t BIG_ENDIAN_ONE = 0x80;


/*
 * Chunk size for sha256
 */
static constexpr uint32_t SHA_256_CHUNK_SIZE = 512;

/*
 * Fractional parts of cubic roots of first 64 primes.
 */
static constexpr std::array<uint32_t, 64> HASH_CONSTANT = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


/*
 * Fractional parts of square roots of first 8 primes.
 */
static constexpr std::array<uint32_t, 8> HASH_INITIAL_CONSTANT = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
};

std::vector<uint32_t> sha_256_pad(const std::string_view &);

std::vector<uint32_t> sha_256_pad(const std::vector<uint8_t> &);

std::string sha_256(const std::string_view &);

std::string sha_256(const std::vector<uint8_t> &);

std::array<uint32_t, 8> sha_256_digest(const std::string_view &);

std::array<uint32_t, 8> sha_256_digest(const std::vector<uint8_t> &);

std::vector<uint8_t> sha_256_digest_to_vector(const std::string_view &);

std::vector<uint8_t> sha_256_digest_to_vector(const std::vector<uint8_t> &);


#endif //SHA256_H
