//
// Created by emrys on 03.12.21.
//

#ifndef UTIL_H
#define UTIL_H

#include <array>
#include <bitset>
#include <bit>
#include <vector>
#include <cstring>
#include <cstdint>
#include <string_view>
#include <stdexcept>
#include <random>
#include <iostream>



static constexpr std::string_view ALPHA_NUM{"0123456789!@#$%^&*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"};

/*
 * Union for swapping from little endian to big endian.
 */
template<typename T>
union Endian {
    T bit_t;
    std::array<uint8_t, sizeof(T)> bit_8;
};

/*
 * Input: Little/Big Endian Value
 * Output: Big/Little Endian representation of the input
 */
template<typename T>
constexpr T swap_endian(T value) {
    Endian<T> source{value};
    std::reverse(source.bit_8.begin(), source.bit_8.end());
    return source.bit_t;
}

/*
 * Pads the given string with 0 until it reaches N bits.
 * N has to be a multiple of 32 and positive.
 * If the given string has more than 512 bits it will throw an std::invalid_argument.
 * TODO Implement HMAC and use this.
 */
template<typename std::size_t N>
std::vector<uint32_t> string_pad_0(const std::string_view &sw) {

    static_assert(N > 31, "Minimum chunk size supported is 32 bits");
    static_assert((N & 31) == 0, "Chunk size has to be a multiple of 32");
    const std::size_t sw_bits = sw.length() * 8;
    if (sw_bits > N) {
        throw std::invalid_argument("Given string has too many bits");
    }


    std::vector<uint32_t> to_return(N / 32);
    std::memcpy(to_return.data(), sw.data(), sw.length());
    if constexpr(std::endian::native == std::endian::little) {
        for (auto &i : to_return) {
            i = swap_endian(i);
        }
    }
    return to_return;

}

std::vector<uint8_t> hex_string_to_vector(const std::string_view &);

std::string keygen(uint32_t);

#endif //UTIL_H
