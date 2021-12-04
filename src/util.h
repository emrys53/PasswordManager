//
// Created by emrys on 03.12.21.
//

#ifndef PASSWORDMANAGER_UTIL_H
#define PASSWORDMANAGER_UTIL_H

#include <array>
#include <bitset>
#include <iostream>
#include <bit>
#include <vector>
#include <cstring>

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
 */
template<typename std::size_t N>
std::vector<uint32_t> string_pad0(const std::string_view &sw) {

    static_assert(N > 31, "Minimum chunk size supported is 32 bits");
    static_assert((N & 31) == 0, "Chunk size has to be a multiple of 32");
    const std::size_t sw_bits = sw.length() * 8;
    if (sw_bits > N) {
        throw std::invalid_argument("Given string has too many bits");
    }


    std::vector<uint32_t> toReturn(N / 32);
    std::memcpy(toReturn.data(), sw.data(), sw.length());
    if constexpr(std::endian::native == std::endian::little) {
        for (std::size_t i = 0; i < toReturn.size(); ++i) {
            toReturn.at(i) = swap_endian(toReturn.at(i));
        }
    }
    return toReturn;

}


#endif //PASSWORDMANAGER_UTIL_H
