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


#define LAMBDA(func_name) [](const auto &x){return func_name(x);}

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

std::vector<uint8_t> hex_string_to_vector(const std::string_view &);

std::string keygen(uint32_t);

std::vector<uint8_t> string_to_vector(const std::string_view &);

#endif //UTIL_H
