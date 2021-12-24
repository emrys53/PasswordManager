/*
It is a simple Password-Manager written in C++20
Copyright (C) 2021  Emrys

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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
#include <iomanip>


#define LAMBDA(func_name) [](const auto &x){return func_name(x);}

#ifdef _WIN32
#define NEWLINE "\r\n"
#elif defined macintosh // OS 9
#define NEWLINE "\r"
#else
#define NEWLINE "\n" // Mac OS X uses \n
#endif


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

std::string vector_to_hex_string(const std::vector<uint8_t> &);

std::string keygen(uint32_t);

std::vector<uint8_t> string_to_vector(const std::string_view &);

std::string vector_to_string(const std::vector<uint8_t> &);


#endif //UTIL_H
