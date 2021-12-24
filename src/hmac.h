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

#ifndef HMAC_H
#define HMAC_H


#include "util.h"

static constexpr uint8_t IPAD_CONSTANT = 0x36;

static constexpr uint8_t OPAD_CONSTANT = 0x5c;

/*
 * First Template Argument is the hash function and the second argument is the block size of that hash algorithm
 * Default BLOCK_SIZE is 64 for sha_256 algorithm.
 */
template<typename Callable, std::size_t BLOCK_SIZE = 64>
std::vector<uint8_t> hmac(std::vector<uint8_t> &key, const std::vector<uint8_t> &message, Callable callable) {

    // Keys longer than blockSize are shortened by hashing them
    if (key.size() > BLOCK_SIZE) {
        key = callable(key);
    }
    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (key.size() < BLOCK_SIZE) {
        key.reserve(BLOCK_SIZE);
        while (key.size() != BLOCK_SIZE) {
            key.push_back(0);
        }
    }

    std::vector<uint8_t> o_key_pad;
    std::vector<uint8_t> i_key_pad;
    o_key_pad.reserve(BLOCK_SIZE);
    i_key_pad.reserve(BLOCK_SIZE);
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        o_key_pad.push_back(key.at(i) ^ OPAD_CONSTANT);
        i_key_pad.push_back(key.at(i) ^ IPAD_CONSTANT);
    }

    i_key_pad.insert(i_key_pad.end(), message.begin(), message.end());
    const auto temp = callable(i_key_pad);
    o_key_pad.insert(o_key_pad.end(), temp.begin(), temp.end());
    return callable(o_key_pad);
}


#endif // HMAC_H
