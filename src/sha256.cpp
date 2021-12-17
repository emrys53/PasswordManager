//
// Created by emrys on 03.12.21.
//

#include "sha256.h"


/*
 * Input: Password to use sha256 on
 * Output: Vector of uint32_t that represents the chunk of password included padding.
 */
std::vector<uint32_t> sha_256_pad(const std::vector<uint8_t> &input) {


    const std::size_t input_length = input.size();

    /*
     * Block size always has to be a multiple of 512 bits(chunks)
     * mul_512 is the minimum number of chunks such that (password_length*8+64+1) is a multiple of 512 bits.
     */
    const std::size_t mul_512 = 1 + (input_length * 8 + 64 + 1) / SHA_256_CHUNK_SIZE;

    /*
     * Reserving mul_512*512 number of bits in uint32_t vector.
     */
    std::vector<uint32_t> block(mul_512 * SHA_256_CHUNK_SIZE / 32);

    /*
     * First copy all elements from input to block.data()
     */
    std::memcpy(block.data(), input.data(), input.size());

    /*
     * Padding 1 first to the end of blocks.
     */
    std::size_t padding_start = input_length / 4;
    Endian<uint32_t> pad{block.at(padding_start)};
    pad.bit_8.at(input_length % 4) = BIG_ENDIAN_ONE;
    block.at(padding_start) = pad.bit_t;

    /*
     * Swap from little endian to big endian if the architecture is little endian.
     */
    if constexpr(std::endian::native == std::endian::little) {
        for (std::size_t i = 0; i < padding_start + 1; ++i) {
            block.at(i) = swap_endian(block.at(i));
        }
    }

    /*
     * At the end of block put number of bits
     */
    block.at(block.size() - 1) = static_cast<uint32_t>(input_length) * 8;
    return block;
}

/*
 * Input: Password to use sha256 on
 * Output: Vector of uint32_t that represents the chunk of password included padding.
 */

std::vector<uint32_t> sha_256_pad(const std::string_view &password) {
    const auto input = string_to_vector(password);
    return sha_256_pad(input);
}

static std::array<uint32_t, 8> compute_sha_256(const std::vector<uint32_t> &block) {
    /*
     * Fractional parts of square roots of first 8 primes.
     */
    auto hash_init = HASH_INITIAL_CONSTANT;

    const std::size_t chunk = block.size() / 16;

    /*
     * To see implementation see : https://en.wikipedia.org/wiki/SHA-2
     */
    for (std::size_t i = 0; i < chunk; ++i) {
        std::array<uint32_t, 64> w{0};
        for (std::size_t j = 0; j < 16; ++j) {
            w.at(j) = block.at(i * 16 + j);
        }
        for (std::size_t j = 16; j < 64; ++j) {
            const uint32_t s_0 = (std::rotr(w.at(j - 15), 7)) xor(std::rotr(w.at(j - 15), 18)) xor(w.at(j - 15) >> 3);
            const uint32_t s_1 = (std::rotr(w.at(j - 2), 17)) xor(std::rotr(w.at(j - 2), 19)) xor(w.at(j - 2) >> 10);
            w.at(j) = w.at(j - 16) + s_0 + w.at(j - 7) + s_1;

        }
        auto hash_current = hash_init;
        for (std::size_t j = 0; j < 64; ++j) {
            uint32_t s_1 = (std::rotr(hash_current.at(4), 6)) xor(std::rotr(hash_current.at(4), 11)) xor
                           (std::rotr(hash_current.at(4), 25));
            uint32_t ch = (hash_current.at(4) & hash_current.at(5)) ^((~hash_current.at(4)) & hash_current.at(6));
            uint32_t temp_1 = hash_current.at(7) + s_1 + ch + HASH_CONSTANT.at(j) + w.at(j);
            uint32_t s_0 = (std::rotr(hash_current.at(0), 2)) xor(std::rotr(hash_current.at(0), 13)) xor
                           (std::rotr(hash_current.at(0), 22));
            uint32_t maj = (hash_current.at(0) & hash_current.at(1)) ^(hash_current.at(0) & hash_current.at(2)) ^
                           (hash_current.at(1) & hash_current.at(2));


            uint32_t temp_2 = s_0 + maj;
            hash_current.at(7) = hash_current.at(6);
            hash_current.at(6) = hash_current.at(5);
            hash_current.at(5) = hash_current.at(4);
            hash_current.at(4) = hash_current.at(3) + temp_1;
            hash_current.at(3) = hash_current.at(2);
            hash_current.at(2) = hash_current.at(1);
            hash_current.at(1) = hash_current.at(0);
            hash_current.at(0) = temp_1 + temp_2;
        }
        /*
         * hash_init += hash_current
         */
        std::transform(hash_init.begin(), hash_init.end(), hash_current.begin(), hash_init.begin(), std::plus<>());
    }

    return hash_init;
}

std::string sha_256(const std::string_view &password) {
    const auto password_vector = string_to_vector(password);
    return sha_256(password_vector);
}

std::string sha_256(const std::vector<uint8_t> &password) {
    const auto hashed_values = sha_256_digest(password);
    std::string to_return;
    for (const std::size_t hashed_value : hashed_values) {
        to_return.append(std::bitset<32>(hashed_value).to_string());
    }
    return to_return;
}

std::array<uint32_t, 8> sha_256_digest(const std::string_view &password) {
    const auto password_vector = string_to_vector(password);
    return sha_256_digest(password_vector);
}

std::array<uint32_t, 8> sha_256_digest(const std::vector<uint8_t> &password) {
    const auto block = sha_256_pad(password);
    const auto hashed_values = compute_sha_256(block);
    return hashed_values;
}

std::vector<uint8_t> sha_256_digest_to_vector(const std::string_view &password) {
    const auto password_vector = string_to_vector(password);
    return sha_256_digest_to_vector(password_vector);
}

std::vector<uint8_t> sha_256_digest_to_vector(const std::vector<uint8_t> &password) {
    const auto digest = sha_256_digest(password);
    std::vector<uint8_t> to_return;
    to_return.reserve(32);
    for (auto i : digest) {
        Endian<uint32_t> to_swap{i};
        if constexpr(std::endian::native == std::endian::big) {
            to_swap = swap_endian(to_swap);
        }
        to_return.push_back(to_swap.bit_8.at(3));
        to_return.push_back(to_swap.bit_8.at(2));
        to_return.push_back(to_swap.bit_8.at(1));
        to_return.push_back(to_swap.bit_8.at(0));
    }
    return to_return;
}
