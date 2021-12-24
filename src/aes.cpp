//
// Created by emrys on 04.12.21.
//

#include "aes.h"

void transpose_matrix(std::array<std::array<uint8_t, 4>, 4> &state) {
    for (std::size_t i = 0; i < 4; ++i) {
        for (std::size_t j = i + 1; j < 4; ++j) {
            std::swap(state.at(i).at(j), state.at(j).at(i));
        }
    }
}

void sub_bytes(std::array<std::array<uint8_t, 4>, 4> &state) {
    for (std::size_t i = 0; i < 4; ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            state.at(i).at(j) = S_BOX.at(state.at(i).at(j));
        }
    }
}

void inv_sub_bytes(std::array<std::array<uint8_t, 4>, 4> &state) {
    for (std::size_t i = 0; i < 4; ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            state.at(i).at(j) = INV_S_BOX.at(state.at(i).at(j));
        }
    }
}

void shift_rows(std::array<std::array<uint8_t, 4>, 4> &state) {
    for (std::size_t i = 1; i < 4; ++i) {
        std::array<uint8_t, 4> row{};
        for (std::size_t j = 0; j < 4; ++j) {
            row.at(j) = state.at(i).at((i + j) % 4);
        }
        for (std::size_t j = 0; j < 4; ++j) {
            state.at(i).at(j) = row.at(j);
        }
    }

}

void inv_shift_rows(std::array<std::array<uint8_t, 4>, 4> &state) {
    for (std::size_t i = 1; i < 4; ++i) {
        std::array<uint8_t, 4> row{};
        for (std::size_t j = 0; j < 4; ++j) {
            row.at(j) = state.at(i).at((4 - i + j) % 4);
        }
        for (std::size_t j = 0; j < 4; ++j) {
            state.at(i).at(j) = row.at(j);
        }
    }
}

void mix_columns(std::array<std::array<uint8_t, 4>, 4> &state) {
    for (std::size_t i = 0; i < 4; ++i) {
        std::array<uint8_t, 4> column{};
        for (std::size_t j = 0; j < 4; ++j) {
            column.at(j) = state.at(j).at(i);
        }
        state.at(0).at(i) =
                GALOIS_TABLE_2.at(column.at(0)) ^ GALOIS_TABLE_3.at(column.at(1)) ^ column.at(2) ^ column.at(3);
        state.at(1).at(i) =
                column.at(0) ^ GALOIS_TABLE_2.at(column.at(1)) ^ GALOIS_TABLE_3.at(column.at(2)) ^ column.at(3);
        state.at(2).at(i) =
                column.at(0) ^ column.at(1) ^ GALOIS_TABLE_2.at(column.at(2)) ^ GALOIS_TABLE_3.at(column.at(3));
        state.at(3).at(i) =
                GALOIS_TABLE_3.at(column.at(0)) ^ column.at(1) ^ column.at(2) ^ GALOIS_TABLE_2.at(column.at(3));

    }
}

void inv_mix_columns(std::array<std::array<uint8_t, 4>, 4> &state) {
    for (std::size_t i = 0; i < 4; ++i) {
        std::array<uint8_t, 4> column{};
        for (std::size_t j = 0; j < 4; ++j) {
            column.at(j) = state.at(j).at(i);
        }
        state.at(0).at(i) =
                GALOIS_TABLE_14.at(column.at(0)) ^ GALOIS_TABLE_11.at(column.at(1)) ^ GALOIS_TABLE_13.at(column.at(2))
                ^ GALOIS_TABLE_9.at(column.at(3));
        state.at(1).at(i) =
                GALOIS_TABLE_9.at(column.at(0)) ^ GALOIS_TABLE_14.at(column.at(1)) ^ GALOIS_TABLE_11.at(column.at(2))
                ^ GALOIS_TABLE_13.at(column.at(3));
        state.at(2).at(i) =
                GALOIS_TABLE_13.at(column.at(0)) ^ GALOIS_TABLE_9.at(column.at(1)) ^ GALOIS_TABLE_14.at(column.at(2))
                ^ GALOIS_TABLE_11.at(column.at(3));
        state.at(3).at(i) =
                GALOIS_TABLE_11.at(column.at(0)) ^ GALOIS_TABLE_13.at(column.at(1)) ^ GALOIS_TABLE_9.at(column.at(2))
                ^ GALOIS_TABLE_14.at(column.at(3));
    }
}

void add_round_key(std::array<std::array<uint8_t, 4>, 4> &state, const std::array<uint32_t, 60> &expanded_key, std::size_t offset) {
    /*
     * We need to xor each column of state array with the elements of expanded_key with some offset.
     * Tricky part is, since expanded_key is 32 bit integers but our state array consists of 8 bit integers, to create 32 bit integer from
     * 4 8 bit integers, In little endian architectures, we have to store each byte in reverse order. In big endian architectures swap_endian method
     * is called to ensure the implementation is correct.
     */
    for (std::size_t i = 0; i < 4; ++i) {
        Endian<uint32_t> temp{};
        temp.bit_8.at(0) = state.at(3).at(i);
        temp.bit_8.at(1) = state.at(2).at(i);
        temp.bit_8.at(2) = state.at(1).at(i);
        temp.bit_8.at(3) = state.at(0).at(i);
        if constexpr(std::endian::native == std::endian::big) {
            temp.bit_t = swap_endian(temp.bit_t);
        }
        temp.bit_t = temp.bit_t ^ expanded_key.at(i + offset);
        if constexpr(std::endian::native == std::endian::big) {
            temp.bit_t = swap_endian(temp.bit_t);
        }
        state.at(0).at(i) = temp.bit_8.at(3);
        state.at(1).at(i) = temp.bit_8.at(2);
        state.at(2).at(i) = temp.bit_8.at(1);
        state.at(3).at(i) = temp.bit_8.at(0);

    }
}

uint32_t sub_word(uint32_t word) {

    Endian<uint32_t> temp{};
    temp.bit_t = word;
    for (auto &i : temp.bit_8) {
        i = S_BOX.at(i);
    }
    return temp.bit_t;
}

uint32_t rotate_word(uint32_t word) {
    return std::rotl(word, 8);
}

std::array<uint32_t, 60> key_expansion(const std::array<uint32_t, 8> &key) {
    std::array<uint32_t, 60> to_return{};
    for (std::size_t i = 0; i < 8; ++i) {
        to_return.at(i) = key.at(i);
    }

    for (std::size_t i = 8; i < 60; ++i) {
        uint32_t temp = to_return.at(i - 1);
        if (i % 8 == 0) {
            temp = sub_word(rotate_word(temp)) ^ R_CON.at(i / 8);
        } else if (i % 8 == 4) {
            temp = sub_word(temp);
        }
        to_return.at(i) = to_return.at(i - 8) ^ temp;

    }
    return to_return;
}

std::vector<uint8_t>
encrypt_aes(std::array<std::array<uint8_t, 4>, 4> &state, const std::array<uint32_t, 60> &expanded_key) {
    std::size_t offset = 0;
    add_round_key(state, expanded_key, offset);
    offset += 4;
    for (std::size_t i = 1; i < 14; ++i) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, expanded_key, offset);
        offset += 4;
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, expanded_key, offset);
    std::vector<uint8_t> to_return(16);
    // Transpose the state matrix to get linear results.
    transpose_matrix(state);
    std::memcpy(to_return.data(), state.data(), 16);
    return to_return;
}

std::vector<uint8_t>
decrypt_aes(std::array<std::array<uint8_t, 4>, 4> &state, const std::array<uint32_t, 60> &expanded_key) {
    std::size_t offset = 56;
    add_round_key(state, expanded_key, offset);
    offset -= 4;
    for (std::size_t i = 1; i < 14; ++i) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, expanded_key, offset);
        inv_mix_columns(state);
        offset -= 4;
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, expanded_key, offset);
    // Transpose the state matrix to get linear results.
    transpose_matrix(state);
    std::vector<uint8_t> to_return(16);
    std::memcpy(to_return.data(), state.data(), 16);
    return to_return;
}

std::vector<uint8_t> encrypt_aes(const std::string_view &sw, const std::array<uint32_t, 8> &key) {
    std::size_t len = sw.length();
    std::vector<uint8_t> input(len);
    std::memcpy(input.data(), sw.data(), len);
    return encrypt_aes(input, key);
}

std::vector<uint8_t> encrypt_aes(const std::vector<uint8_t> &input, const std::array<uint32_t, 8> &key) {
    std::size_t len = input.size();
    if (len == 0) {
        throw std::invalid_argument("Input cannot bet empty");
    }
    /*
     * To work with non block length inputs, I use PKCS7 padding technique. I append bytes until input reaches a multiple of block length.
     * The value of bytes are block_length - number of needed bytes.
     * If the input is already a multiple of block length then I will append 0x01 block length times.
     */
    const auto expanded_key = key_expansion(key);
    std::size_t block = 1 + len / 16;
    std::vector<uint8_t> to_return(block * 16);
    // Normal calculations until the last block.
    for (std::size_t i = 0; i < block - 1; ++i) {
        std::array<std::array<uint8_t, 4>, 4> state{};
        std::memcpy(state.data(), input.data() + i * 16, 16);
        transpose_matrix(state);
        const auto block_vector = encrypt_aes(state, expanded_key);
        std::memcpy(to_return.data() + i * 16, block_vector.data(), 16);
    }
    // Padding
    std::array<std::array<uint8_t, 4>, 4> state{};
    uint8_t pad = (16 - len % 16);
    std::memcpy(state.data(), input.data() + (block - 1) * 16, 16 - pad);
    for (uint8_t i = 16 - pad; i < 16; ++i) {
        state.at(i / 4).at(i % 4) = pad;
    }
    transpose_matrix(state);
    const auto block_vector = encrypt_aes(state, expanded_key);
    std::memcpy(to_return.data() + (block - 1) * 16, block_vector.data(), 16);
    return to_return;
}

std::vector<uint8_t> decrypt_aes(const std::vector<uint8_t> &output, const std::array<uint32_t, 8> &key) {
    std::size_t len = output.size();
    if (len == 0 || len % 16 != 0) {
        throw std::invalid_argument("Output cannot be empty");
    }
    const auto expanded_key = key_expansion(key);
    std::size_t block = len / 16;
    std::vector<uint8_t> to_return(block * 16);
    for (std::size_t i = 0; i < block; ++i) {
        std::array<std::array<uint8_t, 4>, 4> state{};
        std::memcpy(state.data(), output.data() + i * 16, 16);
        transpose_matrix(state);
        const auto block_vector = decrypt_aes(state, expanded_key);
        std::memcpy(to_return.data() + i * 16, block_vector.data(), 16);
    }
    // Remove the padding and catch inaccurate key/output attempts.
    uint8_t pad = to_return.at(to_return.size() - 1);
    uint8_t temp = pad;
    while ((temp--) != 0U) {
        uint8_t pop = to_return.back();
        if (pop != pad) {
            throw std::invalid_argument("Incorrect key or output message");
        }
        to_return.pop_back();
    }

    return to_return;
}

std::vector<uint8_t> decrypt_aes(const std::string_view &sw, const std::array<uint32_t, 8> &key) {
    std::size_t len = sw.length();
    std::vector<uint8_t> input(len);
    std::memcpy(input.data(), sw.data(), len);
    return decrypt_aes(input, key);
}