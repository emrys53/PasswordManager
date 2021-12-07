//
// Created by emrys on 04.12.21.
//

#include "aes.h"

// For debugging purposes.
static void print_array(std::array<std::array<uint8_t, 4>, 4> &state) {
    for (std::size_t i = 0; i < 4; ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            printf("%.2X", state.at(j).at(i));
        }
    }
    printf("\n");
}

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
    print_array(state);

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
                GALOIS_TABLE_14.at(column.at(0)) ^ GALOIS_TABLE_11.at(column.at(1)) ^ GALOIS_TABLE_13.at(column.at(2)) ^ GALOIS_TABLE_9.at(column.at(3));
        state.at(1).at(i) =
                GALOIS_TABLE_9.at(column.at(0)) ^ GALOIS_TABLE_14.at(column.at(1)) ^ GALOIS_TABLE_11.at(column.at(2)) ^ GALOIS_TABLE_13.at(column.at(3));
        state.at(2).at(i) =
                GALOIS_TABLE_13.at(column.at(0)) ^ GALOIS_TABLE_9.at(column.at(1)) ^ GALOIS_TABLE_14.at(column.at(2)) ^ GALOIS_TABLE_11.at(column.at(3));
        state.at(3).at(i) =
                GALOIS_TABLE_11.at(column.at(0)) ^ GALOIS_TABLE_13.at(column.at(1)) ^ GALOIS_TABLE_9.at(column.at(2)) ^ GALOIS_TABLE_14.at(column.at(3));
    }
}

void add_round_key(std::array<std::array<uint8_t, 4>, 4> &state, const std::array<uint32_t, 60> &expanded_key, std::size_t offset) {
    for (std::size_t i = 0; i < 4; ++i) {
        Endian<uint32_t> temp{};
        temp.bit_8.at(0) = state.at(0).at(i);
        temp.bit_8.at(1) = state.at(1).at(i);
        temp.bit_8.at(2) = state.at(2).at(i);
        temp.bit_8.at(3) = state.at(3).at(i);
        temp.bit_t = swap_endian(temp.bit_t);
        temp.bit_t = temp.bit_t ^ expanded_key.at(i + offset);
        temp.bit_t = swap_endian(temp.bit_t);
        state.at(0).at(i) = temp.bit_8.at(0);
        state.at(1).at(i) = temp.bit_8.at(1);
        state.at(2).at(i) = temp.bit_8.at(2);
        state.at(3).at(i) = temp.bit_8.at(3);

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


std::vector<uint8_t> encrypt_aes(std::array<std::array<uint8_t, 4>, 4> &state, const std::array<uint32_t, 60> &expanded_key) {
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
    transpose_matrix(state);
    std::memcpy(to_return.data(), state.data(), 16);
    return to_return;
}

std::vector<uint8_t> decrypt_aes(std::array<std::array<uint8_t, 4>, 4> &state, const std::array<uint32_t, 60> &expanded_key) {
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
    const auto expanded_key = key_expansion(key);
    std::size_t block = 1 + len / 16;
    std::vector<uint8_t> to_return(block * 16);
    for (std::size_t i = 0; i < block - 1; ++i) {
        std::array<std::array<uint8_t, 4>, 4> state{};
        std::memcpy(state.data(), input.data() + i * 16, 16);
        transpose_matrix(state);
        const auto block_vector = encrypt_aes(state, expanded_key);
        std::memcpy(to_return.data() + i * 16, block_vector.data(), 16);
    }
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

std::vector<uint8_t> decrypt_aes(const std::vector<uint8_t> &output, const std::array<uint32_t, 60> &expanded_key) {
    return std::vector<uint8_t>();
}

std::vector<uint8_t> decrypt_aes(const std::string_view &sw, const std::array<uint32_t, 8> &key) {
    return std::vector<uint8_t>();
}




