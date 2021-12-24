//
// Created by emrys on 09.12.21.
//
#include "util.h"

std::vector<uint8_t> hex_string_to_vector(const std::string_view &sw) {
    if (sw.length() % 2 != 0) {
        throw std::invalid_argument("String has to be a multiple of 2");
    }
    static constexpr std::array<uint8_t, 16> hex_array{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::vector<uint8_t> to_return(sw.length() / 2);
    for (std::size_t i = 0; i < sw.length(); i += 2) {

        const auto *it_1 = std::find(hex_array.begin(), hex_array.end(), std::tolower(sw.at(i)));
        const auto *it_2 = std::find(hex_array.begin(), hex_array.end(), std::tolower(sw.at(i + 1)));
        auto distance_1 = std::distance(hex_array.begin(), it_1);
        auto distance_2 = std::distance(hex_array.begin(), it_2);
        to_return.at(i / 2) = static_cast<uint8_t>(distance_2 + 16 * distance_1);
    }
    return to_return;
}

std::string vector_to_hex_string(const std::vector<uint8_t> &v) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    std::for_each(v.cbegin(), v.cend(), [&oss](int c) { oss << std::setw(2) << c; });
    return oss.str();
}


std::string keygen(uint32_t key_length) {
    if (key_length == 0) {
        key_length = 8;
        std::cerr << "Key Length increased to 8." << std::endl;


    }
    if (key_length > 32) {
        key_length = 32;
        std::cerr << "Key Length reduced to 32" << std::endl;
    }
    std::random_device rd{};
    std::uniform_int_distribution<std::size_t> dist(0, ALPHA_NUM.length() - 1);
    std::string to_return{};
    to_return.reserve(key_length);
    for (std::size_t i = 0; i < key_length; ++i) {
        to_return.push_back(ALPHA_NUM.at(dist(rd)));
    }
    return to_return;
}

std::vector<uint8_t> string_to_vector(const std::string_view &sw) {
    std::vector<uint8_t> input(sw.length());
    std::memcpy(input.data(), sw.data(), sw.length());
    return input;
}

std::string vector_to_string(const std::vector<uint8_t> &v) {
    std::string to_return{};
    to_return.resize(v.size());
    std::memcpy(to_return.data(), v.data(), to_return.size());
    return to_return;
}
