//
// Created by emrys on 09.12.21.
//
#include "util.h"

std::vector <uint8_t> hex_string_to_vector(const std::string_view &sw) {
    if (sw.length() % 2 != 0) {
        throw std::invalid_argument("String has to be a multiple of 2");
    }
    static constexpr std::array<uint8_t, 16> hex_array{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::vector<uint8_t> to_return(sw.length() / 2);
    for (std::size_t i = 0; i < sw.length(); i += 2) {
        auto it_1 = std::find(hex_array.begin(), hex_array.end(), sw.at(i));
        auto it_2 = std::find(hex_array.begin(), hex_array.end(), sw.at(i + 1));
        auto distance_1 = std::distance(hex_array.begin(), it_1);
        auto distance_2 = std::distance(hex_array.begin(), it_2);
        to_return.at(i / 2) = static_cast<uint8_t>(distance_2 + 16 * distance_1);
    }
    return to_return;
}
