//
// Created by emrys on 04.12.21.
//

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <doctest/doctest.h>

#include "sha256.h"

TEST_CASE("SHA256 hello world") {
    CHECK(sha256("hello world") ==
          "1011100101001101001001111011100110010011010011010011111000001000101001010010111001010010110101111101101001111101101010111111101011000100100001001110111111100011011110100101001110000000111011101001000010001000111101111010110011100010111011111100110111101001");
}

TEST_CASE("SHA256 Empty") {
    CHECK(sha256("") ==
          "0100111010100101110001010000100010100110010101100110111001110110001001000000010101000011111110001111111010110000011011111101010001010111011101110111101111100011100101010100100111000100000000010110010000110110101011111101101001100101110100100011001100001110");

}

TEST_CASE("SHA256 Long String"){
    std::string test_string(10000, 'c');
    CHECK(sha256(test_string) == "1100101110100001001010001010101101110111111100110010101111001010010010100001010010100101001100110101000001101001100011010000000000111011001001100111001111011011111011110000001011010110011111001101010011100111011000101100011100010011010111011010011001111000");
}

TEST_CASE("SHA256 Inputs Upto 4096 Exceptions"){
    for(std::size_t i = 0 ; i < 4096 ; ++i){
            std::string test_string(i,'Z');
    }
}
