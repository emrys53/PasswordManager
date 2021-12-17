//
// Created by emrys on 04.12.21.
//

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <doctest/doctest.h>

#include "sha256.h"

static constexpr std::string_view SHA_256_HELLO_WORLD{
        "1011100101001101001001111011100110010011010011010011111000001000101001010010111001010010110101111101101001111101101010111111101011000100100001001110111111100011011110100101001110000000111011101001000010001000111101111010110011100010111011111100110111101001"};

TEST_CASE("SHA256 hello world") {
    CHECK_EQ(sha_256("hello world"),
             SHA_256_HELLO_WORLD);
}

TEST_CASE("SHA256 EMPTY") {
    const auto output = sha_256_digest_to_vector("");
    const auto expected = hex_string_to_vector("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK_EQ(output, expected);

}

TEST_CASE("SHA256 LONG STRING") {
    std::string test_string(1000, 'c');
    CHECK_EQ(sha_256(test_string),
             "1110111111101110101010010100010010100111011000010101011110101000100011010010100000010000100100011011011010100111100101100000100001100101001110111100000111110001010010100001000111010000001101010111010000110001110000011001011101110000000110110110000101010101");
}

TEST_CASE("SHA256 INPUTS UPTO 4096 EXCEPTION CHECKER") {
    std::string test_string{"LRASKDASI:321l,ds.dqQWEWQEd,sadsa"};
    for (std::size_t i = 0; i < 64; ++i) {
        test_string.append(i, 'Z');
        CHECK_NOTHROW(sha_256(test_string));
    }
}

TEST_CASE("SHA256 DIGEST TO VECTOR") {
    const auto output = sha_256_digest_to_vector("hello world");
    std::string s{};
    for (auto i : output) {
        s.append(std::bitset<8>(i).to_string());
    }
    CHECK_EQ(s, SHA_256_HELLO_WORLD);
}

TEST_CASE("SHA256 INPUT MULTIPLE OF 4") {
    std::string test_string{"AAAA"};
    const auto output = sha_256_digest(test_string);
    std::array<uint32_t, 8> expected{
            0x63c1dd95,
            0x1ffedf6f,
            0x7fd968ad,
            0x4efa39b8,
            0xed584f16,
            0x2f46e715,
            0x114ee184,
            0xf8de9201
    };
    CHECK_EQ(output, expected);
}
