//
// Created by emrys on 05.12.21.
//

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <doctest/doctest.h>
#include <aes.h>
#include <sha256.h>
/*
 * Test values are taken from https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
 */
TEST_CASE("EXPANSION 256 BIT CIPHER KEY") {
    std::array<uint32_t, 8> cipher_key{
            0x603deb10,
            0x15ca71be,
            0x2b73aef0,
            0x857d7781,
            0x1f352c07,
            0x3b6108d7,
            0x2d9810a3,
            0x0914dff4
    };
    std::array<uint32_t, 60> expected_expanded_key{
            0x603deb10,
            0x15ca71be,
            0x2b73aef0,
            0x857d7781,
            0x1f352c07,
            0x3b6108d7,
            0x2d9810a3,
            0x0914dff4,
            0x9ba35411,
            0x8e6925af,
            0xa51a8b5f,
            0x2067fcde,
            0xa8b09c1a,
            0x93d194cd,
            0xbe49846e,
            0xb75d5b9a,
            0xd59aecb8,
            0x5bf3c917,
            0xfee94248,
            0xde8ebe96,
            0xb5a9328a,
            0x2678a647,
            0x98312229,
            0x2f6c79b3,
            0x812c81ad,
            0xdadf48ba,
            0x24360af2,
            0xfab8b464,
            0x98c5bfc9,
            0xbebd198e,
            0x268c3ba7,
            0x09e04214,
            0x68007bac,
            0xb2df3316,
            0x96e939e4,
            0x6c518d80,
            0xc814e204,
            0x76a9fb8a,
            0x5025c02d,
            0x59c58239,
            0xde136967,
            0x6ccc5a71,
            0xfa256395,
            0x9674ee15,
            0x5886ca5d,
            0x2e2f31d7,
            0x7e0af1fa,
            0x27cf73c3,
            0x749c47ab,
            0x18501dda,
            0xe2757e4f,
            0x7401905a,
            0xcafaaae3,
            0xe4d59b34,
            0x9adf6ace,
            0xbd10190d,
            0xfe4890d1,
            0xe6188d0b,
            0x046df344,
            0x706c631e
    };
    const auto expanded_key = key_expansion(cipher_key);
    for (std::size_t i = 0; i < expanded_key.size(); ++i) {
        CHECK_EQ(expanded_key.at(i), expected_expanded_key.at(i));
    }


}

TEST_CASE("AES SHIFT ROW") {
    std::array<std::array<uint8_t, 4>, 4> state{};
    for (uint8_t i = 0; i < 4; ++i) {
        for (uint8_t j = 0; j < 4; ++j) {
            state.at(i).at(j) = 4 * i + j;
        }
    }
    const auto copy = state;
    shift_rows(state);
    CHECK_EQ(state.at(0).at(0), 0);
    CHECK_EQ(state.at(0).at(1), 1);
    CHECK_EQ(state.at(0).at(2), 2);
    CHECK_EQ(state.at(0).at(3), 3);
    CHECK_EQ(state.at(1).at(0), 5);
    CHECK_EQ(state.at(1).at(1), 6);
    CHECK_EQ(state.at(1).at(2), 7);
    CHECK_EQ(state.at(1).at(3), 4);
    CHECK_EQ(state.at(2).at(0), 10);
    CHECK_EQ(state.at(2).at(1), 11);
    CHECK_EQ(state.at(2).at(2), 8);
    CHECK_EQ(state.at(2).at(3), 9);
    CHECK_EQ(state.at(3).at(0), 15);
    CHECK_EQ(state.at(3).at(1), 12);
    CHECK_EQ(state.at(3).at(2), 13);
    CHECK_EQ(state.at(3).at(3), 14);
    inv_shift_rows(state);
    CHECK_EQ(state, copy);


}

TEST_CASE("AES MIX COLUMNS") {
    std::array<std::array<uint8_t, 4>, 4> state{};
    for (uint8_t i = 0; i < 4; ++i) {
        for (uint8_t j = 0; j < 4; ++j) {
            state.at(i).at(j) = 4 * i + j;
        }
    }
    const auto copy = state;
    mix_columns(state);
    CHECK_FALSE(copy == state);
    inv_mix_columns(state);
    CHECK_EQ(state, copy);

}

TEST_CASE("AES SUB BYTES") {
    std::array<std::array<uint8_t, 4>, 4> state{};
    for (uint8_t i = 0; i < 4; ++i) {
        for (uint8_t j = 0; j < 4; ++j) {
            state.at(i).at(j) = 4 * i + j;
        }
    }
    const auto copy = state;
    sub_bytes(state);
    CHECK_FALSE(copy == state);
    inv_sub_bytes(state);
    CHECK_EQ(state, copy);
}

TEST_CASE("AES ENCRYPT/DECRYPT STANDARD EXAMPLE") {
    std::array<uint32_t, 8> key{
            0x00010203,
            0x04050607,
            0x08090a0b,
            0x0c0d0e0f,
            0x10111213,
            0x14151617,
            0x18191a1b,
            0x1c1d1e1f
    };
    std::array<std::array<uint8_t, 4>, 4> state{};
    uint8_t temp = 0x00;
    for (std::size_t i = 0; i < 4; ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            state.at(i).at(j) = temp;
            temp += 0x11;
        }
    }
    const auto copy = state;
    transpose_matrix(state);
    const auto output = encrypt_aes(state, key_expansion(key));
    std::vector<uint8_t> expected(16);
    expected.at(0) = 0x8e;
    expected.at(1) = 0xa2;
    expected.at(2) = 0xb7;
    expected.at(3) = 0xca;
    expected.at(4) = 0x51;
    expected.at(5) = 0x67;
    expected.at(6) = 0x45;
    expected.at(7) = 0xbf;
    expected.at(8) = 0xea;
    expected.at(9) = 0xfc;
    expected.at(10) = 0x49;
    expected.at(11) = 0x90;
    expected.at(12) = 0x4b;
    expected.at(13) = 0x49;
    expected.at(14) = 0x60;
    expected.at(15) = 0x89;
    CHECK_EQ(output, expected);
    transpose_matrix(state);
    const auto decrypted = decrypt_aes(state, key_expansion(key));
    CHECK_EQ(state, copy);
}


TEST_CASE("AES ENCRYPT/DECRYPT WITH PKCS7") {
    std::string s{"AAAAAAAAAAAAAAA"};
    std::array<uint32_t, 8> key{};
    for (std::size_t i = 0; i < 8; ++i) {
        key.at(i) = 0x41414141;
    }
    const auto encrypted = encrypt_aes(s, key);
    std::vector<uint8_t> expected(16);
    expected.at(0) = 0xe3;
    expected.at(1) = 0xa7;
    expected.at(2) = 0x30;
    expected.at(3) = 0x6e;
    expected.at(4) = 0x06;
    expected.at(5) = 0x96;
    expected.at(6) = 0x1d;
    expected.at(7) = 0x7b;
    expected.at(8) = 0x59;
    expected.at(9) = 0x0c;
    expected.at(10) = 0xbb;
    expected.at(11) = 0x67;
    expected.at(12) = 0x9b;
    expected.at(13) = 0x6a;
    expected.at(14) = 0x8a;
    expected.at(15) = 0x8a;
    CHECK_EQ(encrypted, expected);
    const auto decrypted = decrypt_aes(encrypted, key);
    CHECK_EQ(decrypted.size(), s.length());
    for (std::size_t i = 0; i < decrypted.size(); ++i) {
        CHECK_EQ(decrypted.at(i), static_cast<uint8_t >(s.at(i)));
    }
}

TEST_CASE("AES RANDOM ENCRYPT/DECRYPT") {
    std::string s{"213asdjkasdi21d,/a.sdkDLSADASDKAc,zxmcio3290412-ds;a.cxasdKASDA?S>DASDKASd"};
    for (std::size_t i = 0; i < 256; ++i) {
        const auto key = sha_256_digest(s);
        const auto encrypted = encrypt_aes(s, key);
        const auto decrypted = decrypt_aes(encrypted, key);
        CHECK_EQ(decrypted.size(), s.length());
        for (std::size_t j = 0; j < decrypted.size(); ++j) {
            CHECK_EQ(decrypted.at(j), static_cast<uint8_t >(s.at(j)));
        }
        s.append(1, static_cast<char>(i));
    }
}

TEST_CASE("AES DECRYPT CHECK INVALID PADDING") {
    std::string s{"ABCDEFGH0"};
    const auto key = sha_256_digest(s);
    for (std::size_t i = 0; i < 256; ++i) {
        CHECK_THROWS(s, key);
        s.append(1, static_cast<char>(i));
    }

}



