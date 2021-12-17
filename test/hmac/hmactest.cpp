//
// Created by emrys on 17.12.21.
//

//
// Created by emrys on 05.12.21.
//

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <doctest/doctest.h>
#include "hmac.h"
#include "sha256.h"

TEST_CASE("HMAC BASIC CASE") {
    std::string key{"mykey"};
    std::string message{"helloworld"};
    auto v_1 = string_to_vector(key);
    auto v_2 = string_to_vector(message);
    const auto output = hmac(v_1, v_2, LAMBDA(sha_256_digest_to_vector));
    const auto expected = hex_string_to_vector("7fdfaa9c9c0931f52d9ebf2538bc99700f2e771f3af1c1d93945c2256c11aedd");
    CHECK_EQ(output, expected);
}

TEST_CASE("HMAC UNIT TEST") {
    std::string key{"Enter the  Key"};
    std::string message{"Enter Plain Text to Compute Hash"};
    auto v_1 = string_to_vector(key);
    auto v_2 = string_to_vector(message);
    const auto output = hmac(v_1, v_2, LAMBDA(sha_256_digest_to_vector));
    const auto expected = hex_string_to_vector("6bbd83b89417602c9de60f73db421a2247d4a1c083ca4a781b8fe973d091d715");
    CHECK_EQ(output, expected);
}


TEST_CASE("HMAC LONG KEY") {
    std::string key{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};
    std::string message{"helloworld"};
    auto v_1 = string_to_vector(key);
    auto v_2 = string_to_vector(message);
    const auto output = hmac(v_1, v_2, LAMBDA(sha_256_digest_to_vector));
    const auto expected = hex_string_to_vector("de70711f052dfa3b9e5b4aa54ce57c62062d7d8e4b6c1657b342e8d79cf44d52");
    CHECK_EQ(output, expected);
}

TEST_CASE("HMAC LONG KEY AND MESSAGE") {
    std::string key{"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy"};
    std::string message{
            "electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem"};
    auto v_1 = string_to_vector(key);
    auto v_2 = string_to_vector(message);
    const auto output = hmac(v_1, v_2, LAMBDA(sha_256_digest_to_vector));
    const auto expected = hex_string_to_vector("31113837bd8f34df563caa8b9cb00b5e0aaefb7c65936fbe21cd62894ac33fd4");
    CHECK_EQ(output, expected);
}
