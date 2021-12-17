//
// Created by emrys on 16.12.21.
//


#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <doctest/doctest.h>

#include "util.h"

TEST_CASE("KEY LENGTH TOO SMALL") {
    const auto s = keygen(0);
    CHECK_EQ(s.length(), 8);
}

TEST_CASE("KEY LENGTH TOO BIG") {
    std::string s = keygen(33);
    CHECK_EQ(s.length(), 32);
    s = keygen(64);
    CHECK_EQ(s.length(), 32);
}

TEST_CASE("KEY LENGTH NORMAL") {
    std::string s = keygen(16);
    CHECK_EQ(s.length(), 16);
    s = keygen(32);
    CHECK_EQ(s.length(), 32);
    s = keygen(8);
    CHECK_EQ(s.length(), 8);
}