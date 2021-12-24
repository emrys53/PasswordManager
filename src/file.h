//
// Created by emrys on 23.12.21.
//

#ifndef FILE_H
#define FILE_H

#include "hmac.h"
#include "aes.h"
#include "sha256.h"
#include "util.h"
#include <sstream>
#include <fstream>
#include <ostream>
#include <iomanip>


enum FileVerification {
    EMPTY,
    CORRECT,
    INCORRECT
};

FileVerification verification(const std::string &, const std::string &);

void encrypt(const std::string &, const std::string &, const std::string_view &, const std::string_view &, const std::string_view &);

std::string decrypt(const std::string &, const std::string &, const std::string_view &);

std::string decrypt(const std::string &, const std::string &);

#endif //FILE_H
