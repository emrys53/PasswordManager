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

enum FileVerification {
    EMPTY,
    CORRECT,
    INCORRECT
};

FileVerification verification(const std::string &vault, const std::string &master_file);

void encrypt(const std::string &vault, const std::string &master_file, const std::string_view &id, const std::string_view &user_name,
             const std::string_view &password);

void decrypt(const std::string &vault, const std::string &master_file, const std::string_view &id);

#endif //FILE_H
