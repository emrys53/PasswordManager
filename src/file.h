/*
It is a simple Password-Manager written in C++20
Copyright (C) 2021  Emrys

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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

enum NameOrPassword {
    NAME,
    PASSWORD
};


FileVerification verification(const std::string &, const std::string &);

void encrypt(const std::string &, const std::string &, const std::string_view &, const std::string_view &, const std::string_view &);

std::string decrypt(const std::string &, const std::string &, const std::string_view &);

std::string decrypt(const std::string &, const std::string &);

void remove_by_id(const std::string &, const std::string &, const std::string_view &);


#endif //FILE_H
