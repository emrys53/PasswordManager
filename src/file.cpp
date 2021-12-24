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

#include "file.h"


static std::string read_whole_file(const std::string &path) {
    std::ifstream ifs{path};
    std::stringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

static std::string
create_entry(const std::string_view &master_key, const std::string_view &id, const std::string_view &user_name, const std::string_view &password) {
    const auto sha_key = sha_256_digest(master_key);
    const auto encrypted_user_name = encrypt_aes(user_name, sha_key);
    const auto encrypted_password = encrypt_aes(password, sha_key);
    std::string message{id};
    return message += " " + vector_to_hex_string(encrypted_user_name) + " " + vector_to_hex_string(encrypted_password);

}

static void encrypt_empty(const std::string &vault, const std::string &master_file, const std::string_view &id, const std::string_view &user_name,
                          const std::string_view &password) {
    const auto master_key = read_whole_file(master_file);

    const auto message = create_entry(master_key, id, user_name, password);

    auto hmac_key = string_to_vector(master_key);
    const auto hmac_header = hmac(hmac_key, string_to_vector(message), LAMBDA(sha_256_digest_to_vector));

    std::ofstream vault_file{vault, std::ios::trunc};
    vault_file << vector_to_hex_string(hmac_header) << std::endl << message;
}

static void encrypt_non_empty(const std::string &vault, const std::string &master_file, const std::string_view &id, const std::string_view &user_name,
                              const std::string_view &password) {

    std::string master_key = read_whole_file(master_file);
    std::string whole_file = read_whole_file(vault);

    const auto message = create_entry(master_key, id, user_name, password);
    auto prev_message = whole_file.substr(65) + NEWLINE + message;

    auto hmac_key = string_to_vector(master_key);
    const auto hmac_header = hmac(hmac_key, string_to_vector(prev_message), LAMBDA(sha_256_digest_to_vector));

    std::ofstream vault_file{vault, std::ios::trunc};
    vault_file << vector_to_hex_string(hmac_header) << std::endl << prev_message;
}

static std::vector<std::string> get_entries(const std::string &vault) {
    std::ifstream ifs(vault);
    std::vector<std::string> entries;
    bool first = true;
    for (std::string line; std::getline(ifs, line);) {
        // Skip the first element which is hmac-header.
        if (first) {
            first = false;
            continue;
        }
        entries.emplace_back(line);
    }
    return entries;
}

static std::vector<std::string> get_entries(const std::string &vault, const std::string_view &id) {
    std::ifstream ifs(vault);
    std::vector<std::string> entries;
    bool first = true;
    for (std::string line; std::getline(ifs, line);) {
        if (first) {
            first = false;
            continue;
        }
        auto index = line.find(' ');
        if (index != std::string::npos) {
            std::string temp = line.substr(0, index);
            if (temp == id) {
                entries.emplace_back(line);
            }
        }
    }
    return entries;
}

static std::vector<std::string> split_by_space(const std::string &entry) {
    std::istringstream iss{entry};
    std::string temp;
    std::vector<std::string> entry_vector;
    entry_vector.reserve(3);
    while (std::getline(iss, temp, ' ')) {
        if (!temp.empty()) {
            entry_vector.emplace_back(temp);
        }
    }
    return entry_vector;
}

static std::string decrypt_by_id(const std::string &vault, const std::string &master_file, const std::string_view &id) {
    auto master_key = read_whole_file(master_file);
    const auto entries = get_entries(vault, id);
    // Check if id even exists.
    if (entries.empty()) {
        std::cerr << "Nothing with given Id has been found" << std::endl;
        return "";
    }
    std::stringstream ss;
    for (const auto &entry : entries) {
        const auto entry_vector = split_by_space(entry);
        if (entry_vector.size() != 3) {
            throw std::invalid_argument("Each entry has to contain exactly 3 elements");
        }
        const auto decrypted_user_name = vector_to_string(decrypt_aes(hex_string_to_vector(entry_vector.at(1)), sha_256_digest(master_key)));
        const auto decrypted_password = vector_to_string(decrypt_aes(hex_string_to_vector(entry_vector.at(2)), sha_256_digest(master_key)));
        ss << "Id: " << entry_vector.at(0) << std::endl;
        ss << "Username: " << decrypted_user_name << std::endl;
        ss << "Password: " << decrypted_password << std::endl;
    }
    return ss.str();
}

static std::string decrypt_by_id(const std::string &vault, const std::string &master_file) {
    auto master_key = read_whole_file(master_file);
    std::stringstream ss;
    const auto entries = get_entries(vault);

    for (const auto &entry : entries) {
        const auto entry_vector = split_by_space(entry);
        if (entry_vector.size() != 3) {
            throw std::invalid_argument("Each entry has to contain exactly 3 elements");
        }
        const auto decrypted_user_name = vector_to_string(decrypt_aes(hex_string_to_vector(entry_vector.at(1)), sha_256_digest(master_key)));
        const auto decrypted_password = vector_to_string(decrypt_aes(hex_string_to_vector(entry_vector.at(2)), sha_256_digest(master_key)));
        ss << "Id: " << entry_vector.at(0) << std::endl;
        ss << "Username: " << decrypted_user_name << std::endl;
        ss << "Password: " << decrypted_password << std::endl;
    }
    return ss.str();
}

FileVerification verification(const std::string &vault, const std::string &master_file) {


    std::string master_key = read_whole_file(master_file);
    std::string whole_file = read_whole_file(vault);

    if (whole_file.empty()) {
        return FileVerification::EMPTY;
    }
    // If the file is not empty it has to contain 64 bytes which is the expected hmac result and 65th is the line separator.
    if (whole_file.length() < 65) {
        return FileVerification::INCORRECT;
    }

    // Pos is 65 in order to skip line separator.
    const auto message = string_to_vector(whole_file.substr(65));
    auto key = string_to_vector(master_key);

    const auto hmac_output = hmac(key, message, LAMBDA(sha_256_digest_to_vector));
    const auto hmac_expected = hex_string_to_vector(whole_file.substr(0, 64));

    if (hmac_output != hmac_expected) {
        return FileVerification::INCORRECT;
    }
    return FileVerification::CORRECT;
}


void encrypt(const std::string &vault, const std::string &master_file, const std::string_view &id, const std::string_view &user_name,
             const std::string_view &password) {
    FileVerification file_verification = verification(vault, master_file);
    switch (file_verification) {
        case EMPTY:
            encrypt_empty(vault, master_file, id, user_name, password);
            std::cout << "Added the entry: " << "Id: " << id << " Username: " << user_name << " Password: " << password << std::endl;
            break;
        case CORRECT:
            encrypt_non_empty(vault, master_file, id, user_name, password);
            std::cout << "Added the entry: " << "Id: " << id << " Username: " << user_name << " Password: " << password << std::endl;
            break;
        case INCORRECT:
            std::cerr << "Either vault has been tempered with or your master key is wrong" << std::endl;
            break;
    }
}

std::string decrypt(const std::string &vault, const std::string &master_file, const std::string_view &id) {
    FileVerification file_verification = verification(vault, master_file);
    switch (file_verification) {
        case EMPTY:
            std::cerr << "The vault is empty, there is nothing to decrypt" << std::endl;
            break;
        case CORRECT:
            return decrypt_by_id(vault, master_file, id);
            break;
        case INCORRECT:
            std::cerr << "Either vault has been tempered with or your master key is wrong" << std::endl;
            break;
    }
    return "";
}

std::string decrypt(const std::string &vault, const std::string &master_file) {
    FileVerification file_verification = verification(vault, master_file);
    switch (file_verification) {
        case EMPTY:
            std::cerr << "The vault is empty, there is nothing to decrypt" << std::endl;
            break;
        case CORRECT:
            return decrypt_by_id(vault, master_file);
            break;
        case INCORRECT:
            std::cerr << "Either vault has been tempered with or your master key is wrong" << std::endl;
            break;
    }
    return "";
}
