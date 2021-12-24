//
// Created by emrys on 23.12.21.
//

#include <iomanip>
#include "file.h"


static std::string read_whole_file(const std::string &path) {
    std::ifstream ifs{path};
    std::stringstream string_stream;
    string_stream << ifs.rdbuf();
    return string_stream.str();
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
            break;
        case CORRECT:
            encrypt_non_empty(vault, master_file, id, user_name, password);
            break;
        case INCORRECT:
            std::cerr << "Either vault has been tempered with or your master key is wrong" << std::endl;
            break;
    }
}

void decrypt(const std::string &vault, const std::string &master_file, const std::string_view &id) {

}
