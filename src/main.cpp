#include "aes.h"
#include "sha256.h"
#include "util.h"
#include <bitset>
#include <fstream>
#include <iostream>
#include <iomanip>
#include "hmac.h"


void cli();

void encrypt_file();

void decrypt_file();

void encrypt_file() {
    std::string path_encrypted, path_master_file;
    std::cout << "Please enter the path of database/encrypted file and master file" << std::endl;
    std::cin >> path_encrypted >> path_master_file;
    std::ofstream encrypted_file(path_encrypted, std::ios::app);
    std::ifstream master_file(path_master_file);
    std::string master_key{};
    master_file >> master_key;
    const auto sha_key = sha_256_digest(master_key);
    std::string id, user_name, password;
    bool b = false;
    while (true) {
        char c;
        std::cout << "To encrypt enter 'e', to exit enter 'q', to go back enter 'b'" << std::endl;
        std::cin >> c;
        if (c == 'e') {
            std::cout << "Please enter Id, username  and password" << std::endl;
            std::cin >> id >> user_name >> password;
            const auto encrypted_user_name = encrypt_aes(user_name, sha_key);
            const auto encrypted_password = encrypt_aes(password, sha_key);
            encrypted_file << id << " ";
            for (auto i : encrypted_user_name) {
                encrypted_file << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t> (i & 0xff);
            }
            encrypted_file << " ";
            for (auto i : encrypted_password) {
                encrypted_file << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t> (i & 0xff);
            }
            encrypted_file << std::endl;
            encrypted_file.flush();
        } else if (c == 'q') {
            break;
        } else if (c == 'b') {
            b = true;
            break;
        } else {
            std::cout << "Unknown option" << std::endl;

        }
    }
    if (b) {
        cli();
    }
}

void decrypt_file() {
    std::string path_encrypted, path_master_file;
    std::cout << "Please enter the path of database/encrypted file and master file" << std::endl;
    std::cin >> path_encrypted >> path_master_file;
    std::ifstream encrypted_file(path_encrypted);
    std::ifstream master_file(path_master_file);
    std::string master_key{};
    master_file >> master_key;

    const auto key = sha_256_digest(master_key);
    std::vector<std::string> elements;
    for (std::string line; std::getline(encrypted_file, line);) {
        std::istringstream iss(line);
        std::string item;
        while (std::getline(iss, item, ' ')) {
            if (!item.empty()) {
                elements.emplace_back(item);
            }
        }
    }
    bool b = false;
    while (true) {
        std::cout << "To decrypt enter 'd', to exit enter 'q', to go back enter 'b'" << std::endl;
        char c;
        std::cin >> c;
        if (c == 'd') {
            std::cout << "Enter Id to decrypt username and password" << std::endl;
            std::string id;
            std::cin >> id;

            if (elements.empty()) {
                std::cout << "No username and password have been found" << std::endl;
                continue;
            }
//            std::cout << "Total of " << elements.size() / 3 << " usernames and passwords have been found with given id" << std::endl;
            if (elements.size() % 3 != 0) {
                throw std::invalid_argument("Encrypted file has been tempered!");
            }
            bool found = false;
            for (std::size_t i = 0; i < elements.size(); i += 3) {
                if (elements.at(i) == id) {
                    found = true;
                    const auto convert_user_name = hex_string_to_vector(elements.at(i + 1));
                    const auto convert_password = hex_string_to_vector(elements.at(i + 2));

                    const auto decrypted_user_name = decrypt_aes(convert_user_name, key);
                    const auto decrypted_password = decrypt_aes(convert_password, key);

                    std::cout << "Username: ";
                    for (auto ch : decrypted_user_name) {
                        std::cout << ch;
                    }
                    std::cout << std::endl;
                    std::cout << "Password: ";
                    for (auto ch : decrypted_password) {
                        std::cout << ch;
                    }
                    std::cout << std::endl;
                }

            }
            if (!found) {
                std::cout << "No username and password with given Id have been found" << std::endl;
            }

        } else if (c == 'q') {
            break;
        } else if (c == 'b') {
            b = true;
            break;
        } else {
            std::cout << "Unknown option" << std::endl;

        }

    }
    if (b) {
        cli();
    }
}

void cli() {
    char c;
    std::cout << "To encrypt enter 'e' to decrypt enter 'd', to quit enter q" << std::endl;
    std::cin >> c;
    if (c == 'e') {
        encrypt_file();
    } else if (c == 'd') {
        decrypt_file();
    } else if (c == 'q') {
        exit(0);
    } else {
        std::cout << "Unknown option" << std::endl;
    }
}


int main() {
//    cli();
}

