#include "aes.h"
#include "sha256.h"
#include "util.h"
#include <bitset>
#include <fstream>
#include <iostream>
#include <iomanip>
#include "hmac.h"
#include <getopt.h>
#include <algorithm>
#include "file.h"


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

static constexpr std::string_view USAGE = R"(
           -m --master masterfile.txt
           -v  --vault data.txt
           -g --keygen 32
           -e --encrypt "Id"
           -d --decrypt
           -i --id "Id"
           -u --username "Username"
           -p --pasword "Password"
           -r --remove "Id"
           -c --change
           -a --all
           -o --output "outputfile.txt"
           -h --help/)";


int main(int argc, char **argv) {
   /* std::string path = "/home/emrys/CLionProjects/PasswordManager/";
    std::cout << verification(path + argv[1], path + argv[2]) << std::endl;
    encrypt(path+argv[1],path+argv[2],"15","anan","ceden");*/


    /* static const char *optstring = ":m:v:g:e:d:u:p:r:c:a:o:h";
     static constexpr struct option long_options[] = {
             {"master",   required_argument, nullptr, 'm'},
             {"vault",    required_argument, nullptr, 'v'},
             {"keygen",   required_argument, nullptr, 'g'},
             {"encrypt",  required_argument, nullptr, 'e'},
             {"decrypt",  required_argument, nullptr, 'd'},
             {"username", required_argument, nullptr, 'u'},
             {"password", required_argument, nullptr, 'p'},
             {"remove",   required_argument, nullptr, 'r'},
             {"change",   required_argument, nullptr, 'c'},
             {"all",      no_argument,       nullptr, 'a'},
             {"output",   required_argument, nullptr, 'o'},
             {"help",     no_argument,       nullptr, 'h'},
             {nullptr,    no_argument,       nullptr, 0}
     };
     int32_t opt;
     int32_t optindex;
     bool m = false;
     bool v = false;
     bool g = false;
     bool e = false;
     bool d = false;
     bool u = false;
     bool p = false;
     bool r = false;
     bool c = false;
     bool a = false;
     bool o = false;
     uint32_t key_length = 0;
     std::string user_name{};
     std::string password{};
     std::string id{};
     std::string output_file{};
     while ((opt = getopt_long(argc, argv, optstring, long_options, &optindex)) != -1) {
         switch (opt) {
             case 'm':
                 m = true;
                 break;
             case 'v':
                 v = true;
                 break;
             case 'g':
                 g = true;
                 key_length = static_cast<uint32_t>(std::strtoul(optarg, nullptr, 10));
                 break;
             case 'e':
                 e = true;
                 id = optarg;
                 break;
             case 'd':
                 d = true;
                 id = optarg;
                 break;
             case 'u':
                 u = true;
                 user_name = optarg;
                 break;
             case 'p':
                 p = true;
                 password = optarg;
                 break;
             case 'r':
                 r = true;
                 id = optarg;
                 break;
             case 'c':
                 c = true;
                 id = optarg;
                 break;
             case 'a':
                 a = true;
                 break;
             case 'o':
                 o = true;
                 output_file = optarg;
                 break;
             case 'h':
                 std::cout << USAGE << std::endl;
                 exit(EXIT_SUCCESS);
             case ':':
             default:
                 std::cout << USAGE << std::endl;
                 exit(EXIT_FAILURE);
         }
     }
     // TODO Implement functionalities.
     if (!(m && v)) {
         std::cout << "You have to provide a vault and master file to begin any kind of operations" << std::endl;
     }
     if (e && d) {
         std::cout << "You can't encrypt and decrypt at the same time" << std::endl;
         exit(1);
     }

     if (g) {
         if (o) {
             std::ofstream ofs{output_file, std::ios::app};
             ofs << keygen(key_length) << std::endl;
         } else {
             std::cout << keygen(key_length) << std::endl;
         }
         exit(EXIT_SUCCESS);
     }
     if (a) {
         // TODO Encrypt all Ids and output to stdout or file provided by -o
     }
     if (e) {
         if (!(u && p)) {
             std::cout << "For encryption you need password username and id" << std::endl;
             exit(EXIT_FAILURE);
         }
     }

     if (d) {

     }

     if (r) {
         // TODO: Remove id
     }
     if (c) {
         if (!(u || p)) {
             std::cout << "To change an Id you either need a new username or new password" << std::endl;
             exit(EXIT_FAILURE);
         }
         if (u) {

         }
         if (p) {

         }
         // TODO: Change by Id given username and password.
     }*/


//    cli();
}

