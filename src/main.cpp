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

#include <bitset>
#include <iostream>
#include <getopt.h>

#include "file.h"

static constexpr std::string_view USAGE = R"(-m --master <master_file> : After -m provide the master file to encrypt/decrypt data.
-v  --vault <vault> : Provide which data to encrypt or decrypt, namely your vault.
-k --keygen <length>: Create a random alphanumeric password with given length. Minimum length is 8 and maximum is 256.
-e --encrypt <id> : After providing vault and master file, provide an id to encrypt. You also need to provide username and password.
-d --decrypt <id> : Provide an id and it will decrypt all usernames and passwords with given id.
-u --username <username> : To provide username use this flag. It is used in -e --encrypt along with -p --password.
-p --password <password> : To provide password use this flag. It is used in -e --encrypt along with -u --username.
-r --remove <Id> : Remove all occurrences of given id in data base. Not implemented yet.
-c --change <Id> : Change the given Id with new username or new password. You need to at least specify new username or new password. Not implemented yet.
-l --list : It will list all ids, usernames and passwords. Takes no arguments.
-o --output : If specified It will write the result in specified file instead of stdout. Not completely implemented.
-g --generate <output_file> : It will generate a master_key in given output_file. If you want to specify password use -p. For random password use -k, --keygen.
-h --help
Example Usage:
    ./PasswordManager -k 32 =>  It will create a random password with length 32 and print it in stdout.
    ./PasswordManager -g master.txt -k 64 => It will create a random master key with length 64 stored in master.txt
    ./PasswordManager -m master.txt -v vault.txt -e reddit -u myusername -k 16 => It will create an entry with id reddit and username myusername with random password length 16
    ./PasswordManager -m master.txt -v vault.txt -e reddit -u myusername -p mysecretpassword => It will create an entry with id reddit and username myusername with the password mysecretpassword
    ./PasswordManager -m master.txt -v vault.txt -d reddit => It will find all usernames and passwords with Id = reddit and print it out to stdout.
    ./PasswordManager -m master.txt -v vault.txt -l -o output.txt => It will print out every username and password in the vault into the output.txt. If the -o is not use it will print out to stdout.)";


int main(int argc, char **argv) {
    static const char *optstring = ":m:v:g:e:d:u:p:r:c:lo:hk:";
    static constexpr struct option long_options[] = {
            {"master",   required_argument, nullptr, 'm'},
            {"vault",    required_argument, nullptr, 'v'},
            {"keygen",   required_argument, nullptr, 'k'},
            {"encrypt",  required_argument, nullptr, 'e'},
            {"decrypt",  required_argument, nullptr, 'd'},
            {"username", required_argument, nullptr, 'u'},
            {"password", required_argument, nullptr, 'p'},
            {"remove",   required_argument, nullptr, 'r'},
            {"change",   required_argument, nullptr, 'c'},
            {"all",      no_argument,       nullptr, 'a'},
            {"output",   required_argument, nullptr, 'o'},
            {"help",     no_argument,       nullptr, 'h'},
            {"generate", required_argument, nullptr, 'g'},
            {nullptr,    no_argument,       nullptr, 0}
    };
    int32_t opt;
    int32_t optindex;
    bool m = false;
    bool v = false;
    bool k = false;
    bool e = false;
    bool d = false;
    bool u = false;
    bool p = false;
    bool r = false;
    bool c = false;
    bool l = false;
    bool o = false;
    bool g = false;
    uint32_t key_length = 0;
    std::string user_name{};
    std::string password{};
    std::string id{};
    std::string output_file{};
    std::string vault{};
    std::string master_file{};
    std::string generated_master_file{};
    while ((opt = getopt_long(argc, argv, optstring, long_options, &optindex)) != -1) {
        switch (opt) {
            case 'm':
                m = true;
                master_file = optarg;
                break;
            case 'v':
                v = true;
                vault = optarg;
                break;
            case 'k':
                k = true;
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
            case 'l':
                l = true;
                break;
            case 'o':
                o = true;
                output_file = optarg;
                break;
            case 'g':
                g = true;
                generated_master_file = optarg;
                break;
            case 'h':
                std::cout << USAGE << std::endl;
                exit(EXIT_SUCCESS);
            case ':':
                printf("Missing argument for option -%c\n", optopt);
                /* fall through */
            default:
                std::cout << USAGE << std::endl;
                exit(EXIT_FAILURE);
        }
    }
    // No argument is provided
    if (!(m || v || k || e || d || u || p || r || c || l || o || g)) {
        std::cout << USAGE << std::endl;
        exit(EXIT_SUCCESS);
    }
    if (g) {
        if (!p && !k) {
            std::cerr << "To generate master file you have to specify either password with -p or you need to use -k to generate random key" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (p && k) {
            std::cerr << "You can't simultaneously specify password and also use key generator" << std::endl;
            exit(EXIT_FAILURE);
        }
        std::ofstream ofs{generated_master_file};
        if (p) {
            ofs << password;
        }
        if (k) {
            ofs << keygen(key_length);
        }
        ofs.flush();
        exit(EXIT_SUCCESS);
    }
    // keygen can be used for password when also used with encryption. So only use keygen if encryption is not asked for.
    if (k && !e) {
        if (o) {
            std::ofstream ofs{output_file, std::ios::app};
            ofs << keygen(key_length) << std::endl;
        } else {
            std::cout << keygen(key_length) << std::endl;
        }
        exit(EXIT_SUCCESS);
    }
    // TODO Implement functionalities.
    if (!(m && v)) {
        std::cout << "You have to provide a vault and master file to begin any kind of operations" << std::endl;
        exit(EXIT_FAILURE);
    }
    if (e && d) {
        std::cout << "You can't encrypt and decrypt at the same time" << std::endl;
        exit(EXIT_FAILURE);
    }


    if (l) {
        const auto temp = decrypt(vault, master_file);
        if (o) {
            std::ofstream ofs{output_file, std::ios::app};
            ofs << temp << std::endl;
        } else {
            std::cout << temp << std::endl;
        }
        exit(EXIT_SUCCESS);
    }
    if (e) {
        if (!(u && (p || k))) {
            std::cout << "For encryption you need password username and id" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (k) {
            password = keygen(key_length);
        }
        encrypt(vault, master_file, id, user_name, password);

    }

    if (d) {
        const auto temp = decrypt(vault, master_file, id);
        if (o) {
            std::ofstream ofs{output_file, std::ios::app};
            ofs << temp << std::endl;
        } else {
            std::cout << temp << std::endl;
        }
        exit(EXIT_SUCCESS);
    }

    if (r) {
        // TODO: Remove id
        // Find Id and ask user which one to remove if there are more than once and ask for permission.
        remove_by_id(vault, master_file, id);
    }
    if (c) {
        // TODO: Change by Id given username and password.
        if (!(u || p)) {
            std::cout << "To change an Id you either need a new username or new password" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (u) {

        }
        if (p) {

        }
    }
}

