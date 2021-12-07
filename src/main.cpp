#include "aes.h"
#include <bitset>


int main() {
    std::string s{"AAAAAAAAAAAAAAA"};
    std::array<uint32_t, 8> key{};
    for (std::size_t i = 0; i < 8; ++i) {
        key.at(i) = 0x41414141;
    }
    const auto encrypted = encrypt_aes(s, key);
    for (auto i : encrypted) {
        printf("%.2X", i);
    }
    printf("\n");
    const auto decrypted = decrypt_aes(encrypted, key);
    for (auto i : decrypted) {
        printf("%.2X", i);
    }
    printf("\n");

}

