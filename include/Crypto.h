#pragma once
#include <string>

namespace Crypto {

    std::string sha256(const std::string& input);
    std::string encrypt_aes(const std::string& plaintext, const std::string& key);
    std::string decrypt_aes(const std::string& ciphertext, const std::string& key);

}
