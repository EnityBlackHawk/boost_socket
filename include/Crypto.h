#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace Crypto {

    std::vector<unsigned char> sha256(const std::string& input);
    std::vector<unsigned char> encrypt_aes(const std::string& plaintext,
                                       const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& iv);
    std::string decrypt_aes(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv);

    std::vector<unsigned char> rsa_encrypt(const std::string& pubkey_path,
                                       const std::vector<unsigned char>& data);
    std::vector<unsigned char> rsa_decrypt(const std::string& privkey_path,
                                       const std::vector<unsigned char>& encrypted_data);
    std::vector<unsigned char> generate_random_bytes(size_t length);

    std::vector<unsigned char> rsa_sign(const std::string& privkey_path,
                                    const std::string& message);

    bool rsa_verify(const std::string& pubkey_path,
                const std::string& message,
                const std::vector<unsigned char>& signature);

    bool verify_certificate_signature( const nlohmann::json& cert, const std::string& ca_public_key_file );
    std::string base64_encode(const std::vector<unsigned char>& data);
    nlohmann::json sign_certificate( const nlohmann::json& cert, const std::string& ca_private_key_file );

}
