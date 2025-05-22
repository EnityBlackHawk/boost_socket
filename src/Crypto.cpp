#include "Crypto.h"

#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

std::string Crypto::sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

std::string Crypto::encrypt_aes(const std::string &plaintext, const std::string &key) {

    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::string ciphertext;
    ciphertext.resize(plaintext.size() + 32);

    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(key.c_str()), iv);

    int ciphertext_len;
    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
        reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string result(reinterpret_cast<char*>(iv), 16);
    result += ciphertext.substr(0, ciphertext_len);
    return result;
}

std::string Crypto::decrypt_aes(const std::string& encrypted, const std::string& key) {
    unsigned char iv[16];
    memcpy(iv, encrypted.data(), 16);
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(encrypted.data() + 16);
    int ciphertext_len = encrypted.size() - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::string plaintext;
    plaintext.resize(ciphertext_len);

    int len;
    int plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(key.c_str()), iv);

    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext.substr(0, plaintext_len);
}