#include "Crypto.h"

#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <fstream>
#include <stdexcept>
#include <iostream>

std::vector<unsigned char> Crypto::generate_random_bytes(size_t length) {
    std::vector<unsigned char> buffer(length);
    if (!RAND_bytes(buffer.data(), length)) {
        throw std::runtime_error("Erro ao gerar bytes aleatórios");
    }
    return buffer;
}

std::vector<unsigned char> Crypto::sha256(const std::string& message) {
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int len;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, message.data(), message.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    EVP_MD_CTX_free(ctx);

    hash.resize(len);
    return hash;
}


std::vector<unsigned char> Crypto::encrypt_aes(const std::string& plaintext,
                                       const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, final_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(len + final_len);
    return ciphertext;
}


std::string Crypto::decrypt_aes(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, final_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(len + final_len);
    return std::string(plaintext.begin(), plaintext.end());
}


std::vector<unsigned char> Crypto::rsa_encrypt(const std::string& pubkey_path,
                                       const std::vector<unsigned char>& data) {
    std::ifstream file(pubkey_path);
    if (!file) throw std::runtime_error("Erro ao abrir public.pem");

    FILE* fp = fopen(pubkey_path.c_str(), "rb");
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) throw std::runtime_error("Erro ao ler chave pública");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_encrypt_init(ctx);

    size_t outlen = 0;
    EVP_PKEY_encrypt(ctx, nullptr, &outlen, data.data(), data.size());

    std::vector<unsigned char> out(outlen);
    EVP_PKEY_encrypt(ctx, out.data(), &outlen, data.data(), data.size());
    out.resize(outlen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return out;
}

std::vector<unsigned char> Crypto::rsa_decrypt(const std::string& privkey_path,
                                       const std::vector<unsigned char>& encrypted_data) {
    FILE* fp = fopen(privkey_path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Erro ao abrir private.pem");

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) throw std::runtime_error("Erro ao ler chave privada");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_decrypt_init(ctx);

    size_t outlen = 0;
    EVP_PKEY_decrypt(ctx, nullptr, &outlen, encrypted_data.data(), encrypted_data.size());

    std::vector<unsigned char> out(outlen);
    EVP_PKEY_decrypt(ctx, out.data(), &outlen, encrypted_data.data(), encrypted_data.size());
    out.resize(outlen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return out;
}

std::vector<unsigned char> Crypto::rsa_sign(const std::string& privkey_path,
                                    const std::string& message) {
    FILE* fp = fopen(privkey_path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Erro ao abrir chave privada");

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) throw std::runtime_error("Erro ao ler chave privada");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Erro ao criar contexto");

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
        throw std::runtime_error("Erro em DigestSignInit");

    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0)
        throw std::runtime_error("Erro em DigestSignUpdate");

    size_t siglen = 0;
    EVP_DigestSignFinal(ctx, nullptr, &siglen);

    std::vector<unsigned char> signature(siglen);
    if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) <= 0)
        throw std::runtime_error("Erro em DigestSignFinal");

    signature.resize(siglen);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return signature;
}


bool Crypto::rsa_verify(const std::string& pubkey_path,
                const std::string& message,
                const std::vector<unsigned char>& signature) {
    FILE* fp = fopen(pubkey_path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Erro ao abrir chave pública");

    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) throw std::runtime_error("Erro ao ler chave pública");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Erro ao criar contexto");

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
        throw std::runtime_error("Erro em DigestVerifyInit");

    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) <= 0)
        throw std::runtime_error("Erro em DigestVerifyUpdate");

    const int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result == 1;
}

std::vector<unsigned char> base64_decode(const std::string& b64_input) {
    BIO* bio, *b64;
    int decodeLen = (b64_input.length() * 3) / 4;
    std::vector<unsigned char> buffer(decodeLen);

    bio = BIO_new_mem_buf(b64_input.data(), b64_input.size());
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // Sem quebras de linha
    bio = BIO_push(b64, bio);

    int len = BIO_read(bio, buffer.data(), buffer.size());
    buffer.resize(len);

    BIO_free_all(bio);
    return buffer;
}

std::string Crypto::base64_encode(const std::vector<unsigned char>& data) {
    BIO* bio = nullptr;
    BIO* b64 = nullptr;
    BUF_MEM* bufferPtr = nullptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // Sem quebras de linha
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);

    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    return encoded;
}

nlohmann::json Crypto::sign_certificate(
    const nlohmann::json& cert,
    const std::string& ca_private_key_file
) {

    std::string signed_data = cert.dump();
    std::vector<unsigned char> signature = rsa_sign(ca_private_key_file, signed_data);

    nlohmann::json signed_cert = cert;
    signed_cert["signature"] = base64_encode(signature);
    return signed_cert;
}

bool Crypto::verify_certificate_signature(
    const nlohmann::json& cert,
    const std::string& ca_public_key_file
) {
    std::string signature_b64 = cert["signature"].get<std::string>();
    std::vector<unsigned char> signature = base64_decode(signature_b64);

    nlohmann::json cert_copy = cert;
    cert_copy.erase("signature");

    std::string signed_data = cert_copy.dump();

    return rsa_verify(ca_public_key_file, signed_data, signature);
}


