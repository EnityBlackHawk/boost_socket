#include <common.h>
#include <Crypto.h>
#include <fstream>
#include <iostream>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <random>

using boost::asio::ip::tcp;

#define PRINT_SIZES 0
#define CHANGE_SIGNATURE 1

#if CHANGE_SIGNATURE
std::random_device rd; // Seed for randomness
std::mt19937 gen(rd()); // Mersenne Twister engine
std::uniform_int_distribution<> dist(1, 10); // Range [1, 2]
#endif

void session(tcp::socket& socket, const std::vector<unsigned char> aes_key, const std::vector<unsigned char> aes_iv) {

    try {
        for (;;) {
            uint32_t msg_len = 0;
            boost::asio::read(socket, boost::asio::buffer(&msg_len, sizeof(msg_len)));
            std::vector<unsigned char> encrypted_msg(msg_len);
            boost::asio::read(socket, boost::asio::buffer(encrypted_msg));

            uint32_t payloadLen = 0;
            boost::asio::read(socket, boost::asio::buffer(&payloadLen, sizeof(payloadLen)));
            std::vector<unsigned char> payload(payloadLen);
            boost::asio::read(socket, boost::asio::buffer(payload));

            const std::vector<unsigned char> original_hash(payload.begin(), payload.begin() + 32);
            const std::vector<unsigned char> original_sign(payload.begin() + 32, payload.end());

            std::string message = Crypto::decrypt_aes(encrypted_msg, aes_key, aes_iv);
            auto computed_hash = Crypto::sha256(message);
            const bool is_valid = Crypto::rsa_verify("../tmp_server_public_key.json", message, original_sign);

            std::cout << message;
            if (computed_hash == original_hash) {
                std::cout << "  ";
            } else {
                std::cout << " ❌";
            }

            if (is_valid) {
                std::cout << " " << std::endl;
            } else {
                std::cout << " 󰌿 Assinatura invalida" << std::endl;
            }

        }

    } catch (std::exception& e) {
        std::cerr << "Erro na sessão: " << e.what() << std::endl;
    }

}

int main() {
    try {
        boost::asio::io_context io;
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve("127.0.0.1", "12345");
        tcp::socket socket(io);
        boost::asio::connect(socket, endpoints);

        std::cout << "Conectado ao servidor. Digite mensagens:\n";

        // Handshake - Envia certificado do cliente
        std::ifstream cert_file("../client-cert.json");
        nlohmann::json client_cert = nlohmann::json::parse(cert_file);
        std::string client_cert_str = client_cert.dump();

        uint32_t cert_len = client_cert_str.size();
        socket.write_some(boost::asio::buffer(&cert_len, sizeof(uint32_t)));
        socket.write_some(boost::asio::buffer(client_cert_str));

        // Recebe o certificado do servidor

        uint32_t server_cert_len = 0;
        boost::asio::read(socket, boost::asio::buffer(&server_cert_len, sizeof(uint32_t)));
        std::vector<char> server_cert(server_cert_len);
        boost::asio::read(socket, boost::asio::buffer(server_cert));
        nlohmann::json server_cert_json = nlohmann::json::parse(server_cert);

        std::ofstream tmp_server_public_file("../tmp_server_public_key.json");
        tmp_server_public_file << server_cert_json["public_key"].get<std::string>();
        tmp_server_public_file.close();

        std::cout << "Servidor: " << server_cert_json["subject"] << std::endl;

        // Envia key e iv para o servidor
        auto aes_key = Crypto::generate_random_bytes(32);
        auto aes_iv = Crypto::generate_random_bytes(16);

        std::vector<unsigned char> secret_payload;
        secret_payload.insert(secret_payload.end(), aes_key.begin(), aes_key.end());
        secret_payload.insert(secret_payload.end(), aes_iv.begin(), aes_iv.end());

        auto rsa_encrypted = Crypto::rsa_encrypt("../tmp_server_public_key.json", secret_payload);
        uint32_t rsa_len = rsa_encrypted.size();
        socket.write_some(boost::asio::buffer(&rsa_len, sizeof(rsa_len)));
        socket.write_some(boost::asio::buffer(rsa_encrypted));

        std::thread(session, std::ref(socket), aes_key, aes_iv).detach();

        for (std::string msg; std::getline(std::cin, msg);) {

            auto encrypted_message = Crypto::encrypt_aes(msg, aes_key, aes_iv);

            auto hash = Crypto::sha256(msg);
            auto sign = Crypto::rsa_sign("../client_private.pem", msg);

#if CHANGE_SIGNATURE
            int rnd = dist(gen);
            if (rnd % 5 == 0) {
                std::cout << "Alterando assinatura" << std::endl;
                sign = Crypto::generate_random_bytes(sign.size());
            }

            if (rnd % 2 == 0) {
                std::cout << "Alterando hash" << std::endl;
                hash = Crypto::generate_random_bytes(hash.size());
            }

#endif
            std::vector<unsigned char> payload;
            payload.insert(payload.end(), hash.begin(), hash.end());
            payload.insert(payload.end(), sign.begin(), sign.end());

#if PRINT_SIZES
            std::cout << "Hash: " << hash.size() << std::endl;
            std::cout << "Signature: " << sign.size() << std::endl;
            std::cout << "encrypted_message: " << encrypted_message.size() << std::endl;
            std::cout << "Payload: " << payload.size() << std::endl;
#endif

            uint32_t enc_len = encrypted_message.size();
            socket.write_some(boost::asio::buffer(&enc_len, sizeof(enc_len)));
            socket.write_some(boost::asio::buffer(encrypted_message));

            uint32_t payloadLen = payload.size();
            socket.write_some(boost::asio::buffer(&payloadLen, sizeof(payloadLen)));
            socket.write_some(boost::asio::buffer(payload));

        }

    } catch (std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
    }

    return 0;
}
