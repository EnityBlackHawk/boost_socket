#include <Crypto.h>
#include <fstream>
#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <common.h>
#include <nlohmann/json.hpp>

using boost::asio::ip::tcp;

void writeLoop(tcp::socket& socket, const std::vector<unsigned char> aes_key, const std::vector<unsigned char> aes_iv) {
    for (std::string msg; std::getline(std::cin, msg);) {

        auto encrypted_message = Crypto::encrypt_aes(msg, aes_key, aes_iv);
        auto hash = Crypto::sha256(msg);
        auto sign = Crypto::rsa_sign("../server_private.pem", msg);

        std::vector<unsigned char> payload;
        payload.insert(payload.end(), hash.begin(), hash.end());
        payload.insert(payload.end(), sign.begin(), sign.end());

        uint32_t enc_len = encrypted_message.size();
        boost::asio::write(socket, boost::asio::buffer(&enc_len, sizeof(enc_len)));
        boost::asio::write(socket, boost::asio::buffer(encrypted_message));

        uint32_t payloadLen = payload.size();
        boost::asio::write(socket, boost::asio::buffer(&payloadLen, sizeof(payloadLen)));
        boost::asio::write(socket, boost::asio::buffer(payload));

    }
}

void session(tcp::socket& socket) {
    try {
        // Recebe handshake - certificado do cliente
        uint32_t cert_len = 0;
        boost::asio::read(socket, boost::asio::buffer(&cert_len, sizeof(uint32_t)));

        std::vector<char> data(cert_len);
        boost::asio::read(socket, boost::asio::buffer(data));
        nlohmann::json client_cert = nlohmann::json::parse(data);

        if (Crypto::verify_certificate_signature(client_cert, "../ca_public.pem")) {
            std::cout << "󰄳 Certificado do cliente verificado com sucesso." << std::endl;
        } else {
            std::cerr << "❎ Falha na verificação do certificado do cliente." << std::endl;
        }

        std::ofstream tmp_cliente_public_file("../tmp_client_public_key.json");
        tmp_cliente_public_file << client_cert["public_key"].get<std::string>();
        tmp_cliente_public_file.close();

        std::cout << "Client: " << client_cert["subject"] << std::endl;

        // Envia handshake - certificado do servidor
        std::ifstream cert_file("../server-cert.json");
        nlohmann::json server_cert = nlohmann::json::parse(cert_file);

        server_cert = Crypto::sign_certificate(server_cert, "../ca_private.pem");

        std::string server_cert_str = server_cert.dump();
        uint32_t server_cert_len = server_cert_str.size();
        boost::asio::write(socket, boost::asio::buffer(&server_cert_len, sizeof(uint32_t)));
        boost::asio::write(socket, boost::asio::buffer(server_cert_str));

        // Recebe chave AES e IV
        uint32_t en_secret_payload_len = 0;
        boost::asio::read(socket, boost::asio::buffer(&en_secret_payload_len, sizeof(uint32_t)));
        std::vector<unsigned char> secret_payload(en_secret_payload_len);
        boost::asio::read(socket, boost::asio::buffer(secret_payload));

        const std::vector<unsigned char> decrypted_secret_payload = Crypto::rsa_decrypt("../server_private.pem", secret_payload);

        const std::vector<unsigned char> aes_key(decrypted_secret_payload.begin(), decrypted_secret_payload.begin() + 32);
        const std::vector<unsigned char> aes_iv(decrypted_secret_payload.begin() + 32, decrypted_secret_payload.end());

        std::cout << "Chave e iv recebidas" << std::endl;

        std::thread(writeLoop, std::ref(socket), aes_key, aes_iv).detach();

        for (;;) {

            uint32_t msg_len = 0;
            boost::asio::read(socket, boost::asio::buffer(&msg_len, sizeof(msg_len)));
            std::vector<unsigned char> encrypted_msg(msg_len);
            boost::asio::read(socket, boost::asio::buffer(encrypted_msg));

            uint32_t payloadLen = 0;
            boost::asio::read(socket, boost::asio::buffer(&payloadLen, sizeof(payloadLen)));
            std::vector<unsigned char> payload(payloadLen);
            boost::asio::read(socket, boost::asio::buffer(payload));

            std::string message = Crypto::decrypt_aes(encrypted_msg, aes_key, aes_iv);

            const std::vector<unsigned char> original_hash(payload.begin(), payload.begin() + 32);
            const std::vector<unsigned char> original_sign(payload.begin() + 32, payload.end());

            auto computed_hash = Crypto::sha256(message);
            const auto computed_sign = Crypto::rsa_verify("../tmp_client_public_key.json", message, original_sign);

            std::cout << message;
            if (computed_hash == original_hash) {
                std::cout << "  ";
            } else {
                std::cout << " ❌ Hash invalido";
            }

            if (computed_sign) {
                std::cout << " " << std::endl;
            } else {
                std::cout << " 󰌿 Assinatura invalida" << std::endl;
            }

        }
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
}

int main() {

    try {
        boost::asio::io_context io;
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 12345));

        std::cout << "Server started, waiting for connections..." << std::endl;

        tcp::socket sock(io);
        acceptor.accept(sock);
        std::thread tr(session, std::ref(sock));

        tr.join();

    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

}