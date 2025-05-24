#include <common.h>
#include <Crypto.h>
#include <fstream>
#include <iostream>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

using boost::asio::ip::tcp;

// void session(tcp::socket& socket) {
//     try {
//         for (;;) {
//             char data[1024];
//             boost::system::error_code error;
//
//             size_t lenght = socket.read_some(boost::asio::buffer(data), error);
//
//             if (error == boost::asio::error::eof) {
//                 std::cout << "Client disconnected" << std::endl;
//                 break;
//             }
//             if (error) {
//                 throw boost::system::system_error(error);
//             }
//             std::string msg(data, lenght);
//             std::string decrypted = Crypto::decrypt_aes(msg, AES_KEY);
//             std::string hash_received = decrypted.substr(0, 32);
//             std::string message = decrypted.substr(32);
//
//             std::string hash_calculated = Crypto::sha256(message);
//             std::cout << message;
//
//             if (hash_calculated == hash_received) {
//                 std::cout << " -  Integridade verificada" << std::endl;
//             } else {
//                 std::cout << " - Integridade comprometida" << std::endl;
//             }
//
//         }
//     } catch (std::exception &e) {
//         std::cerr << e.what() << std::endl;
//     }
// }

int main() {
    try {
        boost::asio::io_context io;
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve("127.0.0.1", "12345");
        tcp::socket socket(io);
        boost::asio::connect(socket, endpoints);

        std::cout << "Conectado ao servidor. Digite mensagens:\n";

        //std::thread(session, std::ref(socket)).detach();

        // Handshake - Envia certificado do cliente
        std::ifstream cert_file("../client-cert.json");
        nlohmann::json client_cert = nlohmann::json::parse(cert_file);
        std::string client_cert_str = client_cert.dump();
        std::cout << "Certificado do cliente: " << client_cert_str << std::endl;

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


        for (std::string msg; std::getline(std::cin, msg);) {

            auto encrypted_message = Crypto::encrypt_aes(msg, aes_key, aes_iv);

            auto hash = Crypto::sha256(msg);
            auto sign = Crypto::rsa_sign("../client_private.pem", msg);

            std::cout << "Hash: " << hash.size() << std::endl;
            std::cout << "Signature: " << sign.size() << std::endl;

            std::vector<unsigned char> payload;
            payload.insert(payload.end(), hash.begin(), hash.end());
            payload.insert(payload.end(), sign.begin(), sign.end());

            std::cout << "encrypted_message: " << encrypted_message.size() << std::endl;

            uint32_t enc_len = encrypted_message.size();
            socket.write_some(boost::asio::buffer(&enc_len, sizeof(enc_len)));
            socket.write_some(boost::asio::buffer(encrypted_message));

            std::cout << "Payload: " << payload.size() << std::endl;

            uint32_t payloadLen = payload.size();
            socket.write_some(boost::asio::buffer(&payloadLen, sizeof(payloadLen)));
            socket.write_some(boost::asio::buffer(payload));

        }

    } catch (std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
    }

    return 0;
}
