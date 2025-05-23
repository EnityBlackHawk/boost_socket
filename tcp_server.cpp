#include <Crypto.h>
#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <common.h>

using boost::asio::ip::tcp;

void session(tcp::socket& socket) {
    try {
        for (;;) {

            uint32_t rsa_len = 0;
            boost::asio::read(socket, boost::asio::buffer(&rsa_len, sizeof(rsa_len)));

            std::vector<unsigned char> rsa_payload(rsa_len);
            boost::asio::read(socket, boost::asio::buffer(rsa_payload));

            auto decrypted = Crypto::rsa_decrypt("../server_private.pem", rsa_payload);
            if (decrypted.size() != (32 + 16 + 32)) {
                throw std::runtime_error("RSA encryption failed");
            }

            std::vector<unsigned char> aes_key(decrypted.begin(), decrypted.begin() + 32);
            std::vector<unsigned char> aes_iv(decrypted.begin() + 32, decrypted.begin() + 48);
            std::vector<unsigned char> original_hash(decrypted.begin() + 48, decrypted.end());

            uint32_t msg_len = 0;
            boost::asio::read(socket, boost::asio::buffer(&msg_len, sizeof(msg_len)));
            std::vector<unsigned char> encrypted_msg(msg_len);
            boost::asio::read(socket, boost::asio::buffer(encrypted_msg));

            uint32_t sign_len = 0;
            boost::asio::read(socket, boost::asio::buffer(&sign_len, sizeof(sign_len)));
            std::vector<unsigned char> original_sign(sign_len);
            boost::asio::read(socket, boost::asio::buffer(original_sign));

            std::string message = Crypto::decrypt_aes(encrypted_msg, aes_key, aes_iv);
            auto computed_hash = Crypto::sha256(message);
            const auto computed_sign = Crypto::rsa_verify("../client_public.pem", message, original_sign);

            std::cout << message;
            if (computed_hash == original_hash) {
                std::cout << "  ";
            } else {
                std::cout << " ❌";
            }

            if (computed_sign) {
                std::cout << " " << std::endl;
            } else {
                std::cout << " 󰌿 Assinatura invalida" << std::endl;
            }


            // char data[1024];
            // boost::system::error_code error;
            //
            // size_t lenght = socket.read_some(boost::asio::buffer(data), error);
            //
            // if (error == boost::asio::error::eof) {
            //     std::cout << "Client disconnected" << std::endl;
            //     break;
            // }
            // if (error) {
            //     throw boost::system::system_error(error);
            // }

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

        // for (std::string msg; std::getline(std::cin, msg);) {
        //     std::string hash = Crypto::sha256(msg);
        //     std::string full = hash + msg;
        //     std::string encrypted = Crypto::encrypt_aes(full, AES_KEY);
        //     boost::asio::write(sock, boost::asio::buffer(encrypted));
        //
        // }

        tr.join();

    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

}