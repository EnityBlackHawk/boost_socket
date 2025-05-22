#include <Crypto.h>
#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <common.h>

using boost::asio::ip::tcp;

void session(tcp::socket& socket) {
    try {
        for (;;) {
            char data[1024];
            boost::system::error_code error;

            size_t lenght = socket.read_some(boost::asio::buffer(data), error);

            if (error == boost::asio::error::eof) {
                std::cout << "Client disconnected" << std::endl;
                break;
            }
            if (error) {
                throw boost::system::system_error(error);
            }
            std::string msg(data, lenght);
            std::string decrypted = Crypto::decrypt_aes(msg, AES_KEY);
            std::string hash_received = decrypted.substr(0, 32);
            std::string message = decrypted.substr(32);

            std::string hash_calculated = Crypto::sha256(message);
            std::cout << message << std::endl;

            if (hash_calculated == hash_received) {
                std::cout << " -  Integridade verificada" << std::endl;
            } else {
                std::cout << " - Integridade comprometida" << std::endl;
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

        for (std::string msg; std::getline(std::cin, msg);) {
            std::string hash = Crypto::sha256(msg);
            std::string full = hash + msg;
            std::string encrypted = Crypto::encrypt_aes(full, AES_KEY);
            boost::asio::write(sock, boost::asio::buffer(encrypted));

        }

        tr.join();

    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

}