#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <sstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <boost/asio.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>  // JSON parsing library

using namespace boost::asio;
using namespace std;
using json = nlohmann::json;

// Global variables
std::vector<std::tuple<ip::tcp::socket *, std::string, ip::tcp::endpoint>> clients;
std::vector<std::tuple<std::string, unsigned short>> server_to_connect;
std::vector<ip::tcp::socket *> connected_servers;

std::string server_ip;
unsigned short server_port = 34568;

io_context io_context_;

std::string get_active_private_ip() {
    ip::udp::socket socket_(io_context_, ip::udp::v4());
    ip::udp::endpoint remote_endpoint = ip::udp::endpoint(ip::address::from_string("8.8.8.8"), 53);
    socket_.connect(remote_endpoint);
    ip::address addr = socket_.local_endpoint().address();
    return addr.to_string();
}

std::string get_client_public_key(ip::tcp::socket *client_socket) {
    for (auto &client : clients) {
        if (std::get<0>(client) == client_socket) {
            return std::get<1>(client);
        }
    }
    return "";
}

void forward_message_to_other_servers(const std::string &message_data, const ip::tcp::endpoint &client_address) {
    for (auto *server_socket : connected_servers) {
        try {
            std::stringstream ss;
            ss << message_data;
            boost::asio::write(*server_socket, boost::asio::buffer(ss.str()));
            std::cout << "[FORWARDED] Message forwarded to other server.\n";
        } catch (const std::exception &e) {
            std::cerr << "[ERROR] Could not forward message: " << e.what() << "\n";
        }
    }
}

bool verify_signature(const json &message_data, const std::string &signature_base64, ip::tcp::socket *client_socket) {
    std::string public_key_pem = get_client_public_key(client_socket);
    if (public_key_pem.empty()) {
        std::cerr << "[ERROR] Public key not found for the client.\n";
        return false;
    }

    // Load public key for signature verification
    BIO *bio = BIO_new_mem_buf(public_key_pem.c_str(), -1);
    RSA *rsa_public_key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    if (!rsa_public_key) {
        std::cerr << "[ERROR] Failed to load public key: " << ERR_error_string(ERR_get_error(), NULL) << "\n";
        BIO_free(bio);
        return false;
    }

    // Hash the message data to verify the signature
    std::string message_to_verify = message_data.dump();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(message_to_verify.c_str()), message_to_verify.size(), hash);

    // Decode the signature from base64
    std::vector<unsigned char> signature;
    signature.resize(RSA_size(rsa_public_key));
    size_t signature_len = EVP_DecodeBlock(signature.data(), reinterpret_cast<const unsigned char *>(signature_base64.c_str()), signature_base64.size());

    // Verify the signature
    int verification_result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), signature_len, rsa_public_key);

    RSA_free(rsa_public_key);
    BIO_free(bio);

    return verification_result == 1;
}

void handle_client(ip::tcp::socket *client_socket, ip::tcp::endpoint client_address) {
    std::string public_key;

    try {
        for (;;) {
            char message[1024] = {0};
            size_t length = client_socket->read_some(boost::asio::buffer(message));

            if (length == 0) {
                std::cout << "[DISCONNECTED] Client disconnected.\n";
                break;
            }

            std::string received_message(message, length);
            std::cout << "[MESSAGE] Received: " << received_message << "\n";

            // Parse message using JSON
            json parsed_message = json::parse(received_message);

            if (parsed_message["type"] == "hello") {
                public_key = parsed_message["data"]["public_key"].get<std::string>();
                clients.push_back(make_tuple(client_socket, public_key, client_address));
                std::cout << "[HELLO] Stored public key from client.\n";
            } else if (parsed_message["type"] == "signed_data") {
                std::string signature = parsed_message["signature"].get<std::string>();
                if (verify_signature(parsed_message["data"], signature, client_socket)) {
                    // Handle forwarding logic or execute command
                    std::cout << "[VERIFIED] Message signature is valid.\n";
                } else {
                    std::cerr << "[ERROR] Invalid signature.\n";
                }
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] Client connection error: " << e.what() << "\n";
    }

    // Close the client socket once disconnected
    client_socket->close();
}

void start_server(const std::string &host, unsigned short port) {
    ip::tcp::acceptor acceptor_(io_context_, ip::tcp::endpoint(ip::tcp::v4(), port));
    std::cout << "[LISTENING] Server is listening on " << host << ":" << port << "\n";

    for (;;) {
        ip::tcp::socket *client_socket = new ip::tcp::socket(io_context_);
        acceptor_.accept(*client_socket);
        ip::tcp::endpoint client_endpoint = client_socket->remote_endpoint();
        std::cout << "[NEW CONNECTION] Client connected from: " << client_endpoint << "\n";

        std::thread(handle_client, client_socket, client_endpoint).detach();
    }
}

void listen_for_broadcasts() {
    ip::udp::socket socket_(io_context_, ip::udp::endpoint(ip::udp::v4(), 12345));
    char buffer[1024];
    for (;;) {
        ip::udp::endpoint client_endpoint;
        size_t length = socket_.receive_from(boost::asio::buffer(buffer), client_endpoint);
        std::string received_message(buffer, length);

        // Parse the received message, check if it is "server_hello", and respond with "server_response"
        json message = json::parse(received_message);
        if (message["data"]["type"] == "server_hello") {
            std::cout << "[RECEIVED] Broadcast from " << client_endpoint << ": " << received_message << "\n";

            // Respond with "server_response"
            json response_message = {
                {"data", {{"type", "server_response"}, {"sender", server_ip}, {"port", server_port}}}
            };

            std::string response_str = response_message.dump();
            socket_.send_to(boost::asio::buffer(response_str), client_endpoint);
            std::cout << "[RESPONSE] Sent server_response to " << client_endpoint << "\n";
        }
    }
}

void broadcast_discovery_message() {
    ip::udp::socket socket_(io_context_, ip::udp::v4());
    socket_.set_option(ip::udp::socket::reuse_address(true));
    socket_.set_option(boost::asio::socket_base::broadcast(true));

    std::string private_ip = get_active_private_ip();
    if (private_ip.empty()) {
        std::cerr << "Unable to send broadcast message: could not determine private IP.\n";
        return;
    }

    json message = {
        {"data", {{"type", "server_hello"}, {"sender", private_ip}}}
    };

    std::string message_str = message.dump();
    ip::udp::endpoint broadcast_endpoint(ip::address_v4::broadcast(), 12345);
    socket_.send_to(boost::asio::buffer(message_str), broadcast_endpoint);

    std::cout << "Broadcast message sent from " << private_ip << " on port 12345.\n";
}

void connect_to_other_servers() {
    for (auto &server : server_to_connect) {
        std::string ip = std::get<0>(server);
        unsigned short port = std::get<1>(server);
        while (true) {
            try {
                ip::tcp::socket *server_socket = new ip::tcp::socket(io_context_);
                server_socket->connect(ip::tcp::endpoint(ip::address::from_string(ip), port));
                connected_servers.push_back(server_socket);
                std::cout << "[CONNECTED TO SERVER] Connected to " << ip << ":" << port << "\n";
                break;
            } catch (const std::exception &e) {
                std::cerr << "[ERROR] Could not connect to server " << ip << ":" << port << ": " << e.what() << "\n";
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }
}

int main() {
    server_ip = get_active_private_ip();
    if (server_ip.empty()) {
        std::cerr << "Failed to get active private IP address.\n";
        return 1;
    }

    std::cout << "Using server IP: " << server_ip << "\n";

    std::thread server_thread(start_server, "0.0.0.0", server_port);
    std::thread broadcast_thread(listen_for_broadcasts);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    broadcast_discovery_message();
    connect_to_other_servers();

    server_thread.join();
    broadcast_thread.join();

    return 0;
}
