#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <thread>
#include <sstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

using namespace boost::asio;
using namespace std;
using json = nlohmann::json;

// Global variables
std::unordered_map<int, std::string> clients_public_keys;
std::unordered_set<std::string> client_fingerprints;
std::vector<std::tuple<std::string, unsigned short>> server_to_connect;
std::vector<ip::tcp::socket *> connected_servers;

std::string server_ip;
unsigned short server_port = 0;  // Dynamic port assignment

io_context io_context_;

void listen_for_broadcasts(unsigned short &udp_port) {
    ip::udp::socket socket_(io_context_, ip::udp::endpoint(ip::udp::v4(), udp_port));
    udp_port = socket_.local_endpoint().port();

    std::cout << "[LISTENING] UDP broadcast listening on port: " << udp_port << "\n";

    char buffer[1024];
    for (;;) {
        ip::udp::endpoint client_endpoint;
        size_t length = socket_.receive_from(boost::asio::buffer(buffer), client_endpoint);
        std::string received_message(buffer, length);

        // Parse the received message
        json message = json::parse(received_message);
        if (message["data"]["type"] == "server_hello") {
            std::string sender_ip = message["data"]["sender"];

            std::cout << "[RECEIVED] Broadcast from " << client_endpoint << ": " << received_message << "\n";

            // Avoid self-connection
            if (sender_ip != server_ip) {
                // Store the server to connect to (IP and port)
                unsigned short sender_port = message["data"]["port"];
                server_to_connect.push_back({sender_ip, sender_port});
                std::cout << "[INFO] Adding server to connect list: " << sender_ip << ":" << sender_port << "\n";
            }

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

std::string get_active_private_ip() {
    ip::udp::socket socket_(io_context_, ip::udp::v4());
    ip::udp::endpoint remote_endpoint = ip::udp::endpoint(ip::address::from_string("8.8.8.8"), 53);
    socket_.connect(remote_endpoint);
    ip::address addr = socket_.local_endpoint().address();
    return addr.to_string();
}

void broadcast_discovery_message(unsigned short udp_port) {
    ip::udp::socket socket_(io_context_, ip::udp::v4());
    socket_.set_option(ip::udp::socket::reuse_address(true));
    socket_.set_option(boost::asio::socket_base::broadcast(true));

    std::string private_ip = get_active_private_ip();
    if (private_ip.empty()) {
        std::cerr << "Unable to send broadcast message: could not determine private IP.\n";
        return;
    }

    json message = {
        {"data", {{"type", "server_hello"}, {"sender", private_ip}, {"port", server_port}}}
    };

    std::string message_str = message.dump();
    ip::udp::endpoint broadcast_endpoint(ip::address_v4::broadcast(), udp_port);
    socket_.send_to(boost::asio::buffer(message_str), broadcast_endpoint);

    std::cout << "Broadcast message sent from " << private_ip << " on port " << udp_port << ".\n";
}


void connect_to_other_servers() {
    for (auto &server : server_to_connect) {
        std::string ip = std::get<0>(server);
        unsigned short port = std::get<1>(server);

        if (ip == server_ip) {
            std::cout << "[INFO] Skipping self-connection for server: " << ip << ":" << port << "\n";
            continue;  // Skip connecting to itself
        }

        std::cout << "[INFO] Attempting to connect to server " << ip << ":" << port << "\n";

        int retry_count = 5;
        while (retry_count > 0) {
            try {
                ip::tcp::socket *server_socket = new ip::tcp::socket(io_context_);
                server_socket->connect(ip::tcp::endpoint(ip::address::from_string(ip), port));
                connected_servers.push_back(server_socket);
                std::cout << "[CONNECTED TO SERVER] Connected to " << ip << ":" << port << "\n";
                break;
            } catch (const std::exception &e) {
                std::cerr << "[ERROR] Could not connect to server " << ip << ":" << port << ": " << e.what() << "\n";
                std::this_thread::sleep_for(std::chrono::seconds(5));
                retry_count--;
            }
        }
        if (retry_count == 0) {
            std::cerr << "[ERROR] Could not connect to server " << ip << ":" << port << " after retries\n";
        }
    }
}

std::string get_client_public_key(ip::tcp::socket *client_socket) {
    int socket_handle = client_socket->native_handle();
    auto it = clients_public_keys.find(socket_handle);
    if (it != clients_public_keys.end()) {
        return it->second;
    }
    return "";
}

std::string calculate_fingerprint(const std::string& public_key_pem) {
    // Remove extra whitespace and perform hashing
    stringstream ss;
    ss << public_key_pem;
    std::string cleaned_public_key = ss.str();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(cleaned_public_key.c_str()), cleaned_public_key.size(), hash);
    
    // Base64 encode the fingerprint
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, hash, SHA256_DIGEST_LENGTH);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string fingerprint(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return fingerprint;
}

void broadcast_client_update() {
    // Broadcast a message that updates the client list across all servers
    json client_update = {
        {"type", "client_update"},
        {"clients", json::array()}
    };

    for (const auto& fp : client_fingerprints) {
        client_update["clients"].push_back(fp);
    }

    // Send the update to all connected servers
    for (auto *server_socket : connected_servers) {
        try {
            std::stringstream ss;
            ss << client_update.dump();
            boost::asio::write(*server_socket, boost::asio::buffer(ss.str()));
            std::cout << "[UPDATE SENT] Client update broadcasted.\n";
        } catch (const std::exception &e) {
            std::cerr << "[ERROR] Could not send client update: " << e.what() << "\n";
        }
    }
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
    std::vector<unsigned char> signature(RSA_size(rsa_public_key));
    int signature_len = EVP_DecodeBlock(signature.data(), reinterpret_cast<const unsigned char *>(signature_base64.c_str()), signature_base64.length());

    // Verify the signature
    int verification_result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), signature_len, rsa_public_key);

    RSA_free(rsa_public_key);
    BIO_free(bio);

    return verification_result == 1;
}

void handle_client(ip::tcp::socket *client_socket, ip::tcp::endpoint client_address) {
    try {
        for (;;) {
            char message[1024] = {0};
            size_t length = client_socket->read_some(boost::asio::buffer(message));

            if (length == 0) {
                std::cout << "[DISCONNECTED] Client disconnected.\n";
                break;
            }

            std::string received_message(message, length);
            json parsed_message = json::parse(received_message);

            if (parsed_message["type"] == "hello") {
                std::string public_key = parsed_message["data"]["public_key"].get<std::string>();
                int socket_handle = client_socket->native_handle();
                clients_public_keys[socket_handle] = public_key;

                // Generate and store fingerprint
                std::string fingerprint = calculate_fingerprint(public_key);
                client_fingerprints.insert(fingerprint);

                std::cout << "[HELLO] Stored public key and fingerprint: " << fingerprint << "\n";

                // Broadcast client update
                broadcast_client_update();

            } else if (parsed_message["type"] == "signed_data") {
                // Handle signed data verification and message forwarding
                std::string signature = parsed_message["signature"].get<std::string>();
                std::string destination_ip = parsed_message["data"]["destination_ip"].get<std::string>();
                std::string message_content = parsed_message["data"]["message"].get<std::string>();

                if (verify_signature(parsed_message["data"], signature, client_socket)) {
                    std::cout << "[VERIFIED] Message signature is valid. Forwarding...\n";
                    forward_message_to_other_servers(received_message, client_address);
                } else {
                    std::cerr << "[ERROR] Invalid signature.\n";
                }
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] Client Disconnected: " << e.what() << "\n";
    }

    // Client disconnected, remove public key and fingerprint
    int socket_handle = client_socket->native_handle();
    std::string client_public_key = clients_public_keys[socket_handle];
    std::string fingerprint = calculate_fingerprint(client_public_key);
    client_fingerprints.erase(fingerprint);

    // Broadcast client update
    broadcast_client_update();

    client_socket->close();
}

void start_server(const std::string &host, unsigned short &port) {
    ip::tcp::acceptor acceptor_(io_context_, ip::tcp::endpoint(ip::tcp::v4(), port));
    port = acceptor_.local_endpoint().port();
    std::cout << "[LISTENING] Server is listening on " << host << ":" << port << "\n";

    for (;;) {
        ip::tcp::socket *client_socket = new ip::tcp::socket(io_context_);
        acceptor_.accept(*client_socket);
        ip::tcp::endpoint client_endpoint = client_socket->remote_endpoint();
        std::cout << "[NEW CONNECTION] Client connected from: " << client_endpoint << "\n";

        std::thread(handle_client, client_socket, client_endpoint).detach();
    }
}


int main() {
    server_ip = get_active_private_ip();
    if (server_ip.empty()) {
        std::cerr << "Failed to get active private IP address.\n";
        return 1;
    }

    unsigned short udp_port = 0;
    std::cout << "Using server IP: " << server_ip << "\n";

    std::thread server_thread(start_server, "0.0.0.0", std::ref(server_port));
    std::thread broadcast_thread(listen_for_broadcasts, std::ref(udp_port));

    std::this_thread::sleep_for(std::chrono::seconds(1));
    broadcast_discovery_message(udp_port);
    connect_to_other_servers();

    server_thread.join();
    broadcast_thread.join();

    return 0;
}
