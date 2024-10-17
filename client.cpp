#include <iostream>
#include <string>
#include <thread>
#include <sstream>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>  // JSON parsing library

using namespace boost::asio;
using namespace std;
using json = nlohmann::json;

io_context io_context_;
unsigned int counter = 0;

std::string get_active_private_ip() {
    ip::udp::socket socket_(io_context_, ip::udp::v4());
    ip::udp::endpoint remote_endpoint = ip::udp::endpoint(ip::address::from_string("8.8.8.8"), 53);
    socket_.connect(remote_endpoint);
    ip::address addr = socket_.local_endpoint().address();
    return addr.to_string();
}

std::string base64_encode(const unsigned char* input, int length) {
    BIO *bmem = NULL, *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    std::string output(bptr->data, bptr->length);
    BIO_free_all(b64);

    return output;
}

RSA* generate_rsa_keypair() {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    BN_free(e);
    return rsa;
}

std::string get_public_key_pem(RSA* rsa_keypair) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rsa_keypair);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string public_key_pem(buffer_ptr->data, buffer_ptr->length);

    BIO_free(bio);
    return public_key_pem;
}

std::string sign_message(const json &data, unsigned int counter, RSA* private_key) {
    std::string message_to_sign = data.dump() + std::to_string(counter);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message_to_sign.c_str()), message_to_sign.size(), hash);

    unsigned char* signature = new unsigned char[RSA_size(private_key)];
    unsigned int signature_len;

    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signature_len, private_key);

    std::string signature_base64 = base64_encode(signature, signature_len);
    delete[] signature;

    return signature_base64;
}

void receive_messages(ip::tcp::socket &client_socket) {
    char message[1024];
    while (true) {
        try {
            size_t length = client_socket.read_some(boost::asio::buffer(message));
            std::string received_message(message, length);

            std::cout << "[RAW MESSAGE RECEIVED] " << received_message << "\n";

            json message_data = json::parse(received_message);
            if (message_data.contains("original_sender")) {
                std::string original_sender = message_data["original_sender"];
                std::string received_message = message_data["data"]["message"];
                std::cout << "[FORWARDED MESSAGE FROM " << original_sender << "] " << received_message << "\n";
            } else {
                std::cout << "[MESSAGE RECEIVED] " << message_data.dump() << "\n";
            }

        } catch (std::exception &e) {
            std::cerr << "[ERROR] Connection lost: " << e.what() << "\n";
            client_socket.close();
            break;
        }
    }
}

void send_hello_message(ip::tcp::socket &client_socket, const std::string &public_key_pem) {
    json hello_message = {
        {"data", {
            {"type", "hello"},
            {"public_key", public_key_pem}
        }}
    };

    try {
        client_socket.write_some(boost::asio::buffer(hello_message.dump()));
        std::cout << "[HELLO] Hello message sent\n";
    } catch (std::exception &e) {
        std::cerr << "[ERROR] Could not send hello message: " << e.what() << "\n";
    }
}

void send_messages(ip::tcp::socket &client_socket, RSA* private_key) {
    std::string destination_ip;
    std::string message;

    while (true) {
        std::cout << "Enter destination IP or 'exit' to quit: ";
        std::getline(std::cin, destination_ip);

        if (destination_ip == "exit") {
            std::cout << "[DISCONNECTING] Disconnecting from the server...\n";
            client_socket.shutdown(ip::tcp::socket::shutdown_both);
            client_socket.close();
            break;
        }

        std::cout << "Enter your message: ";
        std::getline(std::cin, message);

        counter += 1;

        json data = {
            {"type", "signed_data"},
            {"data", {
                {"message", message},
                {"destination_ip", destination_ip}
            }},
            {"counter", counter},
            {"signature", sign_message({{"message", message}, {"destination_ip", destination_ip}}, counter, private_key)}
        };

        try {
            client_socket.write_some(boost::asio::buffer(data.dump()));
            std::cout << "[MESSAGE SENT] Message sent to server.\n";
        } catch (std::exception &e) {
            std::cerr << "[ERROR] Could not send message: " << e.what() << "\n";
        }
    }
}

int main() {
    std::string server_ip;
    unsigned short server_port;

    std::cout << "Enter server IP to connect to: ";
    std::getline(std::cin, server_ip);

    std::cout << "Enter server port: ";
    std::cin >> server_port;

    ip::tcp::socket client_socket(io_context_);

    try {
        client_socket.connect(ip::tcp::endpoint(ip::address::from_string(server_ip), server_port));
        std::cout << "[CONNECTED] Connected to server at " << server_ip << ":" << server_port << "\n";

        RSA* private_key = generate_rsa_keypair();
        std::string public_key_pem = get_public_key_pem(private_key);

        send_hello_message(client_socket, public_key_pem);

        std::thread receive_thread(receive_messages, std::ref(client_socket));
        receive_thread.detach();

        send_messages(client_socket, private_key);

    } catch (std::exception &e) {
        std::cerr << "[ERROR] Could not connect to server: " << e.what() << "\n";
        client_socket.close();
    }

    return 0;
}