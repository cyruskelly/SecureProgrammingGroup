#include "server.h"
#include <iostream>

Server *global_server = nullptr;

int Server::callback_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    Server *server_instance = global_server; // Use server instance for non-static calls
    char *received_message = (char *)in;
    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';
            printf("Message received from another server: %s\n", received_message);
            // Validate signature and counter
            if (server_instance->validate_signature(received_message)) {
                server_instance->relay_message_to_servers(received_message); // Securely forward message
            } else {
                printf("Invalid message: Signature or counter check failed\n");
            }
            break;

        case LWS_CALLBACK_ESTABLISHED:
            printf("Connected to another server\n");
            break;

        case LWS_CALLBACK_CLOSED:
            printf("Disconnected from another server\n");
            break;

        default:
            break;
    }
    return 0;
}

int Server::callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    Server *server_instance = global_server;
    char *received_message = (char *)in;
    rapidjson::Document *d;
    std::string rq_type;

    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';
            printf("Message received: %s\n", received_message);
            d = parse_json(received_message);
            rq_type = (*d)["data"]["type"].GetString();

            if (rq_type == "hello") {
                server_instance->add_client(received_message);
                server_instance->send_client_update_to_servers();  // Send client updates after new connections

            } else if (rq_type == "client_update") {
                server_instance->send_client_update_to_servers();  // Use the updated method
            }
            break;

        case LWS_CALLBACK_ESTABLISHED:
            printf("Client connected\n");
            break;

        case LWS_CALLBACK_CLOSED:
            printf("Client disconnected\n");
            server_instance->send_client_update_to_servers();  // Handle disconnection and notify other servers
            break;

        default:
            break;
    }
    return 0;
}

rapidjson::Document * Server::parse_json(const char *json) {
    rapidjson::Document * d = new rapidjson::Document();
    d->Parse(json);
    return d;
}

void Server::connect_to_other_servers(struct lws_context *context) {
    std::vector<std::string> servers = list_servers();  // List of known servers
    for (const auto &server : servers) {
        struct lws_client_connect_info ccinfo = {0};
        ccinfo.context = context;
        ccinfo.address = server.c_str();  // Server address from the list
        ccinfo.port = 8080;               // Ensure matching port
        ccinfo.path = "/";
        ccinfo.protocol = "server-protocol";
        ccinfo.host = lws_canonical_hostname(context);
        ccinfo.origin = "origin";
        ccinfo.ietf_version_or_minus_one = -1;

        struct lws *wsi = lws_client_connect_via_info(&ccinfo);
        printf("Connected to server: %s\n", server.c_str());
    }
}

void Server::send_client_update_to_servers() {
    // Read clients from the file
    std::unordered_map<std::string, std::string> clients = read_clients();
    
    // Format the list of clients as JSON
    std::string client_update = "{ \"type\": \"client_update\", \"clients\": [";
    
    bool first = true; // To handle the comma correctly
    for (const auto& client : clients) {
        if (!first) {
            client_update += ", ";
        }
        client_update += "\"" + client.second + "\""; // client.second is the public key
        first = false;
    }
    
    client_update += "] }";

    // Send the list of clients to all other servers
    relay_message_to_servers(client_update);
}


std::unordered_map<std::string, std::string> Server::read_clients() {
    std::ifstream file("/data/clients.txt");
    std::string line;
    std::unordered_map<std::string, std::string> clients;

    while (std::getline(file, line)) {
        if (!line.empty()) {
            // Assuming each line is formatted as "fingerprint:public_key"
            size_t separator = line.find(':');
            if (separator != std::string::npos) {
                std::string fingerprint = line.substr(0, separator);
                std::string public_key = line.substr(separator + 1);
                clients[fingerprint] = public_key;
            }
        }
    }
    return clients;
}

void Server::relay_message_to_servers(const std::string &message) {
    // Loop through connected servers and send the message
    for (const auto &server : connected_servers) {
        unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 1024 + LWS_SEND_BUFFER_POST_PADDING];
        memset(buf, 0, sizeof(buf));
        size_t n = message.size();
        memcpy(buf + LWS_SEND_BUFFER_PRE_PADDING, message.c_str(), n);
        lws_write(server, buf + LWS_SEND_BUFFER_PRE_PADDING, n, LWS_WRITE_TEXT);
    }
}

int Server::server_main(void) {
    int port;
    std::cout << "Enter port number: ";
    std::cin >> port;

 static struct lws_protocols protocols[] = {
        {"http", lws_callback_http_dummy, 0, 0},
        {"chat-protocol", Server::callback_chat, 0, 1024},
        {"server-protocol", Server::callback_server, 0, 1024},  // Server protocol
        {NULL, NULL, 0, 0} /* terminator */
    };

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = port;
    info.protocols = protocols;
    
    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        printf("Failed to create WebSocket context\n");
        return 1;
    }
    
    connect_to_other_servers(context);
    printf("Server started on port %i\n", port);
    
    while (1) {
        lws_service(context, 1000);
    }

    lws_context_destroy(context);
    return 0;
}

std::vector<std::string> Server::list_servers() {
    FILE *file = fopen("/data/servers.txt", "r");
    if (!file) {
        printf("Error: Could not open servers.txt\n");
        return {}; // Return an empty vector
    }
    
    char line[1024];
    std::vector<std::string> servers;
    while (fgets(line, sizeof(line), file)) {
        // Remove trailing newlines and whitespaces 
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        servers.push_back(line);
    }
    fclose(file);
    return servers;
}



int Server::add_client(std::string client) {
    FILE *file = fopen("/data/clients.txt", "a");
    if (!file) {
        printf("Error: Could not open clients.txt\n");
        return 1; // Return an error code
    }
    
    fprintf(file, "{\n%s\n},\n", client.c_str());
    fclose(file);
    return 0; // Return 0 to indicate success
}


bool Server::validate_signature(const char *message) {
    rapidjson::Document *d = parse_json(message);
    std::string signature_base64 = (*d)["signature"].GetString();
    std::string data = (*d)["data"].GetString();
    std::string sender_fingerprint = (*d)["sender_fingerprint"].GetString();

    // Get the map of clients (fingerprints -> public keys)
    std::unordered_map<std::string, std::string> clients = read_clients();

    // Find the sender's public key using their fingerprint
    if (clients.find(sender_fingerprint) == clients.end()) {
        printf("Error: Could not find sender's public key\n");
        return false;
    }

    std::string public_key_pem = clients[sender_fingerprint];

    // Decode the Base64 signature
    unsigned char signature[256]; // RSA 2048-bit signature size
    int signature_len = EVP_DecodeBlock(signature, (const unsigned char*)signature_base64.c_str(), signature_base64.length());

    if (signature_len <= 0) {
        printf("Error: Failed to decode signature\n");
        return false;
    }

    // Hash the data (data only, no counter involved)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.length(), hash);

    // Convert the PEM public key string to EVP_PKEY
    BIO* bio = BIO_new_mem_buf(public_key_pem.c_str(), -1);
    EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!public_key) {
        printf("Error: Could not load public key\n");
        return false;
    }

    // Verify the RSA-PSS signature using the sender's public key
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pkey_ctx;
    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, EVP_sha256(), NULL, public_key) <= 0) {
        printf("Error: Failed to initialize signature verification\n");
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, 32) <= 0) {
        printf("Error: Failed to configure PSS padding\n");
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestVerify(ctx, signature, signature_len, hash, SHA256_DIGEST_LENGTH) == 1) {
        printf("Signature valid!\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return true;
    } else {
        printf("Signature invalid!\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return false;
    }
}

/*
bool Server::check_counter(const char *message) {
    // Code to verify if the message counter is greater than the last received counter
    // Returns true if valid, false otherwise
}
*/

int main() {
    printf("Working");
    Server server;
    server.server_main();
    return 0;
}