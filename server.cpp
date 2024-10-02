#include "server.h"
#include "fileHandler.h"  // Include FileHandler header for file management
#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>

// Constructor
Server::Server() {
    file_handler = new FileHandler();  // Allocate FileHandler instance
}

// Destructor
Server::~Server() {
    delete file_handler;  // Clean up the FileHandler instance
}
int Server::callback_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    Server *server_instance = static_cast<Server *>(user);
    rapidjson::Document *d;
    std::string rq_type;

    char *received_message = (char *)in;
    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';
            printf("Message received from another server: %s\n", received_message);
            d = parse_json(received_message);
            rq_type = (*d)["type"].GetString();
            printf("Request type: %s\n", rq_type.c_str());

            if (rq_type == "client_update") {
                for (const auto &client : (*d)["clients"].GetArray()) {
                    for (serv &s : server_instance->servers) {  // Use reference to modify the server entry
                        if (s.address == client) {
                            s.clients.push_back(client.GetString());
                        }
                    }
                }
            } else if (rq_type == "client_update_request") {
                server_instance->relay_message_to_servers(received_message);
            } else if (rq_type == "signed_data") {
                if ((*d)["data"]["type"].GetString() == "server_hello") {
                    server_instance->connected_servers.push_back(wsi);
                    server_instance->servers.push_back({(*d)["data"]["sender"].GetString(), {}});
                }
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
    Server *server_instance = static_cast<Server *>(user);

    char *received_message = (char *)in;
    rapidjson::Document *d;
    std::string rq_type;

    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';  // Make sure to null-terminate the message
            printf("Message received: %s\n", received_message);
            d = parse_json(received_message);
            rq_type = (*d)["data"]["type"].GetString();
            printf("Request type: %s\n", rq_type.c_str());

            if (rq_type == "hello") {
                server_instance->add_client((*d)["data"]["public_key"].GetString());
            } else if (rq_type == "client_update") {
                server_instance->send_client_update_to_servers();
            } else if (rq_type == "file_transfer") {
                std::string file_name = (*d)["data"]["file_name"].GetString();
                std::string file_data = (*d)["data"]["file_content"].GetString();

                // Convert the string file data to unsigned char format for storage
                size_t file_size = file_data.length();
                unsigned char *content = new unsigned char[file_size];
                std::memcpy(content, file_data.c_str(), file_size);

                // Store the file using FileHandler and generate a unique URL
                std::string file_url = server_instance->file_handler->store_file(file_name, content, file_size);
                delete[] content;

                // Print the file URL to the server console
                std::cout << "File stored successfully at URL: " << file_url << std::endl;

                // Send the URL back to the client
                std::string response_message = "{ \"type\": \"file_transfer_response\", \"file_url\": \"" + file_url + "\" }";
                server_instance->relay_message_to_servers(response_message);
            }
            break;

        case LWS_CALLBACK_ESTABLISHED:
            printf("Client connected\n");
            break;

        case LWS_CALLBACK_CLOSED:
            printf("Client disconnected\n");
            break;

        default:
            break;
    }
    return 0;
}


rapidjson::Document *Server::parse_json(const char *json) {
    rapidjson::Document *d = new rapidjson::Document();
    d->Parse(json);
    return d;
}

void Server::connect_to_other_servers(struct lws_context *context) {
    std::vector<std::string> servers = list_servers();
    for (const auto &server : servers) {
        struct lws_client_connect_info ccinfo = {0};
        ccinfo.context = context;
        ccinfo.address = server.c_str();
        ccinfo.port = 8080;
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
    std::vector<std::string> clients = read_clients();
    std::string client_update = "{ \"type\": \"client_update\", \"clients\": [";
    for (size_t i = 0; i < clients.size(); i++) {
        client_update += "\"" + clients[i] + "\"";
        if (i < clients.size() - 1) {
            client_update += ", ";
        }
    }
    client_update += "] }";
    relay_message_to_servers(client_update);
}

std::vector<std::string> Server::read_clients() {
    std::ifstream file("./data/clients.txt");
    std::string line;
    std::vector<std::string> clients;
    std::string client;

    while (std::getline(file, line)) {
        if (line[0] == '{') {
            client = "";
        } else if (line[0] == '}') {
            clients.push_back(client);
        } else {
            client += line;
        }
    }
    return clients;
}

void Server::relay_message_to_servers(const std::string &message) {
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
        {"chat-protocol", Server::callback_chat, 0, 8192},
        {"server-protocol", Server::callback_server, 0, 8192},
        {NULL, NULL, 0, 0}
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
    FILE *file = fopen("./data/servers.txt", "r");
    if (!file) {
        printf("Error: Could not open servers.txt\n");
        return std::vector<std::string>();
    }
    
    char line[1024];
    std::vector<std::string> servers;
    while (fgets(line, sizeof(line), file)) {
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
    std::vector<std::string> client_list = read_clients();
    for (std::string c : client_list) {
        if (c == client) {
            return 0;
        }
    }

    FILE *file = fopen("./data/clients.txt", "a");
    fprintf(file, "{\n%s\n}\n", client.c_str());
    fclose(file);
    return 0;
}

int main() {
    Server server;
    server.server_main();
    return 0;
}
