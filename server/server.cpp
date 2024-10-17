#include "server.h"
#include <iostream>

int Server::callback_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
     // Cast user to Server* to call non-static member functions
    Server *server_instance = static_cast<Server *>(user);  // Assuming user data points to a Server instance
    rapidjson::Document * d;
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
                for (rapidjson::Value::ConstValueIterator itr = (*d)["clients"].GetArray().Begin(); itr != (*d)["clients"].GetArray().End(); ++itr) {
                    for (serv s : server_instance->servers) {
                        if (s.address == itr->GetString()) {
                            s.clients.push_back(itr->GetString());
                        }
                    }
                }
                
            } else if (rq_type == "client_update_request") {
                // Relay the message to all other servers
                server_instance->server_hello(wsi);
            } else if (rq_type == "signed_data") {
                if ((*d)["data"]["type"].GetString() == "server_hello") {
                    // Add the server to the list of connected servers
                    server_instance->connected_servers.push_back(wsi);

                    // Create an instance of serv
                    serv new_server;
                    new_server.address = (*d)["data"]["sender"].GetString();
                    new_server.clients = std::vector<std::string>();

                    server_instance->servers.push_back(new_server);
                }
            }

            break;

        case LWS_CALLBACK_ESTABLISHED:
            printf("Connected to another server\n");
            lws_callback_on_writable(wsi);
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
    rapidjson::Document * d;
    rapidjson::Document * d_response;
    std::string rq_type;
    std::string signed_rq_type;



    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';  // Make sure to null-terminate the message
            printf("Message received: %s\n", received_message);
            // Here you would decrypt and handle the received message
            d = parse_json(received_message);
            rq_type = (*d)["type"].GetString();
            printf("Request type: %s\n", rq_type.c_str());

            if (rq_type == "client_update") {
                for (rapidjson::Value::ConstValueIterator itr = (*d)["clients"].GetArray().Begin(); itr != (*d)["clients"].GetArray().End(); ++itr) {
                    for (serv s : server_instance->servers) {
                        if (s.address == itr->GetString()) {
                            s.clients.push_back(itr->GetString());
                        }
                    }
                }
                
            } else if (rq_type == "client_update_request") {
                // Relay the message to all other servers
                server_instance->server_hello(wsi);
            } else if (rq_type == "signed_data") {
                signed_rq_type = (*d)["data"]["type"].GetString() == "server_hello";
                if (signed_rq_type == "server_hello") {
                    // Add the server to the list of connected servers
                    server_instance->connected_servers.push_back(wsi);

                    // Create an instance of serv
                    serv new_server;
                    new_server.address = (*d)["data"]["sender"].GetString();
                    new_server.clients = std::vector<std::string>();

                    server_instance->servers.push_back(new_server);
                } else if (signed_rq_type == "hello") {
                    // Add the client to the list of clients
                    server_instance->add_client((*d)["data"]["public_key"].GetString());
                } else if (signed_rq_type == "client_update") {
                    server_instance->send_client_update_to_server(wsi);  // Use server_instance
                } 

            }


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

rapidjson::Document * Server::parse_json(const char *json) {
    rapidjson::Document * d = new rapidjson::Document();
    d->Parse(json);
    return d;
}

void Server::server_hello(lws *wsi) {
    std::string server_hello = "{ \"type\": \"signed_data\", \"data\": { \"type\": \"server_hello\", \"sender\": \"";
    server_hello += server_address + ":" + std::to_string(server_port);
    server_hello += "\" } }";
    relay_message_to_server(server_hello, wsi);
}

void Server::connect_to_other_servers(struct lws_context *context) {
    std::vector<std::string> servers = list_servers();  // List of known servers
    std::string addr;
    int port = 8080; // Default port

    for (const auto &server : servers) {
        size_t colon_pos = server.find(':');
        if (colon_pos != std::string::npos) {
            addr = server.substr(0, colon_pos);
            port = std::stoi(server.substr(colon_pos + 1));
        } else {
            addr = server;
        }

        if (addr == server_address && port == server_port) {
            continue;
        }

        struct lws_client_connect_info ccinfo = {0};
        ccinfo.context = context;
        ccinfo.address = addr.c_str();
        ccinfo.port = port;
        ccinfo.path = "/";
        ccinfo.protocol = "server-protocol";
        ccinfo.host = lws_canonical_hostname(context);
        ccinfo.origin = "origin";
        ccinfo.ietf_version_or_minus_one = -1;
        ccinfo.ssl_connection = 0;
        ccinfo.userdata = this;

        struct lws *wsi = lws_client_connect_via_info(&ccinfo);
        if (wsi == NULL) {
            printf("Failed to connect to server: %s\n", server.c_str());
        } else {
            printf("Connected to server: %s\n", server.c_str());
            server_hello(wsi);  // Send hello once connected
        }
    }
}


void Server::send_client_update_to_server(struct lws* server) {
    // Read clients from the file
    std::vector<std::string> clients = read_clients();
    
    // Format the list of clients as JSON
    std::string client_update = "{ \"type\": \"client_update\", \"clients\": [";
    for (size_t i = 0; i < clients.size(); i++) {
        client_update += "\"" + clients[i] + "\"";
        if (i < clients.size() - 1) {
            client_update += ", ";
        }
    }
    client_update += "] }";

    // Send the list of clients to all other servers
    relay_message_to_server(client_update, server);
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
            client = trim(client);
            clients.push_back(client);
        } else {
            client += line + "\n";
        }
    }
    return clients;
}

void Server::relay_message_to_all_servers(const std::string &message) {
    // Loop through connected servers and send the message
    for (const auto &server : connected_servers) {
        unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 8192 + LWS_SEND_BUFFER_POST_PADDING];
        memset(buf, 0, sizeof(buf));
        size_t n = message.size();
        memcpy(buf + LWS_SEND_BUFFER_PRE_PADDING, message.c_str(), n);
        lws_write(server, buf + LWS_SEND_BUFFER_PRE_PADDING, n, LWS_WRITE_TEXT);
        lws_callback_on_writable(server);

    }
}

void Server::relay_message_to_server(const std::string &message, lws *wsi) {
    unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 8192 + LWS_SEND_BUFFER_POST_PADDING];
    memset(buf, 0, sizeof(buf));
    size_t n = message.size();
    memcpy(buf + LWS_SEND_BUFFER_PRE_PADDING, message.c_str(), n);
    if (wsi != NULL) {
        lws_write(wsi, buf + LWS_SEND_BUFFER_PRE_PADDING, n, LWS_WRITE_TEXT);
        lws_callback_on_writable(wsi);
        printf("Relaying message: %s\n", message.c_str());
    } else {
        printf("Error: Server not connected\n");
    }
}

void Server::broadcast_discovery_message() {
    int sock;
    struct sockaddr_in broadcast_addr;
    std::string message = "{ \"data\": { \"type\": \"server_hello\", \"sender\": \"" + server_address + ":" + std::to_string(server_port) + "\" } }";
    int broadcast = 1;

    // Create a socket for broadcasting
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Set socket options to enable broadcast
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        perror("setsockopt");
        return;
    }

    // Define the broadcast address
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    broadcast_addr.sin_port = htons(12345);  // The broadcast port

    // Send the broadcast message
    if (sendto(sock, message.c_str(), message.length(), 0, (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr)) < 0) {
        perror("sendto");
    } else {
        printf("Broadcast message sent: %s\n", message.c_str());
    }

    close(sock);
}

void Server::listen_for_broadcasts() {
    int sock;
    struct sockaddr_in recv_addr;
    socklen_t addr_len;
    char buffer[1024];

    // Create a socket to listen for UDP messages
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Bind the socket to all interfaces and the broadcast port
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    recv_addr.sin_port = htons(12345);

    if (bind(sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("bind");
        return;
    }

    while (true) {
        // Listen for broadcast messages
        addr_len = sizeof(recv_addr);
        if (recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len) < 0) {
            perror("recvfrom");
            continue;
        }

        // Parse and handle the received message
        rapidjson::Document *d = parse_json(buffer);
        std::string type = (*d)["data"]["type"].GetString();
        if (type == "server_hello") {
            std::string sender = (*d)["data"]["sender"].GetString();
            printf("Received server_hello from %s\n", sender.c_str());

            // Add the discovered server to the list of known servers
            servers.push_back({sender, std::vector<std::string>()});
        }
    }

    close(sock);
}


int Server::server_main(void) {
    // Get the dynamic private IP address like in the Python script
    server_address = get_active_private_ip();
    if (server_address.empty()) {
        std::cerr << "Failed to get active private IP address" << std::endl;
        return 1;
    }

    std::cout << "Using server address: " << server_address << std::endl;

    std::cout << "Enter port: ";
    std::cin >> server_port;

    // Update the servers list with the new server
    update_servers_list();

    // Start a thread to listen for broadcast responses
    std::thread listen_thread(&Server::listen_for_broadcasts, this);
    listen_thread.detach();  // Detach so it runs in the background

    // Broadcast discovery message
    broadcast_discovery_message();

    static struct lws_protocols protocols[] = {
        {"http", lws_callback_http_dummy, 0, 0},
        {"chat-protocol", Server::callback_chat, 0, 8192},
        {"server-protocol", Server::callback_server, 0, 8192},
        {NULL, NULL, 0, 0} // terminator
    };

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = server_port;
    info.protocols = protocols;

    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        std::cerr << "Failed to create WebSocket context" << std::endl;
        return 1;
    }

    std::cout << "Server started on port " << server_port << std::endl;

    // Connect to discovered servers
    connect_to_other_servers(context); 

    while (1) {
        lws_service(context, 5000);
    }

    lws_context_destroy(context);
    return 0;
}


std::vector<std::string> Server::list_servers() {
    std::ifstream file("servers.txt");
    std::string line;
    std::vector<std::string> servers;

    if (!file.is_open()) {
        std::cerr << "Error: Could not open servers.txt" << std::endl;
        return servers;
    }

    while (std::getline(file, line)) {
        // Trim leading/trailing whitespaces and skip empty lines
        line = trim(line);  // Trim whitespaces using the custom `trim()` function

        if (!line.empty()) {  // Only process non-empty lines
            servers.push_back(line);
            std::cout << "Found server: " << line << std::endl;  // Debugging log to verify the server being added
        }
    }

    file.close();
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

/*
Group 7
Bunsarak Ann | Cyrus Kelly | Md Raiyan Rahman
*/