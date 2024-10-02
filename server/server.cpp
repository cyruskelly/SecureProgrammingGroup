#include "server.h"
#include <iostream>

int Server::callback_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
     // Cast user to Server* to call non-static member functions
    Server *server_instance = static_cast<Server *>(user);  // Assuming user data points to a Server instance

    char *received_message = (char *)in;
    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';
            printf("Message received from another server: %s\n", received_message);
            // Use server_instance to call non-static methods
            server_instance->relay_message_to_servers(received_message);
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
    rapidjson::Document * d;
    rapidjson::Document * d_response;
    std::string rq_type;

    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';  // Make sure to null-terminate the message
            printf("Message received: %s\n", received_message);
            // Here you would decrypt and handle the received message
            d = parse_json(received_message);
            rq_type = (*d)["data"]["type"].GetString();
            printf("Request type: %s\n", rq_type.c_str());

            if (rq_type == "hello") {
                // Add the client to the list of clients
                add_client(d->operator[]("data")["public_key"].GetString());

            }
            } else if (rq_type == "client_update") {
                server_instance->send_client_update_to_servers();  // Use server_instance
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
    relay_message_to_servers(client_update);
}

std::vector<std::string> Server::read_clients() {
    std::ifstream file("/data/clients.txt");
    std::string line;
    std::vector<std::string> clients;

    while (std::getline(file, line)) {
        if (!line.empty()) {
            clients.push_back(line);
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
        {"chat-protocol", Server::callback_chat, 0, 8192},
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
    FILE *file = fopen("./data/clients.txt", "a");
    printf("File opened\n");
    fprintf(file, "{\n%s\n}\n", client.c_str());
    printf("Client added\n");
    fclose(file);
    return 0;
}


int main() {
    Server server;
    server.server_main();
    return 0;
}