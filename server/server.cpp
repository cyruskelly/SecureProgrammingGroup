#include "server.h"
#include <iostream>



int Server::callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    char *received_message = (char *)in;
    rapidjson::Document * d;
    std::string rq_type;

    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';  // Make sure to null-terminate the message
            printf("Message received: %s\n", received_message);
            // Here you would decrypt and handle the received message
            d = parse_json(received_message);
            rq_type = (*d)["data"]["type"].GetString();

            if (rq_type == "hello") {
                // Add the client to the list of clients
                add_client(received_message);

            } else if (rq_type == "client_update") {
                // Clients are stored as {client},\n within the file and can be multiline
                FILE* file = fopen("/data/clients.txt", "r");
                std::vector<std::string> clients;
                char line[1024];
                char client[1024];
                while (fgets(line, 1024, file)) {
                    if (line[0] == '{') {
                        client[0] = '\0';
                    } else if (line[0] == '}') {
                        clients.push_back(client);
                    } else {
                        strcat(client, line);
                    }
                }
                fclose(file);
                // TODO: Format the list of clients into the following format:
                /*
                {
                    "type": "client_update",
                    "clients": [
                        "<PEM of exported RSA public key of client>",
                    ]
                }
                */

                // TODO: Send the list of clients to all other servers

            }
            
            break;
        case LWS_CALLBACK_ESTABLISHED:
            printf("Client connected %s\n", received_message);

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

int Server::server_main(void) {
    int port;
    std::cout << "Enter port number: ";
    std::cin >> port;

    static struct lws_protocols protocols[] = {
        {"http", lws_callback_http_dummy, 0, 0},
        {"chat-protocol", Server::callback_chat, 0, 1024},
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
    
    printf("Server started on port %i\n", port);
    
    while (1) {
        lws_service(context, 1000);
    }

    lws_context_destroy(context);
    return 0;
}

std::vector<std::string> Server::list_servers() {
    FILE *file = fopen("/data/servers.txt", "r");
    char line[1024];
    std::vector<std::string> servers;
    while (fgets(line, 1024, file)) {
        servers.push_back(line);
    }
    fclose(file);
    return servers;
}



int Server::add_client(std::string client) {
    FILE *file = fopen("/data/clients.txt", "a");
    fprintf(file, "{\n%s\n},\n", client.c_str());
    fclose(file);
}


int main() {
    Server server;
    server.server_main();
    return 0;
}