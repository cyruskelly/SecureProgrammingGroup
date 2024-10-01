#include "server.h"
#include <iostream>



int Server::callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    char *received_message = (char *)in;
    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            received_message[len] = '\0';  // Make sure to null-terminate the message
            printf("Message received: %s\n", received_message);
            // Here you would decrypt and handle the received message

            
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

int Server::add_client(std::vector<std::string> &client_list, std::string client) {
    client_list.push_back(client);
    return 0;
}


int main() {
    Server server;
    server.server_main();
    return 0;
}