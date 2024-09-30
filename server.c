#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

static int callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_RECEIVE:
            char *received_message = (char *)in;
            received_message[len] = '\0';  // Make sure to null-terminate the message
            printf("Message received: %s\n", received_message);
            // Here you would decrypt and handle the received message
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

static struct lws_protocols protocols[] = {
    {"http", lws_callback_http_dummy, 0, 0},
    {"chat-protocol", callback_chat, 0, 1024},
    {NULL, NULL, 0, 0} /* terminator */
};

int main(void) {
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = 8080;
    info.protocols = protocols;
    
    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        printf("Failed to create WebSocket context\n");
        return 1;
    }
    
    printf("Server started on port 8080\n");
    
    while (1) {
        lws_service(context, 1000);
    }

    lws_context_destroy(context);
    return 0;
}
