#include "client.h"

#define MAX_MESSAGE_LENGTH 1024

static int callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("Client connected to server\n");
            lws_callback_on_writable(wsi);  // Request a writable event after connecting
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
            printf("Received message from server: %s\n", (char *)in);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:
            {
                // Read user input from the terminal
                char message[MAX_MESSAGE_LENGTH];
                printf("Enter message (or type 'exit' to quit): ");
                fgets(message, MAX_MESSAGE_LENGTH, stdin);
                
                // Remove the newline character from the input
                message[strcspn(message, "\n")] = 0;

                // Exit if the user types 'exit'
                if (strcmp(message, "exit") == 0) {
                    printf("Exiting...\n");
                    lws_cancel_service(lws_get_context(wsi));  // Stops the WebSocket service
                    return -1;
                }

                // Prepare buffer with the required padding
                unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + MAX_MESSAGE_LENGTH + LWS_SEND_BUFFER_POST_PADDING];
                memset(buf, 0, sizeof(buf)); // Clear the buffer

                size_t n = strlen(message);
                memcpy(buf + LWS_SEND_BUFFER_PRE_PADDING, message, n);  // Copy the message into the buffer

                // Send the message over WebSocket
                lws_write(wsi, buf + LWS_SEND_BUFFER_PRE_PADDING, n, LWS_WRITE_TEXT);
                printf("Sending message: %s\n", message);

                // Request the WebSocket to be writable again for the next message
                lws_callback_on_writable(wsi);
            }
            break;

        default:
            break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    {"http", lws_callback_http_dummy, 0, 0},
    {"chat-protocol", callback_chat, 0, MAX_MESSAGE_LENGTH},
    {NULL, NULL, 0, 0} /* terminator */
};

int main(void) {
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN; // No server, only client
    info.protocols = protocols;
    
    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        printf("Failed to create WebSocket client context\n");
        return 1;
    }
    
    struct lws_client_connect_info ccinfo = {0};
    ccinfo.context = context;
    ccinfo.address = "localhost";  // Assuming server is running on localhost
    ccinfo.port = 8080;            // Make sure this matches the server port
    ccinfo.path = "/";
    ccinfo.protocol = "chat-protocol";
    ccinfo.host = lws_canonical_hostname(context);
    ccinfo.origin = "origin";
    ccinfo.ietf_version_or_minus_one = -1;

    struct lws *wsi = lws_client_connect_via_info(&ccinfo);

    // Run the WebSocket service loop
    while (1) {
        lws_service(context, 1000);  // Service the WebSocket connection
    }

    lws_context_destroy(context);
    return 0;
}