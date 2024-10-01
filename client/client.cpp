#include "client.h"

#define MAX_MESSAGE_LENGTH 1024

RSA* Client::get_private_rsa_keypair() {
    RSA* rsa = nullptr; // Declare and initialize 'rsa' variable

    FILE* fp = fopen("./data/private.pem", "r");
    if (fp == NULL) {
        fclose(fp);

        rsa = generate_rsa_keypair(); // Assign value to 'rsa'
        save_rsa_private_key(rsa, "./data/private.pem");
        save_rsa_public_key(rsa, "./data/public.pem");

    } else {
        fclose(fp);

        fp = fopen("./data/private.pem", "r");
        rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL); // Assign value to 'rsa'
        fclose(fp);
    }

    return rsa;
}

RSA* Client::get_public_rsa_keypair() {
    RSA* rsa = nullptr; // Declare and initialize 'rsa' variable

    FILE* fp = fopen("./data/public.pem", "r");
    if (fp == NULL) {
        Client::get_private_rsa_keypair();
    } else {
    }
    rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL); // Assign value to 'rsa'
    fclose(fp);
    return rsa;
}

int Client::make_request(struct lws *wsi, const char *message, lws_write_protocol type) {
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
    lws_write(wsi, buf + LWS_SEND_BUFFER_PRE_PADDING, n, type);
    printf("Sending message: %s\n", message);

    // Request the WebSocket to be writable again for the next message
    lws_callback_on_writable(wsi);
}

int Client::callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("Client connected to server\n");

                /* Implementation of:
            {
                "data": {
                    "type": "hello",
                    "public_key": "<Exported PEM of RSA public key>"
                }
            }
            */

            // Generate RSA key pair
            RSA* rsa;
            rsa = Client::get_public_rsa_keypair();

            char message[MAX_MESSAGE_LENGTH];
            snprintf(message, MAX_MESSAGE_LENGTH, "{ \"data\": { \"type\": \"hello\", \"public_key\": \"%s\" } }", rsa);


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

                // Encrypt the message using the RSA public key

                // Send the message to the server
                make_request(wsi, message, LWS_WRITE_TEXT);
            }
            break;

        default:
            break;
    }
    return 0;
}

int Client::client_main(void) {

    static struct lws_protocols protocols[] = {
        {"http", lws_callback_http_dummy, 0, 0},
        {"chat-protocol", callback_chat, 0, MAX_MESSAGE_LENGTH},
        {NULL, NULL, 0, 0} /* terminator */
    };

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

int main() {
    Client client;
    return client.client_main();
}