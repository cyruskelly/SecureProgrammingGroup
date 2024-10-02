#include <stdio.h>
#include <string>
#include "encrypt.h"
#include <libwebsockets.h>
//#include "../libs/base64.hpp"


#define MAX_MESSAGE_LENGTH 1024
#ifndef CLIENT_OLAF_N
#define CLIENT_OLAF_N

class Client {

    public:
        static RSA* get_private_rsa_keypair();

        static std::string get_public_rsa_keypair();

        static int make_request(struct lws *wsi, const char *message, lws_write_protocol type);

        static int callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

        int client_main(void);
};

#endif // DEBUG


