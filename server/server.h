#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <libwebsockets.h>


class Server {

    public:
        std::vector<std::string> client_list;
        static int callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
        static int add_client(std::vector<std::string> &client_list, std::string client);
        int server_main(void);

};