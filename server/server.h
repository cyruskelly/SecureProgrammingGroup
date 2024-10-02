#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <libwebsockets.h>
#include<unordered_map>
#include "../libs/rapidjson/document.h"




class Server {

    public:
        std::vector<std::string> client_list;
        std::vector<struct lws*> connected_servers;  // Declare connected servers
        
        // Static callback functions
        static int callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
        static int callback_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

        // Non-static member functions
        int add_client(std::string client);
        std::vector<std::string> list_servers();
        void connect_to_other_servers(struct lws_context *context);
        void send_client_update_to_servers();
        std::unordered_map<std::string, std::string> read_clients();
        void relay_message_to_servers(const std::string &message);

        // Static JSON parser
        static rapidjson::Document *parse_json(const char *json);

        // Signature validation function
        bool validate_signature(const char *message);

        
        // Main server function
        int server_main(void);

};