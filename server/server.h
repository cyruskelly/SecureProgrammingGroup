#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <libwebsockets.h>
#include "../libs/rapidjson/document.h"
#include "../libs/trim.h"




class Server {

    public:
        std::vector<struct lws *> connected_servers;  // Declare connected servers
        struct serv {
            std::string address;
            std::vector<std::string> clients;
        };
        std::vector<serv> servers;

        std::string server_address;
        int server_port;
        
        // Static callback functions
        static int callback_chat(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
        static int callback_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

        // Non-static member functions
        int add_client(std::string client);
        std::vector<std::string> list_servers();
        void connect_to_other_servers(struct lws_context *context);
        void send_client_update_to_server(struct lws* server);
        std::vector<std::string> read_clients();
        void relay_message_to_all_servers(const std::string &message);
        void relay_message_to_server(const std::string &message, struct lws *wsi);
        void server_hello(struct lws *wsi);


        // Static JSON parser
        static rapidjson::Document *parse_json(const char *json);

        // Main server function
        int server_main(void);

        private:
        void update_servers_list() {
            std::ofstream servers_file("servers.txt", std::ios::app); // Open servers.txt in append mode
            if (servers_file.is_open()) {
                servers_file << server_address << ":" << server_port << "\n"; // Write the server address and port
                servers_file.close();
            } else {
                std::cerr << "Error: Could not open servers.txt to update server list." << std::endl;
            }
        }

        std::string trim(const std::string& str) {
        
            auto start = std::find_if_not(str.begin(), str.end(), [](unsigned char ch) {
                return std::isspace(ch);
            });

            auto end = std::find_if_not(str.rbegin(), str.rend(), [](unsigned char ch) {
                return std::isspace(ch);
            }).base();

            return (start < end ? std::string(start, end) : std::string());
        }
};