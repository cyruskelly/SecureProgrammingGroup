#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <thread>
#include <libwebsockets.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../libs/rapidjson/document.h"
#include "../libs/trim.h"

std::string get_active_private_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return "";
    }

    struct sockaddr_in loopback;
    memset(&loopback, 0, sizeof(loopback));
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = inet_addr("8.8.8.8");
    loopback.sin_port = htons(53); // DNS port

    if (connect(sock, (struct sockaddr *)&loopback, sizeof(loopback)) < 0) {
        perror("connect");
        close(sock);
        return "";
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr *)&name, &namelen) < 0) {
        perror("getsockname");
        close(sock);
        return "";
    }

    close(sock);

    char buffer[INET_ADDRSTRLEN];
    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, sizeof(buffer));
    if (p == nullptr) {
        perror("inet_ntop");
        return "";
    }
    
    return std::string(buffer);
}

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
    void broadcast_discovery_message();
    void listen_for_broadcasts();

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
};

/*
Group 7
Bunsarak Ann | Cyrus Kelly | Md Raiyan Rahman
*/
