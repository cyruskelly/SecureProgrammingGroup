# Submitted by: Group 7
Bunsarak Ann | Cyrus Kelly | Md Raiyan Rahman
 
 * Coded in C++


# Dependencies

- **libwebsockets**: For handling WebSocket connections.
- **OpenSSL**: Required for handling encryption and decryption.
- **g++**: The GNU C++ Compiler, used for compiling the code.



Install libwebsockets, openssl and g++ using the following code: 
```
sudo apt update
sudo apt install libwebsockets-dev openssl libssl-dev g++
```

From our understanding we have to submit a zip-file and with that being said when you try implementing our system, esnure that you have correctly navigated to the folder where you have extracted SecureProgrammingGroup: 

```
<your_path>/SecureProgrammingGroup#
```

From here, compile server.cpp by first changing directory to server:
```
cd server
```
and then implementing the following compilation command: 
```
g++ server.cpp -o server -lwebsockets -lssl -lcrypto -I./libs/libwebsockets -I./libs/rapidjson -L./libs/libwebsockets
```

When compiled, run the file by: 
```
./server
```

When prompted for port address and number, you can type anything and the sever should come online. 


For the client, go back to SecureProgrammingGroup directory and then to client:

```
cd ..
cd client
```

Compile client.c using 
```
g++ client.cpp encrypt.cpp -o client -lwebsockets -lssl -lcrypto -I./libs/libwebsockets -I./libs/rapidjson -L./libs/libwebsockets
```

