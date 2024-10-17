# Submitted by: Group 7

Bunsarak Ann | Cyrus Kelly | Md Raiyan Rahman
 
 * Coded in C++


# Dependencies

- **libwebsockets**: For handling WebSocket connections.
- **OpenSSL**: Required for handling encryption and decryption.
- **g++**: The GNU C++ Compiler, used for compiling the code.



Install libwebsockets, openssl and g++ using the following code: 
```
sudo apt-get update && sudo apt-get install -y g++ libboost-all-dev libssl-dev nlohmann-json3-dev
```

For MacOS: 
```
brew update && brew install gcc boost openssl nlohmann-json
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
g++ -std=c++17 server.cpp -o server -lboost_system -lssl -lcrypto -lpthread
```

When compiled, run the file by: 
```
./server
```

For the client, go back to SecureProgrammingGroup directory and then to client:

```
cd ..
cd client
```

Compile client.cpp using 
```
g++ -std=c++17 client.cpp -o client -lboost_system -lssl -lcrypto -lpthread
```

When compiled, run the file by: 
```
./client
```

