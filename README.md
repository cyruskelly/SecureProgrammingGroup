Compile server.c using 
```
cd server
gcc server.cpp -o server -lwebsockets -lssl -lcrypto -I/usr/local/include -L/usr/local/lib
```


//\\ run 
./server

The server will start on port `8080`

Compile client.c using 
```
cd client
gcc client.cpp encrypt.cpp -o client -lwebsockets -lssl -lcrypto -I/usr/include -L/usr/libs
```


//\\run 
./client 

Any Messages typed from the clients end will be sent to the server 
