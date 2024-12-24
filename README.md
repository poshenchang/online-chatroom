# Real-time Online Chatroom

A simple online chatroom implemented using C++ with socket programming. This project includes both server and client interface that communicate through TCP sockets to support real-time messaging in a group chat environment.

The server acts as a central hub that relays and process messages in between clientts. The server listens for new connections, register users and authenticates clients, and maintains list of connected clients and user database. Each client application handles its own UI and user input. The client onlny sends messages to the server when necessary, and receives messages from the server, which it then displays locally.

## Features

* User authentication(registration, login, logout)
* Multithread server: supports up to 20 concurrent connections
* Peer-to-peer messaging: messages are sent directly from client to client without passing through server
* OpenSSL encryption: secure communication system for both client-to-client and client-to-server interactions.

## Prerequisites

* g++ (GCC) 14.2.1 or similar compiler
* Linux/UNIX system is recommended

## Installation and Usage

1. Clone the repository

2. Compile the server and client

```bash
cd online-chatroom
make
```

3. Generate a private key and a self-signed certificate for the server/client:
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

4. Run server with a specified port
```bash
./server <port>
```

5. Start a client with the server's IP address and port
```bash
./client <server-ip> <server-port>
```

## Commands

* `help`: List available commands.
* `register`: Register with a unique username.
* `login`: Log in with a unique username.
* `logout`: Log out from account.
* `hello`/`hi`:  Say hi to the server!
* `message`/`msg`: Message other users.
* `exit`: Exit session.

## Limitations and future improvements

Currently, messages are transmitted in plain text. File transfer or multimedia are not (yet) supported. Future improvements could include audio/video streaming and a GUI for a more user-friendly experience.