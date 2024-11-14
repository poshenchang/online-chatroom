# Real-time Online Chatroom

A simple online chatroom implemented using C++ with socket programming. This project includes both server and client interface that communicate through TCP sockets to support real-time messaging in a group chat environment.

The server acts as a central hub that relays and process messages in between clientts. The server listens for new connections, register users and authenticates clients, and maintains list of connected clients and user database. Each client application handles its own UI and user input. The client onlny sends messages to the server when necessary, and receives messages from the server, which it then displays locally.

> [!WARNING]
> The application currently supports only one concurrent client at a time.

## Prerequisites

* g++ (GCC) 14.2.1 or similar compiler
* Linux/UNIX system is recommended

## Installation and Usage

1. Clone the repository

2. Compile the server and client

```bash
cd online-chatroom/code
make
```

3. Run server with a specified port
```bash
./server <port>
```

4. Start a client with the server's IP address and port
```bash
./client <server-ip> <port>
```

## Commands

* `help`: List available commands.
* `register`: Register with a unique username.
* `login`: Log in with a unique username.
* `logout`: Log out from account.
* `hello`/`hi`:  Say hi to the server!
* `exit`: Exit session.

## Limitations

Currently, messages are transmitted in plain text. File transfer or multimedia are not (yet) supported. Future improvements could include message encryption, enhanced authentication, and a GUI for a more user-friendly experience.
