# Real-time Online Chatroom

## Server

The server acts as a central hub that relays and process messages in between clientts. The server listens for new connections, register users and authenticates clients, and maintains list of connected clients and user database. 

## Client

Each client application handles its own UI and user input. The client onlny sends messages to the server when necessary, and receives messages from the server, which it then displays locally.
