CC = g++
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto -lavformat -lavcodec -lavutil -lswresample -lswscale -lSDL2

all: server client

server: server.cpp
	$(CC) server.cpp -o server $(CFLAGS) $(LDFLAGS)

client: client.cpp
	$(CC) client.cpp -o client $(CFLAGS) $(LDFLAGS)

clean:
	rm -f server client