CC = g++
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto -lportaudio -lmpg123

all: server client

server: server.cpp
	$(CC) server.cpp -o server $(CFLAGS) $(LDFLAGS)

client: client.cpp
	$(CC) client.cpp -o client $(CFLAGS) $(LDFLAGS)

clean:
	rm -f server client