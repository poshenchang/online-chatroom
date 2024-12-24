CC = g++
FLAGS = -lssl -lcrypto

all: server client

server: server.cpp
	$(CC) server.cpp -o server $(FLAGS)

client: client.cpp
	$(CC) client.cpp -o client $(FLAGS)

clean:
	rm -f server client