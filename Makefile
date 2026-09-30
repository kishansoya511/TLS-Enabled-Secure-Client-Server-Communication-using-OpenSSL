CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lssl -lcrypto

all: server client

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LIBS)

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LIBS)

cert:
	openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
	    -days 365 -nodes -subj "/CN=localhost"

clean:
	rm -f server client server.key server.crt

.PHONY: all cert clean
