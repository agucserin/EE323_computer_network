CC = gcc
CFLAGS = -W -Wall

all: client server

client: client.o
	$(CC) $(CFLAGS) -o client client.o

server: server.o
	$(CC) $(CFLAGS) -o server server.o

%.o: %.c
	$(CC) $(CFLAGS) $< -c

clean:
	@rm *.o client server