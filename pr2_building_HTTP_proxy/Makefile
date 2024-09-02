CC = gcc
CFLAGS = -W -Wall

all: proxy

proxy: proxy.o
	$(CC) $(CFLAGS) -o proxy proxy.o -lpthread

%.o: %.c
	$(CC) $(CFLAGS) $< -c

clean:
	@rm *.o proxy