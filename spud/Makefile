CC=gcc
CFLAGS=-W -Wall -std=c99 -pedantic -g
LIB_DIR=-L/usr/local/lib
LIBS=-lsodium
FILE=spud

all:
	$(CC) $(CFLAGS) -o $(FILE) $(FILE).c $(LIB_DIR) $(LIBS)

clean:
	rm $(FILE)
	rm -rf $(FILE).dSYM
