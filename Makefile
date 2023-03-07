CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=aes.c GTCRblockcipher.c cipher_wrap.c ghash.c main.c utils.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=out

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o out

