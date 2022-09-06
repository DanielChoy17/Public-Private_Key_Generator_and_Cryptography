CC = clang
CFLAGS = -Wall -Werror -Wextra -Wpedantic $(shell pkg-config --cflags gmp)
LFLAGS = $(shell pkg-config --libs gmp)

all: encrypt decrypt keygen

encrypt: encrypt.o numtheory.o randstate.o rsa.o
	$(CC) -o encrypt encrypt.o numtheory.o randstate.o rsa.o $(LFLAGS)

decrypt: decrypt.o 
	$(CC) -o decrypt decrypt.o numtheory.o randstate.o rsa.o $(LFLAGS)

keygen: keygen.o
	$(CC) -o keygen keygen.o numtheory.o randstate.o rsa.o $(LFLAGS)

encrypt.o: encrypt.c
	$(CC) $(CFLAGS) -c encrypt.c

decrypt.o: decrypt.c
	$(CC) $(CFLAGS) -c decrypt.c

keygen.o: keygen.c
	$(CC) $(CFLAGS) -c keygen.c

numtheory.o: numtheory.c
	$(CC) $(CFLAGS) -c numtheory.c

randstate.o: randstate.c
	$(CC) $(CFLAGS) -c randstate.c

rsa.o: rsa.c
	$(CC) $(CFLAGS) -c rsa.c

clean:
	rm -f encrypt decrypt keygen *.o

format:
	clang-format -i -style=file *.c *.h
