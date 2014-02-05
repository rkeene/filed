CC = gcc
CFLAGS = -Wall -Werror -W -pthread -O3
LDFLAGS = -pthread -static
LIBS = -lpthread

filed: filed.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LIBS)

filed.o: filed.c

clean:
	rm -f filed filed.o

distclean: clean

.PHONY: clean distclean
