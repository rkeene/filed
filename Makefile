CC = gcc
CFLAGS = -Wall -Werror -W -pthread -O3 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDFLAGS = -pthread -static
LIBS = -lpthread

filed: filed.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LIBS)

filed.o: filed.c

clean:
	rm -f filed filed.o

distclean: clean

.PHONY: clean distclean
