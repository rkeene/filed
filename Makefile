CC = gcc
CFLAGS = -Wall -Werror -W -pthread -O3
LDFLAGS = -pthread
LIBS = -lpthread

filed: filed.o
filed.o: filed.c

clean:
	rm -f filed filed.o

distclean: clean

.PHONY: clean distclean
