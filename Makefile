CC = gcc
CFLAGS = -Wall -Werror -W -pthread -O3 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDFLAGS = -pthread
LIBS = -lpthread

PREFIX = /usr/local
prefix = $(PREFIX)
bindir = $(prefix)/bin
mandir = $(prefix)/share/man

all: filed

filed: filed.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LIBS)

filed.o: filed.c

install: filed filed.1
	test -d "$(DESTDIR)$(mandir)/man1" || mkdir -p "$(DESTDIR)$(mandir)/man1"
	test -d "$(DESTDIR)$(bindir)" || mkdir -p "$(DESTDIR)$(bindir)"
	cp filed.1 "$(DESTDIR)$(mandir)/man1/"
	cp filed "$(DESTDIR)$(bindir)/"

clean:
	rm -f filed filed.o

distclean: clean

.PHONY: all install clean distclean
