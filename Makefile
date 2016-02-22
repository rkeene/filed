CC = gcc
CFLAGS = -std=gnu11 -Wall -Werror -Wno-error=cpp -W -pthread -O3 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDFLAGS = -pthread
LIBS = -lpthread
MIMETYPES = /etc/httpd/mime.types

PREFIX = /usr/local
prefix = $(PREFIX)
bindir = $(prefix)/bin
mandir = $(prefix)/share/man

all: filed

filed: filed.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LIBS)

filed.o: filed.c filed-mime-types.h

filed-mime-types.h: generate-mime-types mime.types
	./generate-mime-types "$(MIMETYPES)" > filed-mime-types.h.new || \
		./generate-mime-types mime.types > filed-mime-types.h.new
	mv filed-mime-types.h.new filed-mime-types.h

install: filed filed.1
	test -d "$(DESTDIR)$(mandir)/man1" || mkdir -p "$(DESTDIR)$(mandir)/man1"
	test -d "$(DESTDIR)$(bindir)" || mkdir -p "$(DESTDIR)$(bindir)"
	cp filed.1 "$(DESTDIR)$(mandir)/man1/"
	cp filed "$(DESTDIR)$(bindir)/"

clean:
	rm -f filed filed.o
	rm -f filed-mime-types.h.new

distclean: clean
	rm -f filed-mime-types.h

.PHONY: all install clean distclean
