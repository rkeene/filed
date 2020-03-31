FILED_EXTRA_CFLAGS    := 
FILED_EXTRA_LDLAGS    := 
FILED_EXTRA_LIBS      := 
FILED_ADDITIONAL_DEPS := 

CC         = gcc
CFLAGS     = -I. -Wall -W -pthread -O3 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE $(FILED_EXTRA_CFLAGS)
LDFLAGS    = -pthread $(FILED_EXTRA_LDFLAGS)
LIBS       = -lpthread $(FILED_EXTRA_LIBS)
MIMETYPES  = /etc/httpd/mime.types

PREFIX := /usr/local
prefix := $(PREFIX)
bindir = $(prefix)/bin
mandir = $(prefix)/share/man
srcdir = .
vpath %.c $(srcdir)

ifeq ($(FILED_DO_SECCOMP),1)
FILED_EXTRA_CFLAGS += -DFILED_DO_SECCOMP=1
FILED_ADDTIONAL_DEPS += filed.seccomp.h
endif

all: filed

filed: filed.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LIBS)

filed.o: $(srcdir)/filed.c filed-mime-types.h $(FILED_ADDTIONAL_DEPS)

filed-mime-types.h: $(srcdir)/generate-mime-types $(srcdir)/mime.types
	'$(srcdir)/generate-mime-types' '$(MIMETYPES)' > filed-mime-types.h.new || \
		'$(srcdir)/generate-mime-types' '$(srcdir)/mime.types' > filed-mime-types.h.new
	mv filed-mime-types.h.new filed-mime-types.h

filed.seccomp.h: $(srcdir)/filed.seccomp $(srcdir)/generate-seccomp-filter
	$(srcdir)/generate-seccomp-filter $(srcdir)/filed.seccomp x86_64 "" i386 "" > filed.seccomp.h.new
	mv filed.seccomp.h.new filed.seccomp.h

install: filed $(srcdir)/filed.1
	test -d "$(DESTDIR)$(mandir)/man1" || mkdir -p "$(DESTDIR)$(mandir)/man1"
	test -d "$(DESTDIR)$(bindir)" || mkdir -p "$(DESTDIR)$(bindir)"
	cp '$(srcdir)/filed.1' "$(DESTDIR)$(mandir)/man1/"
	cp filed "$(DESTDIR)$(bindir)/"

clean:
	rm -f filed filed.o
	rm -f filed-mime-types.h.new filed.seccomp.h.new

distclean: clean
	rm -f filed-mime-types.h filed.seccomp.h

.PHONY: all install clean distclean
