CFLAGS=-Wextra -Wall -O0 -g -D_GNU_SOURCE -pthread

all: segfault generate core

generate: generate.o coredump.h coredump.o minidump.o minidump.h format.h
	$(CC) $(CFLAGS) $(LIBS) $^ -o $@

segfault: segfault.c
	$(CC) $(CFLAGS) $(LIBS) $^ -o $@

core:	segfault
	( ./segfault ||: ) > /dev/null 2>&1

clean:
	rm -f core.* core segfault generate
