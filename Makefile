CFLAGS=-Wextra -Wall -O0 -g -D_GNU_SOURCE -pthread

all: segfault mkminidump core

mkminidump: mkminidump.o \
	minidump.o \
	minidump.h \
	context.h \
	read-coredump.o \
	read-coredump.h \
	read-minidump.o \
	read-minidump.h \
	format.h \
	read-process.o \
	read-process.h \
	write-minicore.o \
	write-minicore.h \
	write-minidump.o \
	write-minidump.h \
	coredump-util.h \
	coredump-util.o \
	util.c \
	util.h
	$(CC) $(CFLAGS) $(LIBS) $^ -o $@

segfault: segfault.c
	$(CC) $(CFLAGS) $(LIBS) $^ -o $@

core:	segfault
	( ./segfault ||: ) > /dev/null 2>&1

clean:
	rm -f core.* core segfault mkminidump *.o
