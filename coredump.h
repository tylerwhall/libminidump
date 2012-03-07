#ifndef foocoredumphfoo
#define foocoredumphfoo

#include <elf.h>
#include <link.h>

int coredump_read_header(int fd, ElfW(Ehdr) *header);
int coredump_read_segment_header(int fd, const ElfW(Ehdr) *header, unsigned long i, ElfW(Phdr) *segment);
int coredump_read_memory(int fd, const ElfW(Ehdr) *header, unsigned long source, void *destination, size_t length);

int coredump_find_note_segment(int fd, const ElfW(Ehdr) *header, off_t *offset, off_t *length);
int coredump_next_note(int fd, off_t *offset, off_t *length, ElfW(Nhdr) *n, off_t *name, off_t *descriptor);

#endif
