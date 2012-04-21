/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of libminidump.

  Copyright 2012 Lennart Poettering

  libminidump is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  libminidump is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with libminidump; If not, see
  <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/param.h>

#include "coredump-util.h"

int coredump_read_header(int fd, ElfW(Ehdr) *header) {
        ssize_t l;

        assert(fd >= 0);
        assert(header);

        l = pread(fd, header, sizeof(*header), 0);
        if (l < 0)
                return -errno;
        if (l != sizeof(*header))
                return -EIO;

        if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0)
                return -EBADMSG;

        if (header->e_type != ET_CORE)
                return -EBADMSG;

        if (header->e_ehsize != sizeof(ElfW(Ehdr)))
                return -EBADMSG;

        if (header->e_phentsize != sizeof(ElfW(Phdr)))
                return -EBADMSG;

#if __WORDSIZE == 32
        if (header->e_ident[EI_CLASS] != ELFCLASS32)
                return -EBADMSG;
#elif __WORDSIZE == 64
        if (header->e_ident[EI_CLASS] != ELFCLASS64)
                return -EBADMSG;
#else
#error "Unknown word size."
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
        if (header->e_ident[EI_DATA] != ELFDATA2LSB)
                return -EBADMSG;
#elif __BYTE_ORDER == __BIG_ENDIAN
        if (header->e_ident[EI_DATA] != ELFDATA2MSB)
                return -EBADMSG;
#else
#error "Unknown endianess."
#endif

#if defined(__i386)
        if (header->e_machine != EM_386)
                return -EBADMSG;
#elif defined(__x86_64)
        if (header->e_machine != EM_X86_64)
                return -EBADMSG;
#else
#error "Unknown machine."
#endif

        return 0;
}

int coredump_read_segment_header(int fd, const ElfW(Ehdr) *header, unsigned long i, ElfW(Phdr) *segment) {
        ssize_t l;

        assert(fd >= 0);
        assert(header);
        assert(segment);

        if (header->e_phoff == 0)
                return -E2BIG;

        if (i >= header->e_phnum)
                return -E2BIG;

        l = pread(fd, segment, sizeof(*segment),
                  header->e_phoff + i * header->e_phentsize);

        if (l < 0)
                return -errno;
        if (l != sizeof(*segment))
                return -EIO;

        return 0;
}

int coredump_find_note_segment(int fd, const ElfW(Ehdr) *header, off_t *offset, off_t *length) {
        unsigned long i;
        int r;

        assert(fd >= 0);
        assert(header);
        assert(offset);
        assert(length);

        for (i = 0; i < header->e_phnum; i++) {
                ElfW(Phdr) segment;

                r = coredump_read_segment_header(fd, header, i, &segment);
                if (r < 0)
                        return r;

                if (segment.p_type == PT_NOTE) {
                        *offset = segment.p_offset;
                        *length = segment.p_filesz;

                        return 1;
                }
        }

        return 0;
}

int coredump_read_memory(int fd, const ElfW(Ehdr) *header, unsigned long source, void *destination, size_t length) {
        unsigned long i;
        int r;

        assert(fd >= 0);
        assert(header);
        assert(destination);
        assert(length > 0);

        for (i = 0; i < header->e_phnum; i++) {
                ElfW(Phdr) segment;
                ssize_t l;

                r = coredump_read_segment_header(fd, header, i, &segment);
                if (r < 0)
                        return r;

                if (segment.p_type != PT_LOAD)
                        continue;

                if (source >= segment.p_vaddr + segment.p_filesz)
                        continue;

                if (source + length < segment.p_vaddr)
                        continue;

                /* We assume that what we are looking for lies
                 * entirely within one segment. */

                if (source < segment.p_vaddr ||
                    source + length > segment.p_vaddr + segment.p_filesz)
                        return -EIO;

                l = pread(fd,
                          destination, length,
                          segment.p_offset + (source - segment.p_vaddr));
                if (l < 0)
                        return -errno;
                if ((size_t) l != length)
                        return -EIO;

                return 1;
        }

        return 0;
}

int coredump_next_note(int fd, off_t *offset, off_t *length, ElfW(Nhdr) *n, off_t *name, off_t *descriptor) {
        ssize_t l;
        off_t j;

        assert(fd >= 0);
        assert(offset);
        assert(length);
        assert(n);
        assert(name);
        assert(descriptor);

        l = pread(fd, n, sizeof(*n), *offset);
        if (l < 0)
                return -errno;
        if (l != sizeof(*n))
                return -EIO;

        j = sizeof(*n) +
                roundup(n->n_namesz, sizeof(int)) +
                roundup(n->n_descsz, sizeof(int));

        if (j > *length)
                return -EIO;

        *name = *offset + sizeof(*n);
        *descriptor = *offset + sizeof(*n) + roundup(n->n_namesz, sizeof(int));

        *offset += j;
        *length -= j;

        return 0;
}
