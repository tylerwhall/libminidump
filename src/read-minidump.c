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

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>

#include "context.h"
#include "read-minidump.h"

#define MAX_MEMORY_STREAMS 2048
#define MAX_THREADS 2048

int minidump_read_header(struct context *c) {
        ssize_t l;

        assert(c);
        assert(CONTEXT_HAVE_MINIDUMP(c));

        l = pread(c->minidump_fd, &c->minidump_header, sizeof(c->minidump_header), 0);
        if (l < 0)
                return -errno;
        if (l != sizeof(c->minidump_header))
                return -EIO;

        if (c->minidump_header.signature != htole32(0x504d444d))
                return -EBADMSG;

        c->have_minidump_header = true;

        return 0;
}

static int find_stream(struct context *c, uint32_t type, off_t *offset, off_t *length) {
        unsigned i;

        assert(c);
        assert(CONTEXT_HAVE_MINIDUMP(c));
        assert(offset);
        assert(length);

        for (i = 0; i < c->minidump_header.number_of_streams; i++) {
                off_t o;
                struct minidump_directory d;
                ssize_t l;

                o = c->minidump_header.stream_directory_rva + (sizeof(struct minidump_directory) * i);

                l = pread(c->minidump_fd, &d, sizeof(d), o);
                if (l < 0)
                        return -errno;
                if (l != sizeof(d))
                        return -EBADMSG;

                if (d.stream_type == type) {
                        *offset = d.location.rva;
                        *length = d.location.data_size;

                        return 1;
                }
        }

        return 0;
}

static int find_memory_list_stream(struct context *c, unsigned *n_descriptors, off_t *offset) {
        struct minidump_memory_list h;
        int r;
        ssize_t l;
        off_t size, off;

        assert(c);
        assert(CONTEXT_HAVE_MINIDUMP(c));
        assert(n_descriptors);
        assert(offset);

        r = find_stream(c, MINIDUMP_MEMORY_LIST_STREAM, &off, &size);
        if (r <= 0)
                return r;

        if (size < (off_t) offsetof(struct minidump_memory_list, memory_ranges))
                return -EBADMSG;

        l = pread(c->minidump_fd, &h, offsetof(struct minidump_memory_list, memory_ranges), off);
        if (l < 0)
                return -errno;
        if (l != offsetof(struct minidump_memory_list, memory_ranges))
                return -EBADMSG;

        if ((off_t) offsetof(struct minidump_memory_list, memory_ranges) +
            ((off_t) h.number_of_memory_ranges * (off_t) sizeof(struct minidump_memory_descriptor)) != size)
                return -EBADMSG;

        if (h.number_of_memory_ranges > MAX_MEMORY_STREAMS)
                return -E2BIG;

        *n_descriptors = h.number_of_memory_ranges;
        *offset = off + offsetof(struct minidump_memory_list, memory_ranges);

        return 1;
}

int minidump_read_memory(struct context *c, unsigned long source, void *destination, size_t length) {
        off_t offset;
        unsigned i, n;
        int r;
        ssize_t l;

        assert(c);
        assert(destination);
        assert(length > 0);
        assert(CONTEXT_HAVE_MINIDUMP(c));

        r = find_memory_list_stream(c, &n, &offset);
        if (r <= 0)
                return r;

        for (i = 0; i < n; i++) {
                struct minidump_memory_descriptor d;
                off_t o;

                o = offset + (sizeof(struct minidump_memory_descriptor) * i);

                l = pread(c->minidump_fd, &d, sizeof(d), o);
                if (l < 0)
                        return -errno;
                if (l != sizeof(d))
                        return -EBADMSG;

                if (source >= d.start_of_memory_range + d.memory.data_size)
                        continue;

                if (source + length < d.start_of_memory_range)
                        continue;

                if (source < d.start_of_memory_range ||
                    source + length > d.start_of_memory_range + d.memory.data_size)
                        return -EIO;

                l = pread(c->minidump_fd,
                          destination, length,
                          d.memory.rva + (source - d.start_of_memory_range));
                if (l < 0)
                        return -errno;
                if ((size_t) l != length)
                        return -EIO;

                return 1;
        }

        return 0;
}

int minidump_read_threads(struct context *c) {
        struct minidump_thread_list h;
        int r;
        off_t off, size;
        ssize_t l;
        unsigned i;

        assert(c);
        assert(CONTEXT_HAVE_MINIDUMP(c));

        r = find_stream(c, MINIDUMP_THREAD_LIST_STREAM, &off, &size);
        if (r <= 0)
                return r;

        if (size < (off_t) offsetof(struct minidump_thread_list, threads))
                return -EBADMSG;

        l = pread(c->minidump_fd, &h, offsetof(struct minidump_thread_list, threads), off);
        if (l < 0)
                return -errno;
        if (l != offsetof(struct minidump_thread_list, threads))
                return -EBADMSG;

        if ((off_t) offsetof(struct minidump_thread_list, threads) +
            ((off_t) h.number_of_threads * (off_t) sizeof(struct minidump_thread)) != size)
                return -EBADMSG;

        if (h.number_of_threads > MAX_THREADS)
                return -E2BIG;

        return -ENOTSUP;
}

int minidump_read_maps(struct context *c) {
        off_t offset;
        unsigned i, n;
        int r;
        ssize_t l;

        assert(c);
        assert(CONTEXT_HAVE_MINIDUMP(c));

        r = find_memory_list_stream(c, &n, &offset);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBADMSG;

        for (i = 0; i < n; i++) {
                off_t o;
                struct minidump_memory_descriptor d;

                o = offset + (sizeof(struct minidump_memory_descriptor) * i);

                l = pread(c->minidump_fd, &d, sizeof(d), o);
                if (l < 0)
                        return -errno;
                if (l != sizeof(d))
                        return -EBADMSG;

                r = context_add_mapping(c, d.start_of_memory_range, d.start_of_memory_range + d.memory.data_size, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

int minidump_read_streams(struct context *c) {
        unsigned i;
        int r;

        assert(c);
        assert(CONTEXT_HAVE_MINIDUMP(c));

        for (i = 0; i < c->minidump_header.number_of_streams; i++) {
                off_t o;
                struct minidump_directory d;
                ssize_t l;
                struct buffer *b = NULL;

                o = c->minidump_header.stream_directory_rva + (sizeof(struct minidump_directory) * i);

                l = pread(c->minidump_fd, &d, sizeof(d), o);
                if (l < 0)
                        return -errno;
                if (l != sizeof(d))
                        return -EBADMSG;

                if (d.stream_type == MINIDUMP_LINUX_PRPSINFO) {
                        if (d.location.data_size != sizeof(struct elf_prpsinfo))
                                return -EBADMSG;

                        l = pread(c->minidump_fd, &c->prpsinfo, sizeof(c->prpsinfo), d.location.rva);
                        if (l < 0)
                                return -errno;
                        if (l != sizeof(c->prpsinfo))
                                return -EBADMSG;

                        c->have_prpsinfo = true;
                        continue;
                }

                b = context_find_buffer(c, d.stream_type);
                if (b) {
                        r = context_pread_buffer(c->minidump_fd, b, d.location.data_size, d.location.rva);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
