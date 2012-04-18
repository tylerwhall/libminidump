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

#include "context.h"
#include "read-minidump.h"

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

int minidump_read_memory(struct context *c, unsigned long source, void *destination, size_t length) {
        assert(c);
        assert(destination);
        assert(length > 0);
        assert(CONTEXT_HAVE_MINIDUMP(c));

        /* FIXME */

        return -ENOTSUP;
}

int minidump_read_threads(struct context *c) {
        assert(c);
        assert(CONTEXT_HAVE_MINIDUMP(c));

        /* FIXME */

        return -ENOTSUP;
}

int minidump_read_maps(struct context *c) {
        assert(c);
        assert(CONTEXT_HAVE_MINIDUMP(c));

        /* FIXME */

        return -ENOTSUP;
}
