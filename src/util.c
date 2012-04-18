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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <inttypes.h>

#include "util.h"

void* memdup(const void *p, size_t l) {
        void *r;

        assert(p);

        r = malloc(l);
        if (!r)
                return NULL;

        memcpy(r, p, l);
        return r;
}

int read_full_file(const char *path, void **_buffer, size_t *_size) {
        void *buffer = NULL;
        size_t size = 0, allocated = 0;
        FILE *f;
        int r;

        assert(path);
        assert(_buffer);
        assert(_size);

        f = fopen(path, "re");
        if (!f)
                return -errno;

        while (!feof(f)) {
                size_t k;

                if (size >= allocated) {
                        size_t l;
                        void *p;

                        l = MAX(LINE_MAX, size * 2);
                        p = realloc(buffer, l);
                        if (!p) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        buffer = p;
                        allocated = l;
                }

                k = fread((uint8_t*) buffer + size, 1, allocated - size, f);
                if (k <= 0 && ferror(f)) {
                        r = -errno;
                        goto finish;
                }

                size += k;
        }

        r = 0;

        *_buffer = buffer;
        *_size = size;

finish:
        fclose(f);

        return r;
}
