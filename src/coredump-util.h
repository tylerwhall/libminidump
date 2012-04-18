/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foocoredumputilhfoo
#define foocoredumputilhfoo

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

#include <elf.h>
#include <link.h>

int coredump_read_header(int fd, ElfW(Ehdr) *header);
int coredump_read_segment_header(int fd, const ElfW(Ehdr) *header, unsigned long i, ElfW(Phdr) *segment);
int coredump_read_memory(int fd, const ElfW(Ehdr) *header, unsigned long source, void *destination, size_t length);

int coredump_find_note_segment(int fd, const ElfW(Ehdr) *header, off_t *offset, off_t *length);
int coredump_next_note(int fd, off_t *offset, off_t *length, ElfW(Nhdr) *n, off_t *name, off_t *descriptor);

#endif
