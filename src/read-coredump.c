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
#include <string.h>
#include <stdlib.h>

#include "coredump-util.h"
#include "read-coredump.h"

#define NOTE_SIZE_MAX (1024*1024*10)

int coredump_read_threads(struct context *c) {
        off_t offset, length;
        int r;
        struct thread_info i;
        unsigned thread_count;
        bool found_prpsinfo = false, found_auxv = false;
        bool found_prstatus = false, found_fpregset = false;

        assert(c);
        assert(CONTEXT_HAVE_COREDUMP(c));

        r = coredump_find_note_segment(c->coredump_fd, &c->coredump_header, &offset, &length);
        if (r < 0)
                return r;
        if (r == 0)
                return -EIO;

        thread_count = 0;

        while (length > 0) {
                off_t name_offset, descriptor_offset;
                char name[16];
                ssize_t l;
                ElfW(Nhdr) note;

                r = coredump_next_note(c->coredump_fd, &offset, &length, &note, &name_offset, &descriptor_offset);
                if (r < 0)
                        return r;

                if (note.n_namesz >= sizeof(name))
                        continue;

                if (note.n_descsz >= NOTE_SIZE_MAX)
                        return -EBADMSG;

                l = pread(c->coredump_fd, name, note.n_namesz, name_offset);
                if (l < 0)
                        return -errno;
                if (l != note.n_namesz)
                        return -EIO;

                name[l] = 0;

                fprintf(stderr, "Found note %s, type %u\n", name, note.n_type);

                if (strcmp(name, "CORE") == 0 &&
                    note.n_type == NT_PRSTATUS) {

                        if (thread_count > 0) {
                                if (!found_prstatus || !found_fpregset)
                                        return -EIO;

                                context_add_thread(c, &i);
                        }

                        memset(&i, 0, sizeof(i));
                        thread_count ++;
                        found_prstatus = true;
                        found_fpregset = false;

                        if (note.n_descsz != sizeof(i.prstatus))
                                return -EIO;

                        l = pread(c->coredump_fd, &i.prstatus, sizeof(i.prstatus), descriptor_offset);
                        if (l < 0)
                                return -errno;
                        if (l != sizeof(i.prstatus))
                                return -EIO;

                        i.tid = i.prstatus.pr_pid;
                        memcpy(&i.regs, i.prstatus.pr_reg, sizeof(i.regs));

                } else if (strcmp(name, "CORE") == 0 &&
                           note.n_type == NT_PRPSINFO) {

                        if (found_prpsinfo)
                                return -EIO;

                        found_prpsinfo = true;

                        if (note.n_descsz != sizeof(c->prpsinfo))
                                return -EIO;

                        l = pread(c->coredump_fd, &c->prpsinfo, sizeof(c->prpsinfo), descriptor_offset);
                        if (l < 0)
                                return -errno;
                        if (l != sizeof(c->prpsinfo))
                                return -EIO;

                } else if (strcmp(name, "CORE") == 0 &&
                           note.n_type == NT_AUXV) {

                        if (found_auxv)
                                return -EIO;

                        found_auxv = true;

                        free(c->auxv.data);
                        c->auxv.data = malloc(note.n_descsz);
                        if (!c->auxv.data)
                                return -ENOMEM;

                        l = pread(c->coredump_fd, c->auxv.data, note.n_descsz, descriptor_offset);
                        if (l < 0)
                                return -errno;
                        if (l != note.n_descsz)
                                return -EIO;

                        c->auxv.size = note.n_descsz;

                } else if (strcmp(name, "CORE") == 0 &&
                           note.n_type == NT_FPREGSET) {

                        if (found_fpregset)
                                return -EIO;

                        found_fpregset = true;

                        if (note.n_descsz != sizeof(i.fpregs))
                                return -EIO;

                        l = pread(c->coredump_fd, &i.fpregs, sizeof(i.fpregs), descriptor_offset);
                        if (l < 0)
                                return -errno;
                        if (l != sizeof(i.fpregs))
                                return -EIO;
#ifdef __i386
                } else if (strcmp(name, "LINUX") == 0 &&
                           note.n_type == NT_PRXFPREG) {

                        if (note.n_descsz != sizeof(i.fpxregs))
                                return -EIO;

                        l = pread(c->fd, &i.fpxregs, sizeof(i.fpxregs), descriptor_offset);
                        if (l < 0)
                                return -errno;
                        if (l != sizeof(i.fpxregs))
                                return -EIO;
#endif
                } else if (strcmp(name, "LENNART") == 0) {
                        struct buffer *b;

                        b = context_find_buffer(c, note.n_type);
                        if (b) {
                                r = context_pread_buffer(c->coredump_fd, b, note.n_descsz, descriptor_offset);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (thread_count > 0) {
                if (!found_prstatus || !found_fpregset)
                        return -EIO;

                i.have_prstatus = true;

                context_add_thread(c, &i);
        }

        if (!found_prpsinfo || !found_auxv)
                return -EIO;

        c->have_prpsinfo = true;

        return 0;
}

int coredump_read_maps(struct context *c) {
        unsigned long i;
        int r;

        assert(c);
        assert(CONTEXT_HAVE_COREDUMP(c));

        for (i = 0; i < c->coredump_header.e_phnum; i++) {
                ElfW(Phdr) segment;

                r = coredump_read_segment_header(c->coredump_fd, &c->coredump_header, i, &segment);
                if (r < 0)
                        return r;

                if (segment.p_type != PT_LOAD)
                        continue;

                r = context_add_mapping(c, segment.p_vaddr, segment.p_vaddr+segment.p_filesz, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}
