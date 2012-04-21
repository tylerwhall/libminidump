/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foocontexthfoo
#define foocontexthfoo

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

#include <stdbool.h>
#include <elf.h>
#include <sys/user.h>
#include <sys/procfs.h>
#include <signal.h>
#include <link.h>

#include "minidump.h"
#include "format.h"

#define MINIDUMP_STREAMS_MAX 17
#define CODE_SAVE_SIZE 256
#define STACK_SAVE_SIZE (32*1024)

struct buffer {
        char *data;
        size_t size;
};

struct extent {
        unsigned long address;
        size_t size;
};

struct map_info {
        struct extent extent;
        char *name;
        char *build_id;

        /* When writing a minidump, the location of this stream */
        size_t minidump_offset;
};

struct thread_info {
        pid_t tid;
        unsigned long stack_pointer;
        unsigned long instruction_pointer;
        char *name;

        bool have_prstatus:1;
        bool have_siginfo:1;
        bool have_user:1;

        struct elf_prstatus prstatus;         /* only available on coredumps */
        siginfo_t siginfo;                    /* only available on ptrace */
        struct user user;                     /* only available on ptrace */

        struct user_regs_struct regs;
        struct user_fpregs_struct fpregs;
#ifdef __i386
        struct user_fpxregs_struct fpxregs;
#endif

        /* When writing a minidump, the location of this context */
        size_t minidump_offset;
};

struct context {
        pid_t pid;
        int coredump_fd;
        int minidump_fd;

        bool have_coredump_header:1;
        bool have_minidump_header:1;
        bool have_prpsinfo:1;

        ElfW(Ehdr) coredump_header;              /* only available on coredumps */
        struct elf_prpsinfo prpsinfo;            /* only available on coredumps */

        struct minidump_header minidump_header;  /* only available on minidumps */

        struct buffer auxv;

        /* The total maps we know off */
        struct map_info *maps;
        unsigned n_maps;
        unsigned allocated_maps;

        /* The subset we care about */
        struct map_info *write_maps;
        unsigned n_write_maps;

        struct thread_info *threads;
        unsigned n_threads;
        unsigned allocated_threads;

        /* Data from /proc */
        struct buffer proc_maps;
        struct buffer proc_status;
        struct buffer proc_environ;
        struct buffer proc_cmdline;
        struct buffer proc_comm;
        struct buffer proc_attr_current;
        struct buffer proc_exe;

        /* System data */
        struct buffer proc_cpuinfo;
        struct buffer lsb_release;
        struct buffer os_release;

        void *output;
        size_t output_size;
        size_t output_allocated;
        size_t output_offset;

        /* This is needed while writing a minidump */
        struct minidump_directory minidump_directory[MINIDUMP_STREAMS_MAX];
        uint32_t minidump_n_streams;

        /* This is needed while writing a minicore */
        ElfW(Phdr) *minicore_phs;
        uint32_t minicore_n_phs;
};

#define CONTEXT_HAVE_PROCESS(c) ((c)->pid > 0)
#define CONTEXT_HAVE_COREDUMP(c) ((c)->coredump_fd >= 0)
#define CONTEXT_HAVE_MINIDUMP(c) ((c)->minidump_fd >= 0)

int context_read_memory(struct context *c, unsigned long source, void *destination, size_t length);

int context_add_thread(struct context *c, struct thread_info *i);
int context_add_mapping(struct context *c, unsigned long start, unsigned long end, const char *name);

struct map_info *context_find_map_info(struct map_info *m, unsigned n, unsigned long address);

int context_reserve_bytes(struct context *c, size_t bytes, void **ptr, size_t *offset);
int context_append_bytes(struct context *c, const void *data, size_t bytes, size_t *offset);
int context_null_bytes(struct context *c, size_t bytes, size_t *offset);
int context_append_concat_string(struct context *c, size_t *offset, size_t *size, ...);

struct buffer *context_find_buffer(struct context *c, unsigned type);

void context_show(FILE *f, struct context *c);
int context_load(struct context *c);
void context_release(struct context *c);

int context_pread_buffer(int fd, struct buffer *b, size_t length, off_t offset);

#endif
