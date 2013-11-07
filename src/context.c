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
#include <sys/param.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "minidump.h"
#include "format.h"
#include "coredump-util.h"
#include "context.h"
#include "read-minidump.h"
#include "read-coredump.h"
#include "read-process.h"
#include "write-minidump.h"
#include "write-minicore.h"
#include "util.h"

int context_read_memory(struct context *c, unsigned long source, void *destination, size_t length) {
        int r;

        assert(c);
        assert(destination);
        assert(length > 0);

        if (CONTEXT_HAVE_COREDUMP(c)) {
                r = coredump_read_memory(c->coredump_fd, &c->coredump_header, source, destination, length);

                if (r != 0)
                        return r;
        }

        if (CONTEXT_HAVE_MINIDUMP(c)) {
                r = minidump_read_memory(c, source, destination, length);

                if (r != 0)
                        return r;
        }

        if (CONTEXT_HAVE_PROCESS(c)) {
                r = process_read_memory(c, source, destination, length);

                if (r != 0)
                        return r;
        }

        return 0;
}

int context_add_thread(struct context *c, struct thread_info *i) {
        unsigned j;

        assert(c);

#if defined(__i386)
        i->stack_pointer = (unsigned long) i->regs.esp;
        i->instruction_pointer = (unsigned long) i->regs.eip;
#elif defined(__x86_64)
        i->stack_pointer = (unsigned long) i->regs.rsp;
        i->instruction_pointer = (unsigned long) i->regs.rip;
#else
#error "I need porting to your architecture"
#endif

        if (c->n_threads >= c->allocated_threads) {
                struct thread_info *t;
                unsigned k;

                k = MAX(8, c->n_threads * 2);
                t = realloc(c->threads, sizeof(struct thread_info) * k);
                if (!t)
                        return -errno;

                c->allocated_threads = k;
                c->threads = t;
        }

        j = c->n_threads++;
        c->threads[j] = *i;

        fprintf(stderr, "Added thread %u tid=%lu sp=%0lx ip=%0lx\n",
                j,
                (unsigned long) i->tid,
                (unsigned long) i->stack_pointer,
                (unsigned long) i->instruction_pointer);

        return 0;
}

int context_add_mapping(struct context *c, unsigned long start, unsigned long end, const char *name) {
        unsigned j;

        assert(c);
        assert(end >= start);

        if (c->n_maps >= c->allocated_maps) {
                struct map_info *m;
                unsigned k;

                k = MAX(64, c->n_maps * 2);
                m = realloc(c->maps, sizeof(struct map_info) * k);
                if (!m)
                        return -errno;

                c->allocated_maps = k;
                c->maps = m;
        }

        j = c->n_maps++;

        c->maps[j].extent.address = start;
        c->maps[j].extent.size = (size_t) (end - start);
        c->maps[j].name = name ? strdup(name) : NULL;
        c->maps[j].build_id = NULL;

        if (name)
                fprintf(stderr, "Added mapping %u address=0x%lx size=0x%lx name=%s\n", j, c->maps[j].extent.address, c->maps[j].extent.size, name);
        else
                fprintf(stderr, "Added mapping %u address=0x%lx size=0x%lx\n", j, c->maps[j].extent.address, c->maps[j].extent.size);

        return 0;
}

struct map_info *context_find_map_info(struct map_info *m, unsigned n, unsigned long address) {
        unsigned j;

        assert(m);

        for (j = 0; j < n; j++) {

                if (address < m[j].extent.address)
                        continue;

                if (address >= m[j].extent.address + m[j].extent.size)
                        continue;

                return m + j;
        }

        return NULL;
}

static int pick_maps(struct context *c) {
        unsigned i;

        assert(c);

        c->n_write_maps = c->n_threads * 2;
        c->write_maps = malloc(sizeof(struct map_info) * c->n_write_maps);

        if (!c->write_maps)
                return -ENOMEM;

        memset(c->write_maps, 0, sizeof(struct map_info) * c->n_write_maps);

        for (i = 0; i < c->n_threads; i++) {
                struct thread_info *t;
                struct map_info *m;

                t = c->threads + i;
                m = c->write_maps + i * 2;

                if (t->instruction_pointer > CODE_SAVE_SIZE/2)
                        m[0].extent.address = t->instruction_pointer - CODE_SAVE_SIZE/2;
                else
                        m[0].extent.address = 0;
                m[0].extent.size = CODE_SAVE_SIZE;

                m[1].extent.address = t->stack_pointer & ~(getpagesize() - 1);
                m[1].extent.size = STACK_SAVE_SIZE;
        }

        return 0;
}

static bool extents_overlap(struct extent *a, struct extent *b) {
        assert(a);
        assert(b);

        return (a->address <= b->address + b->size) &&
                (a->address + a->size >= b->address);
}

static bool maps_merge(struct map_info *d, struct map_info *a, struct map_info *b) {
        unsigned long start, end;

        assert(a);
        assert(b);

        assert(!a->name);
        assert(!b->name);
        assert(!a->build_id);
        assert(!b->build_id);

        if (!extents_overlap(&a->extent, &b->extent))
                return false;

        start = MIN(a->extent.address, b->extent.address);
        end = MAX(a->extent.address + a->extent.size, b->extent.address + b->extent.size);

        fprintf(stderr, "Merging %lx|%lx=%lx %lu|%lu=%lu\n",
                (unsigned long) a->extent.address,
                (unsigned long) b->extent.address,
                (unsigned long) start,
                (unsigned long) a->extent.size,
                (unsigned long) b->extent.size,
                (unsigned long) (end - start));

        d->extent.address = start;
        d->extent.size = end - start;


        d->name = d->build_id = NULL;

        return true;
}

static int merge_maps(struct context *c) {
        bool merged;

        assert(c);

        /* Merge overlapping maps into one */

        do {
                unsigned i, j;

                merged = false;

                for (i = 0; i < c->n_write_maps; i++) {
                        for (j = i + 1; j < c->n_write_maps; j++)
                                if (maps_merge(c->write_maps+i, c->write_maps+i, c->write_maps+j)) {
                                        memmove(c->write_maps+j, c->write_maps+j+1,
                                                sizeof(struct map_info) * (c->n_write_maps-j-1));
                                        c->n_write_maps--;
                                        merged = true;
                                        break;
                                }

                        if (merged)
                                break;
                }

        } while (merged);

        return 0;
}

static bool maps_add(struct map_info *d, struct map_info *a, struct map_info *b) {
        unsigned long start, end;

        /* Masks a against b, and stores it in d */

        assert(!a->name);
        assert(!a->build_id);

        if (!extents_overlap(&a->extent, &b->extent))
                return false;

        start = MAX(a->extent.address, b->extent.address);
        end = MIN(a->extent.address + a->extent.size, b->extent.address + b->extent.size);

        d->extent.address = start;
        d->extent.size = end - start;

        d->name = b->name ? strdup(b->name) : NULL;
        d->build_id = b->build_id ? strdup(b->build_id) : NULL;

        return true;
}

static int mask_maps(struct context *c) {
        unsigned i, j;
        unsigned n_result = 0;
        struct map_info *result;

        assert(c);

        /* Split maps we write along the chunks of the maps we read */

        result = malloc(sizeof(struct map_info)*(c->n_write_maps + c->n_maps));

        if (!result)
                return -ENOMEM;

        for (i = 0; i < c->n_write_maps; i ++)
                for (j = 0; j < c->n_maps; j ++)
                        if (maps_add(result+n_result, c->write_maps+i, c->maps+j))
                                n_result++;

        free(c->write_maps);
        c->write_maps = result;
        c->n_write_maps = n_result;

        return 0;
}

int context_reserve_bytes(struct context *c, size_t bytes, void **ptr, size_t *offset) {
        assert(c);

        if (c->output_size + bytes > c->output_allocated) {
                size_t l;
                void *p;

                l = (c->output_size + bytes) * 2;
                if (l < 4096)
                        l = 4096;

                p = realloc(c->output, l);
                if (!p)
                        return -ENOMEM;

                c->output = p;
                c->output_allocated = l;
        }

        *ptr = (uint8_t*) c->output + c->output_size;

        if (offset)
                *offset = c->output_size;

        c->output_size += bytes;
        return 0;
}

int context_append_bytes(struct context *c, const void *data, size_t bytes, size_t *offset) {
        void *p;
        int r;

        assert(c);
        assert(data || bytes <= 0);

        r = context_reserve_bytes(c, bytes, &p, offset);
        if (r < 0)
                return r;

        if (bytes > 0)
                memcpy(p, data, bytes);

        return r;
}

int context_null_bytes(struct context *c, size_t bytes, size_t *offset) {
        void *p;
        int r;

        assert(c);

        r = context_reserve_bytes(c, bytes, &p, offset);
        if (r < 0)
                return r;

        if (bytes > 0)
                memset(p, 0, bytes);

        return r;
}

int context_append_concat_string(struct context *c, size_t *offset, size_t *size, ...) {
        va_list ap;
        bool first = true;
        size_t sum = 0, o = 0;
        int r;

        assert(c);

        va_start(ap, size);

        for (;;) {
                size_t l;
                const char *p;

                p = va_arg(ap, const char *);
                if (!p)
                        break;

                l = strlen(p);
                r = context_append_bytes(c, p, l, first ? &o : NULL);
                if (r < 0)
                        goto finish;

                sum += l;
                first = false;
        }

        r = context_append_bytes(c, "", 1, first ? &o : NULL);
        if (r < 0)
                goto finish;

        sum += 1;

        if (offset)
                *offset = o;

        if (size)
                *size = sum;

finish:
        va_end(ap);

        return r;
}

struct buffer *context_find_buffer(struct context *c, unsigned type) {
        assert(c);

        switch (type) {

        case MINIDUMP_LINUX_MAPS:
                return &c->proc_maps;

        case MINIDUMP_LINUX_PROC_STATUS:
                return &c->proc_status;

        case MINIDUMP_LINUX_ENVIRON:
                return &c->proc_environ;

        case MINIDUMP_LINUX_CMD_LINE:
                return &c->proc_cmdline;

        case MINIDUMP_LINUX_COMM:
                return &c->proc_comm;

        case MINIDUMP_LINUX_ATTR_CURRENT:
                return &c->proc_attr_current;

        case MINIDUMP_LINUX_EXE:
                return &c->proc_exe;

        case MINIDUMP_LINUX_CPU_INFO:
                return &c->proc_cpuinfo;

        case MINIDUMP_LINUX_LSB_RELEASE:
                return &c->lsb_release;

        case MINIDUMP_LINUX_OS_RELEASE:
                return &c->os_release;

        case MINIDUMP_LINUX_AUXV:
                return &c->auxv;
        }

        return NULL;
}

static int show_buffer(FILE *f, const char *title, struct buffer *b) {
        char *p;

        assert(f);
        assert(b);

        if (!b->data)
                return 0;

        fprintf(f, "-- %s\n", title);

        for (p = b->data; p < b->data + b->size; p++) {

                if ((*p < ' ' || *p >= 127) &&
                    *p != '\n' &&
                    *p != '\t') {
                        fprintf(f, "\\x%02x", *p);
                } else
                        putc(*p, f);
        }

        putc('\n', f);
        return 0;
}

static void map_show(FILE *f, unsigned i, struct map_info *m) {
        assert(f);
        assert(m);

        fprintf(f, "%4u: ", i);

        fprintf(f, "%016lx-%016lx %20lu bytes",
                (unsigned long) m->extent.address,
                (unsigned long) (m->extent.address + m->extent.size),
                m->extent.size);

        if (m->build_id)
                fprintf(f, "(build-id %s)", m->build_id);

        if (m->name) {
                fputs(" \"", f);
                fputs(m->name, f);
                fputc('\"', f);
        }

        fputc('\n', f);
}

static void thread_show(FILE *f, unsigned i, struct thread_info *t) {
        assert(f);
        assert(t);

        fprintf(f,
                "%4u %10lu: IP=%016lx SP=%016lx",
                i,
                (unsigned long) t->tid,
                (unsigned long) t->instruction_pointer,
                (unsigned long) t->stack_pointer);

        if (t->name) {
                fputs("\" ", f);
                fputs(t->name, f);
                fputc('\"', f);
        }

        fputc('\n', f);
}

void context_show(FILE *f, struct context *c) {
        unsigned i;
        unsigned long sum;

        assert(f);
        assert(c);

        fprintf(f,
                "-- Source\n"
                "Have Process: %s\n"
                "Have Coredump: %s\n"
                "Have Minidump: %s\n"
                "-- Available Maps\n",
                yes_no(CONTEXT_HAVE_PROCESS(c)),
                yes_no(CONTEXT_HAVE_COREDUMP(c)),
                yes_no(CONTEXT_HAVE_MINIDUMP(c)));

        for (i = 0, sum = 0; i < c->n_maps; i++) {
                map_show(f, i, c->maps + i);
                sum += c->maps[i].extent.size;
        }
        fprintf(f, "Total size = %lu bytes\n", sum);

        fputs("-- Reduced Maps\n", f);
        for (i = 0, sum = 0; i < c->n_write_maps; i++) {
                map_show(f, i, c->write_maps + i);
                sum += c->write_maps[i].extent.size;
        }
        fprintf(f, "Total size = %lu bytes\n", sum);

        fputs("-- Threads\n", f);
        for (i = 0; i < c->n_threads; i++)
                thread_show(f, i, c->threads + i);

        show_buffer(f, "Auxiliary Vector", &c->auxv);
        show_buffer(f, "/proc/$PID/maps", &c->proc_maps);
        show_buffer(f, "/proc/$PID/status", &c->proc_status);
        show_buffer(f, "/proc/$PID/cmdline", &c->proc_cmdline);
        show_buffer(f, "/proc/$PID/environ", &c->proc_environ);
        show_buffer(f, "/proc/$PID/comm", &c->proc_comm);
        show_buffer(f, "/proc/$PID/attr_context", &c->proc_attr_current);
        show_buffer(f, "/proc/$PID/exe", &c->proc_exe);
        show_buffer(f, "/proc/cpuinfo", &c->proc_cpuinfo);
        show_buffer(f, "/etc/lsb-release", &c->lsb_release);
        show_buffer(f, "/etc/os-release", &c->os_release);
}

static int map_compare(const void *_a, const void *_b) {
        const struct map_info *a = _a, *b = _b;

        if (a->extent.address < b->extent.address)
                return -1;

        if (a->extent.address >= b->extent.address)
                return 1;

        return 0;
}

int context_load(struct context *c) {
        int r;

        assert(c);

        if (CONTEXT_HAVE_MINIDUMP(c)) {
                r = minidump_read_header(c);
                if (r < 0)
                        return r;

                r = minidump_read_maps(c);
                if (r < 0)
                        return r;

                r = minidump_read_threads(c);
                if (r < 0)
                        return r;

                r = minidump_read_streams(c);
                if (r < 0)
                        return r;
        }

        if (CONTEXT_HAVE_COREDUMP(c)) {
                r = coredump_read_header(c->coredump_fd, &c->coredump_header);
                if (r < 0)
                        return r;

                c->have_coredump_header = true;

                r = coredump_read_maps(c);
                if (r < 0)
                        return r;

                r = coredump_read_threads(c);
                if (r < 0)
                        return r;
        }

        if (CONTEXT_HAVE_PROCESS(c)) {
                if (kill(c->pid, 0) < 0)
                        return -errno;

                r = process_attach(c);
                if (r < 0)
                        return r;

                r = process_read_maps(c);
                if (r < 0)
                        return r;

                r = process_read_threads(c);
                if (r < 0)
                        return r;

                r = process_read_fields(c);
                if (r < 0)
                        return r;
        }

        r = pick_maps(c);
        if (r < 0)
                return r;

        r = merge_maps(c);
        if (r < 0)
                return r;

        r = mask_maps(c);
        if (r < 0)
                return r;

        qsort(c->maps, c->n_maps, sizeof(struct map_info), map_compare);
        qsort(c->write_maps, c->n_write_maps, sizeof(struct map_info), map_compare);

        return r;
}

void context_release(struct context *c) {
        unsigned j;

        assert(c);

        if (CONTEXT_HAVE_PROCESS(c))
                process_detach(c);

        free(c->auxv.data);
        for (j = 0; j < c->n_maps; j++) {
                free(c->maps[j].name);
                free(c->maps[j].build_id);
        }
        for (j = 0; j < c->n_write_maps; j++) {
                free(c->write_maps[j].name);
                free(c->write_maps[j].build_id);
        }

        free(c->maps);
        free(c->write_maps);
        free(c->threads);
        free(c->output);
        free(c->proc_maps.data);
        free(c->proc_status.data);
        free(c->proc_environ.data);
        free(c->proc_cmdline.data);
        free(c->proc_comm.data);
        free(c->proc_attr_current.data);
        free(c->proc_exe.data);
        free(c->proc_cpuinfo.data);
        free(c->lsb_release.data);
        free(c->os_release.data);
}

static int make(pid_t pid, int fd,
                void **output, size_t *output_size,
                int (*write_dump)(struct context *c)) {
        struct context c;
        int r;

        if (pid <= 0 && fd < 0)
                return -EINVAL;

        if (!output)
                return -EINVAL;

        if (!output_size)
                return -EINVAL;

        memset(&c, 0, sizeof(c));
        c.pid = pid;
        c.coredump_fd = fd;
        c.minidump_fd = -1;

        r = context_load(&c);
        if (r < 0)
                goto finish;

        r = write_dump(&c);
        if (r < 0)
                goto finish;

        *output = c.output;
        *output_size = c.output_size;
        c.output = NULL;

finish:
        context_release(&c);
        return r;
}

__attribute__ ((visibility("default")))
int minidump_make(pid_t pid, int fd, void **minidump, size_t *size) {
        return make(pid, fd, minidump, size, minidump_write);
}

__attribute__ ((visibility("default")))
int minicore_make(pid_t pid, int fd, void **minicore, size_t *size) {
        return make(pid, fd, minicore, size, minicore_write);
}

static int show(FILE *f, pid_t pid, int coredump_fd, int minidump_fd) {
        struct context c;
        int r;

        if (!f)
                f = stdout;

        if (coredump_fd < 0 && pid <= 0 && minidump_fd < 0)
                return -EINVAL;

        memset(&c, 0, sizeof(c));
        c.pid = pid;
        c.coredump_fd = coredump_fd;
        c.minidump_fd = minidump_fd;

        r = context_load(&c);
        if (r < 0)
                goto finish;

        context_show(f, &c);
        r = 0;

finish:
        context_release(&c);
        return r;
}

__attribute__ ((visibility("default")))
int minidump_show(FILE *f, int minidump_fd) {
        return show(f, 0, -1, minidump_fd);
}

__attribute__ ((visibility("default")))
int coredump_show(FILE *f, pid_t pid, int coredump_fd) {
        return show(f, pid, coredump_fd, -1);
}

__attribute__ ((visibility("default")))
int minidump_to_minicore(int minidump_fd, void **output, size_t *output_size) {
        struct context c;
        int r;

        if (minidump_fd < 0)
                return -EINVAL;

        if (!output)
                return -EINVAL;

        if (!output_size)
                return -EINVAL;

        memset(&c, 0, sizeof(c));
        c.coredump_fd = -1;
        c.minidump_fd = minidump_fd;

        r = context_load(&c);
        if (r < 0)
                goto finish;

        r = minicore_write(&c);
        if (r < 0)
                goto finish;

        *output = c.output;
        *output_size = c.output_size;
        c.output = NULL;

finish:
        context_release(&c);
        return r;
}

int context_pread_buffer(int fd, struct buffer *b, size_t length, off_t offset) {
        void *p;
        ssize_t l;

        assert(fd >= 0);
        assert(b);
        assert(length > 0);

        p = malloc(length);
        if (!p)
                return -ENOMEM;

        l = pread(fd, p, length, offset);
        if (l < 0) {
                free(p);
                return -errno;
        }

        if ((size_t) l != length) {
                free(p);
                return -EIO;
        }

        free(b->data);
        b->data = p;
        b->size = length;

        return 0;
}
