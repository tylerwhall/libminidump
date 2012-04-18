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
#include <string.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <alloca.h>
#include <time.h>

#include "context.h"

static int minidump_write_string(struct context *c, const char *s, size_t *offset) {
        size_t n, l;
        struct minidump_string h;
        unsigned i;
        int r;
        void *p;

        assert(c);
        assert(s);

        l = strlen(s);
        n = offsetof(struct minidump_string, buffer) + l*2;

        r = context_reserve_bytes(c, n, &p, offset);
        if (r < 0)
                return r;

        memset(&h, 0, sizeof(h));
        h.length = htole32(l*2);
        memcpy(p, &h, offsetof(struct minidump_string, buffer));

        for (i = 0; i < l; i++) {
                uint16_t le;

                /* We just care about ASCII, so the conversion to UTF16 is trivial */

                le = htole16(s[i]);
                memcpy((uint8_t*) p + offsetof(struct minidump_string, buffer) + (2 * i), &le, 2);

                /* FIXME: We should have proper UTF8 → UTF16 conversion here */
        }

        return 0;
}

static int minidump_append_directory(struct context *c, uint32_t stream_type, size_t offset, size_t size) {
        uint32_t i;

        assert(c);

        i = c->minidump_n_streams++;
        assert(i < MINIDUMP_STREAMS_MAX);

        c->minidump_directory[i].stream_type = htole32(stream_type);
        c->minidump_directory[i].location.data_size = htole32((uint32_t) size);
        c->minidump_directory[i].location.rva = htole32((uint32_t) offset);

        fprintf(stderr, "Appending directory entry type=0x%x offset=%lu size=%lu\n", stream_type, (unsigned long) offset, (unsigned long) size);

        return 0;
}

static int minidump_write_blob_stream(struct context *c, uint32_t stream_type, const void *buffer, size_t size) {
        int r;
        size_t offset;

        assert(c);
        assert(buffer);
        assert(size > 0);

        r = context_append_bytes(c, buffer, size, &offset);
        if (r < 0)
                return r;

        r = minidump_append_directory(c, stream_type, offset, size);
        if (r < 0)
                return r;

        return r;
}

static int minidump_write_buffer_stream(struct context *c, uint32_t stream_type, const struct buffer *buffer) {
        assert(c);
        assert(buffer);

        if (!buffer->data)
                return 0;

        return minidump_write_blob_stream(c, stream_type, buffer->data, buffer->size);
}

static int minidump_write_system_info_stream(struct context *c) {
        struct minidump_system_info i;
        long l;
        struct utsname u;
        int r;
        size_t offset;

        assert(c);

        memset(&i, 0, sizeof(i));

        i.platform_id = htole32(MINIDUMP_PLATFORM_LINUX);

#if defined(__i386)
        i.processor_architecture = htole16(MINIDUMP_PROCESSOR_ARCHITECTURE_INTEL);
#elif defined(__mips__)
        i.processor_architecture = htole16(MINIDUMP_PROCESSOR_ARCHITECTURE_MIPS);
#elif defined(__ppc__)
        i.processor_architecture = htole16(MINIDUMP_PROCESSOR_ARCHITECTURE_PPC);
#elif defined (__arm__)
        i.processor_architecture = htole16(MINIDUMP_PROCESSOR_ARCHITECTURE_ARM);
#elif defined (__ia64__)
        i.processor_architecture = htole16(MINIDUMP_PROCESSOR_ARCHITECTURE_IA64);
#elif defined (__x86_64)
        i.processor_architecture = htole16(MINIDUMP_PROCESSOR_ARCHITECTURE_AMD64);
#elif defined (__sparc__)
        i.processor_architecture = htole16(MINIDUMP_PROCESSOR_ARCHITECTURE_SPARC);
#else
#error "I need porting"
#endif

        l = sysconf(_SC_NPROCESSORS_ONLN);
        i.number_of_processors = l <= 0 ? 1 : l;

        r = uname(&u);
        if (r < 0)
                return -errno;

        r = context_append_concat_string(c,
                                         &offset, NULL,
                                         u.sysname, " ",
                                         u.release, " ",
                                         u.version, " ",
                                         u.machine, " ",
                                         NULL);
        if (r < 0)
                return r;

        i.csd_version_rva = htole32((uint32_t) offset);

        /* FIXME: Breakpad fills these one in too, and we should as well, based on CPUID */
        /* FIXME: i.processor_level = "cpu family"; */
        /* FIXME: i.processor_revision = "model" << 8 | "stepping"; */
        /* FIXME: i.cpu.x86_cpu_info.vendor_id = "vendor_id"; */

        /* FIXME: On top of that we probably should fill in these as well: */
        /* FIXME: i.major_version = 3 */
        /* FIXME: i.minor_version = 3*/
        /* FIXME: i.build_number = 1 */
        /* FIXME: i.cpu.x86_cpu_info = CPUID... */

        return minidump_write_blob_stream(c, MINIDUMP_SYSTEM_INFO_STREAM, &i, sizeof(i));
}

#ifdef __x86_64
#define minidump_context minidump_context_amd64

static void minidump_fill_context(struct minidump_context_amd64 *context, struct thread_info *t) {
        assert(context);
        assert(t);

        context->context_flags = MINIDUMP_CONTEXT_AMD64_FULL|MINIDUMP_CONTEXT_AMD64_SEGMENTS;

        context->cs = t->regs.cs;
        context->ds = t->regs.ds;
        context->es = t->regs.es;
        context->fs = t->regs.fs;
        context->gs = t->regs.gs;
        context->ss = t->regs.ss;
        context->eflags = t->regs.eflags;
        if (t->have_user) {
                context->dr0 = t->user.u_debugreg[0];
                context->dr1 = t->user.u_debugreg[1];
                context->dr2 = t->user.u_debugreg[2];
                context->dr3 = t->user.u_debugreg[3];
                context->dr6 = t->user.u_debugreg[6];
                context->dr7 = t->user.u_debugreg[7];
        }
        context->rax = t->regs.rax;
        context->rcx = t->regs.rcx;
        context->rdx = t->regs.rdx;
        context->rbx = t->regs.rbx;
        context->rsp = t->regs.rsp;
        context->rbp = t->regs.rbp;
        context->rsi = t->regs.rsi;
        context->rdi = t->regs.rdi;
        context->r8 = t->regs.r8;
        context->r9 = t->regs.r9;
        context->r10 = t->regs.r10;
        context->r11 = t->regs.r11;
        context->r12 = t->regs.r12;
        context->r13 = t->regs.r13;
        context->r14 = t->regs.r14;
        context->r15 = t->regs.r15;
        context->rip = t->regs.rip;

        context->flt_save.control_word = t->fpregs.cwd;
        context->flt_save.status_word = t->fpregs.swd;
        context->flt_save.tag_word = t->fpregs.ftw;
        context->flt_save.error_opcode = t->fpregs.fop;
        context->flt_save.error_offset = t->fpregs.rip;
        context->flt_save.data_offset = t->fpregs.rdp;
        context->flt_save.mx_csr = t->fpregs.mxcsr;
        context->flt_save.mx_csr_mask = t->fpregs.mxcr_mask;
        memcpy(&context->flt_save.float_registers, &t->fpregs.st_space, 8 * 16);
        memcpy(&context->flt_save.xmm_registers, &t->fpregs.xmm_space, 16 * 16);
}
#else
#error "I need porting"
#endif

static int minidump_write_thread_list_stream(struct context *c) {
        struct minidump_thread_list *h;
        unsigned i;
        size_t l;
        int r;

        l = offsetof(struct minidump_thread_list, threads) +
                sizeof(struct minidump_thread) * c->n_threads;
        h = alloca(l);
        memset(h, 0, l);
        h->number_of_threads = htole32(c->n_threads);

        for (i = 0; i < c->n_threads; i++) {
                struct thread_info *a;
                struct minidump_thread *b;
                size_t offset;
                struct minidump_context context;
                struct map_info *m;

                a = c->threads + i;
                b = h->threads + i;

                memset(&context, 0, sizeof(context));
                minidump_fill_context(&context, a);
                r = context_append_bytes(c, &context, sizeof(context), &offset);
                if (r < 0)
                        return r;

                memset(b, 0, sizeof(*b));
                b->thread_id = htole32(a->tid);
                b->thread_context.rva = htole32(offset);
                b->thread_context.data_size = htole32(sizeof(context));

                m = context_find_map_info(c->write_maps, c->n_write_maps, a->stack_pointer);
                if (m) {
                        b->stack.start_of_memory_range = htole64(m->extent.address);
                        b->stack.memory.data_size = htole32(m->extent.size);
                        b->stack.memory.rva = htole32(m->minidump_offset);
                }

                a->minidump_offset = offset;
        }

        return minidump_write_blob_stream(c, MINIDUMP_THREAD_LIST_STREAM, h, l);
}

static int minidump_write_module_list_stream(struct context *c) {
        struct minidump_module_list *h;
        unsigned i;
        size_t l;
        int r;

        assert(c);

        l = offsetof(struct minidump_module_list, modules) +
                sizeof(struct minidump_module) * c->n_maps;
        h = alloca(l);
        memset(h, 0, l);
        h->number_of_modules = htole32(c->n_maps);

        for (i = 0; i < c->n_maps; i++) {
                struct map_info *a;
                struct minidump_module *b;
                size_t offset;

                a = c->maps + i;
                b = h->modules + i;

                memset(b, 0, sizeof(*b));
                b->base_of_image = htole64(a->extent.address);
                b->size_of_image = htole32(a->extent.size);

                if (a->name) {
                        r = minidump_write_string(c, a->name, &offset);
                        if (r < 0)
                                return r;

                        b->module_name_rva = htole32(offset);
                }

                /* FIXME: we should fill in a lot more here */
        }

        return minidump_write_blob_stream(c, MINIDUMP_MODULE_LIST_STREAM, h, l);
}

static int minidump_write_memory_list_stream(struct context *c) {
        struct minidump_memory_list *h;
        unsigned i;
        size_t l;
        int r;

        assert(c);

        l = offsetof(struct minidump_memory_list, memory_ranges) +
                sizeof(struct minidump_memory_descriptor) * c->n_write_maps;
        h = alloca(l);
        memset(h, 0, l);
        h->number_of_memory_ranges = htole32(c->n_write_maps);

        for (i = 0; i < c->n_write_maps; i++) {
                struct map_info *a;
                struct minidump_memory_descriptor *b;
                size_t offset;
                void *p;

                a = c->write_maps + i;
                b = h->memory_ranges + i;

                r = context_reserve_bytes(c, a->extent.size, &p, &offset);
                if (r < 0)
                        return r;

                r = context_read_memory(c, a->extent.address, p, a->extent.size);
                if (r < 0)
                        return r;

                memset(b, 0, sizeof(*b));
                b->start_of_memory_range = htole64(a->extent.address);
                b->memory.rva = htole32(offset);
                b->memory.data_size = htole32(a->extent.size);

                a->minidump_offset = offset;
        }

        return minidump_write_blob_stream(c, MINIDUMP_MEMORY_LIST_STREAM, h, l);
}

static int minidump_write_exception_stream(struct context *c) {
        struct minidump_exception_stream h;
        struct thread_info *t;

        assert(c);
        assert(c->n_threads > 0);

        t = c->threads+0;

        memset(&h, 0, sizeof(h));
        h.thread_id = htole32(t->tid);

        if (t->have_prstatus)
                h.exception_record.exception_code = htole32(t->prstatus.pr_info.si_signo);
        else if (t->have_siginfo) {
                h.exception_record.exception_code = htole32(t->siginfo.si_signo);
                h.exception_record.exception_address = htole64((uint64_t) t->siginfo.si_addr);
        }

        h.thread_context.data_size = htole32(sizeof(struct minidump_context));
        h.thread_context.rva = htole32(t->minidump_offset);

        return minidump_write_blob_stream(c, MINIDUMP_EXCEPTION_STREAM, &h, sizeof(h));
}

static int minidump_write_directory(struct context *c) {
        size_t offset;
        struct minidump_header *h;
        int r;

        assert(c);

        r = context_append_bytes(c, c->minidump_directory, sizeof(struct minidump_directory) * c->minidump_n_streams, &offset);
        if (r < 0)
                return r;

        /* The beginning of the minidump is definitely aligned, so we
         * access it directly and patch in the directory data. */
        h = c->output;
        h->number_of_streams = htole32(c->minidump_n_streams);
        h->stream_directory_rva = htole32((uint32_t) offset);

        return 0;
}

int minidump_write(struct context *c) {
        struct minidump_header h;
        int r;

        assert(c);

        memset(&h, 0, sizeof(h));
        h.signature = htole32(0x504d444d);
        h.version = htole32(0x0000a793);
        h.time_date_stamp = htole32(time(NULL));

        r = context_append_bytes(c, &h, sizeof(h), NULL);
        if (r < 0)
                return r;

        r = minidump_write_memory_list_stream(c);
        if (r < 0)
                return r;

        r = minidump_write_thread_list_stream(c);
        if (r < 0)
                return r;

        r = minidump_write_module_list_stream(c);
        if (r < 0)
                return r;

        r = minidump_write_exception_stream(c);
        if (r < 0)
                return r;

        r = minidump_write_system_info_stream(c);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_MAPS, &c->proc_maps);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_PROC_STATUS, &c->proc_status);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_ENVIRON, &c->proc_environ);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_CMD_LINE, &c->proc_cmdline);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_COMM, &c->proc_comm);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_ATTR_CURRENT, &c->proc_attr_current);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_EXE, &c->proc_exe);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_CPU_INFO, &c->proc_cpuinfo);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_LSB_RELEASE, &c->lsb_release);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_OS_RELEASE, &c->os_release);
        if (r < 0)
                return r;

        r = minidump_write_buffer_stream(c, MINIDUMP_LINUX_AUXV, &c->auxv);
        if (r < 0)
                return r;

        if (c->have_prpsinfo) {
                r = minidump_write_blob_stream(c, MINIDUMP_LINUX_PRPSINFO, &c->prpsinfo, sizeof(c->prpsinfo));
                if (r < 0)
                        return r;
        }

        if (c->have_coredump_header) {
                r = minidump_write_blob_stream(c, MINIDUMP_LINUX_CORE_EHDR, &c->coredump_header, sizeof(c->coredump_header));
                if (r < 0)
                        return r;
        }

        /* We probably should find __abort_msg and __glib_assert_msg
         * and include it here */

        r = minidump_write_directory(c);
        if (r < 0)
                return r;

        return 0;
}
