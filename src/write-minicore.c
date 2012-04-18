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
#include <sys/param.h>
#include <stdlib.h>
#include <errno.h>

#include "write-minicore.h"

static int minicore_append_ph(struct context *c, const ElfW(Phdr) *ph) {
        uint32_t i;

        assert(c);

        i = c->minicore_n_phs++;
        assert(i < c->n_write_maps + 1);

        memcpy(c->minicore_phs+i, ph, sizeof(*ph));

        fprintf(stderr, "Appending segment type=0x%x size=%lu\n",
                (unsigned) ph->p_type,
                (unsigned long) ph->p_filesz);

        return 0;
}

static int minicore_write_maps(struct context *c) {
        unsigned i;
        int r;

        assert(c);

        for (i = 0; i < c->n_write_maps; i++) {
                struct map_info *a;
                ElfW(Phdr) ph;
                void *p;
                size_t offset;

                a = c->write_maps + i;

                r = context_reserve_bytes(c, a->extent.size, &p, &offset);
                if (r < 0)
                        return r;

                r = context_read_memory(c, a->extent.address, p, a->extent.size);
                if (r < 0)
                        return r;

                memset(&ph, 0, sizeof(ph));
                ph.p_type = PT_LOAD;
                ph.p_offset = offset;
                ph.p_filesz = a->extent.size;
                ph.p_memsz = a->extent.size;
                ph.p_vaddr = a->extent.address;
                ph.p_flags = PF_W|PF_R|PF_X;

                r = minicore_append_ph(c, &ph);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int minicore_write_one_note(struct context *c, const char *name, ElfW(Word) type, const void *data, size_t length) {
        int r;
        ElfW(Nhdr) nh;

        assert(c);
        assert(name);
        assert(data || length <= 0);

        if (length <= 0)
                return 0;

        memset(&nh, 0, sizeof(nh));
        nh.n_namesz = strlen(name);
        nh.n_descsz = length;
        nh.n_type = type;

        r = context_append_bytes(c, &nh, sizeof(nh), NULL);
        if (r < 0)
                return r;

        r = context_append_bytes(c, name, nh.n_namesz, NULL);
        if (r < 0)
                return r;

        r = context_null_bytes(c, roundup(nh.n_namesz, sizeof(int)) - nh.n_namesz, NULL);
        if (r < 0)
                return r;

        r = context_append_bytes(c, data, nh.n_descsz, NULL);
        if (r < 0)
                return r;

        r = context_null_bytes(c, roundup(nh.n_descsz, sizeof(int)) - nh.n_descsz, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int minicore_write_note_prstatus(struct context *c, struct thread_info *i) {
        struct elf_prstatus synthetic;
        assert(c);
        assert(i);

        if (i->have_prstatus)
                return minicore_write_one_note(c, "CORE", NT_PRSTATUS, &i->prstatus, sizeof(i->prstatus));

        memset(&synthetic, 0, sizeof(synthetic));
        synthetic.pr_pid = i->tid;
        memcpy(&synthetic.pr_reg, &i->regs, sizeof(i->regs));

        return minicore_write_one_note(c, "CORE", NT_PRSTATUS, &synthetic, sizeof(synthetic));
}

static int minicore_write_note_prpsinfo(struct context *c) {
        struct elf_prpsinfo synthetic;

        assert(c);

        if (c->have_prpsinfo)
                return minicore_write_one_note(c, "CORE", NT_PRPSINFO, &c->prpsinfo, sizeof(c->prpsinfo));

        memset(&synthetic, 0, sizeof(synthetic));
        synthetic.pr_pid = c->pid;
        if (c->proc_comm.data)
                memcpy(synthetic.pr_fname, c->proc_comm.data, MIN(sizeof(synthetic.pr_fname), sizeof(c->proc_comm.size)));

        return minicore_write_one_note(c, "CORE", NT_PRPSINFO, &synthetic, sizeof(synthetic));
}

static int minicore_write_note_auxv(struct context *c) {
        assert(c);

        if (c->auxv.data)
                return minicore_write_one_note(c, "CORE", NT_AUXV, c->auxv.data, c->auxv.size);

        return 0;
}

static int minicore_write_note_fpregset(struct context *c, struct thread_info *i) {
        assert(c);

        return minicore_write_one_note(c, "CORE", NT_FPREGSET, &i->fpregs, sizeof(i->fpregs));
}

#ifdef __i386
static int minicore_write_note_fpregset(struct context *c, struct thread_info *i) {
        assert(c);

        return minicore_write_one_note(c, "LINUX", NT_PRXFPREG, &i->fpxregs, sizeof(i->fpxregs));
}
#endif

static int minicore_write_notes_for_thread(struct context *c, unsigned i) {
        int r;

        r = minicore_write_note_prstatus(c, c->threads+i);
        if (r < 0)
                return r;

        if (i == 0) {
                /* The data for the process is written in the middle
                 * of the data of thread #1 */
                r = minicore_write_note_prpsinfo(c);
                if (r < 0)
                        return r;

                r = minicore_write_note_auxv(c);
                if (r < 0)
                        return r;
        }
        r = minicore_write_note_fpregset(c, c->threads+i);
        if (r < 0)
                return r;

#ifdef __i386
        r = minicore_write_note_prxfpreg(c, c->threads+i);
        if (r < 0)
                return r;
#endif

        return 0;
}

static int minicore_write_meta_notes(struct context *c) {
        int r;

        assert(c);

        /* We use the same type identifiers as the minidump logic */

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_MAPS, c->proc_maps.data, c->proc_maps.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_PROC_STATUS, c->proc_status.data, c->proc_status.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_ENVIRON, c->proc_environ.data, c->proc_environ.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_CMD_LINE, c->proc_cmdline.data, c->proc_cmdline.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_COMM, c->proc_comm.data, c->proc_comm.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_ATTR_CURRENT, c->proc_attr_current.data, c->proc_attr_current.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_EXE, c->proc_exe.data, c->proc_exe.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_CPU_INFO, c->proc_cpuinfo.data, c->proc_cpuinfo.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_LSB_RELEASE, c->lsb_release.data, c->lsb_release.size);
        if (r < 0)
                return r;

        r = minicore_write_one_note(c, "LENNART", MINIDUMP_LINUX_OS_RELEASE, c->os_release.data, c->os_release.size);
        if (r < 0)
                return r;

        return 0;
}

static int minicore_write_notes(struct context *c) {
        ElfW(Phdr) ph;
        unsigned i;
        size_t offset;
        int r;

        assert(c);
        assert(c->n_threads > 0);

        offset = c->output_size;

        for (i = 0; i < c->n_threads; i++) {
                r = minicore_write_notes_for_thread(c, i);
                if (r < 0)
                        return r;
        }

        r = minicore_write_meta_notes(c);
        if (r < 0)
                return r;

        memset(&ph, 0, sizeof(ph));
        ph.p_type = PT_NOTE;
        ph.p_offset = offset;
        ph.p_filesz = c->output_size - offset;

        r = minicore_append_ph(c, &ph);
        if (r < 0)
                return r;

        return 0;
}

static int minicore_write_phs(struct context *c) {
        size_t offset;
        ElfW(Ehdr) *h;
        int r;

        assert(c);

        r = context_append_bytes(c, c->minicore_phs, sizeof(ElfW(Phdr)) * c->minicore_n_phs, &offset);
        if (r < 0)
                return r;

        h = c->output;
        h->e_phnum = c->minicore_n_phs;
        h->e_phoff = offset;

        return 0;
}

int minicore_write(struct context *c) {
        ElfW(Ehdr) h;
        int r;

        assert(c);

        memset(&h, 0, sizeof(h));
        memcpy(h.e_ident, ELFMAG, SELFMAG);
        h.e_type = ET_CORE;
        h.e_ehsize = sizeof(ElfW(Ehdr));
        h.e_phentsize = sizeof(ElfW(Phdr));
        h.e_shentsize = sizeof(ElfW(Shdr));

#if __WORDSIZE == 32
        h.e_ident[EI_CLASS] = ELFCLASS32;
#elif __WORDSIZE == 64
        h.e_ident[EI_CLASS] = ELFCLASS64;
#else
#error "Unknown word size."
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
        h.e_ident[EI_DATA] = ELFDATA2LSB;
#elif __BYTE_ORDER == __BIG_ENDIAN
        h.e_ident[EI_DATA] = ELFDATA2MSB;
#else
#error "Unknown endianess."
#endif
        h.e_ident[EI_VERSION] = EV_CURRENT;
        h.e_ident[EI_OSABI] = ELFOSABI_NONE;

#if defined(__i386)
        h.e_machine = EM_386;
#elif defined(__x86_64)
        h.e_machine = EM_X86_64;
#else
#error "Unknown machine."
#endif
        h.e_version = EV_CURRENT;

        r = context_append_bytes(c, &h, sizeof(h), NULL);
        if (r < 0)
                return r;

        /* Allocate an array for one segment per map plus one NOTE segment */
        c->minicore_phs = malloc(sizeof(ElfW(Phdr)) * (1 + c->n_write_maps));
        if (!c->minicore_phs)
                return -ENOMEM;

        r = minicore_write_notes(c);
        if (r < 0)
                return r;

        r = minicore_write_maps(c);
        if (r < 0)
                return r;

        r = minicore_write_phs(c);
        if (r < 0)
                return r;

        return 0;
}
