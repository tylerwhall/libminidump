/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#include <assert.h>
#include <stdbool.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/procfs.h>
#include <sys/uio.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <sys/utsname.h>
#include <stddef.h>
#include <endian.h>

#include "coredump.h"
#include "format.h"
#include "minidump.h"

#define MINIDUMP_STREAMS_MAX 17
#define CODE_SAVE_SIZE 256
#define STACK_SAVE_SIZE (32*1024)

#define NOTE_SIZE_MAX (1024*1024*10)

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

        /* The total maps we know of */
        struct map_info *maps;
        unsigned n_maps;
        unsigned allocated_maps;

        /* The subset we know off */
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

        /* system data */
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

#define HAVE_PROCESS(c) ((c)->pid > 0)
#define HAVE_COREDUMP(c) ((c)->coredump_fd >= 0)
#define HAVE_MINIDUMP(c) ((c)->minidump_fd >= 0)

static void* memdup(const void *p, size_t l) {
        void *r;

        assert(p);

        r = malloc(l);
        if (!r)
                return NULL;

        memcpy(r, p, l);
        return r;
}

static int threads_begin(pid_t pid, DIR **_d) {
        char *path;
        DIR *d;

        assert(pid > 0);

        if (asprintf(&path, "/proc/%lu/task", (unsigned long) pid) < 0)
                return -ENOMEM;

        d = opendir(path);
        free(path);

        if (!d)
                return -errno;

        *_d = d;
        return 0;
}

static int threads_next(DIR *d, pid_t *pid) {
        struct dirent buf, *de;
        int k;
        long l;
        char *p;

        for (;;) {
                k = readdir_r(d, &buf, &de);
                if (k != 0)
                        return -k;

                if (!de)
                        return 0;

                if (de->d_name[0] == '.')
                        continue;

                if (de->d_type != DT_DIR)
                        continue;

                errno = 0;
                l = strtol(de->d_name, &p, 10);
                if (errno != 0)
                        continue;

                if (p && *p != 0)
                        continue;

                if (l <= 0)
                        continue;

                *pid = (pid_t) l;
                return 1;
        }
}

static int read_full_file(const char *path, void **_buffer, size_t *_size) {
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

static int attach_threads(struct context *c) {
        DIR* d = NULL;
        int r;

        assert(c);
        assert(HAVE_PROCESS(c));

        r = threads_begin(c->pid, &d);
        if (r < 0)
                return r;

        for (;;) {
                pid_t tid;

                r = threads_next(d, &tid);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        break;

                if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {

                        if (errno == ESRCH)
                                continue;

                        r = -errno;
                        goto finish;
                }

                /* Wait until the thread is actually stopped */
                for (;;) {
                        int status;

                        if (waitpid(tid, &status, __WALL) < 0) {
                                if (errno == EINTR)
                                        continue;

                                r = -errno;
                                goto finish;
                        }

                        if (WIFSTOPPED(status))
                                break;
                }
        }

        r = 0;

finish:
        if (d)
                closedir(d);

        return r;
}

static int detach_threads(struct context *c) {
        DIR* d = NULL;
        int r;

        assert(c);
        assert(HAVE_PROCESS(c));

        r = threads_begin(c->pid, &d);
        if (r < 0)
                return r;

        for (;;) {
                pid_t tid;

                r = threads_next(d, &tid);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        break;

                if (ptrace(PTRACE_DETACH, tid, NULL, NULL) < 0) {

                        if (errno == ESRCH)
                                continue;

                        r = -errno;
                        goto finish;
                }
        }

        r = 0;

finish:
        if (d)
                closedir(d);

        return r;
}

static int ptrace_copy(enum __ptrace_request req, pid_t pid, unsigned long source, void *destination, size_t length) {
        long l;

        assert(req == PTRACE_PEEKTEXT ||
               req == PTRACE_PEEKDATA ||
               req == PTRACE_PEEKUSER);

        assert(pid > 0);
        assert(destination);
        assert(length > 0);

        while (length > 0) {

                errno = 0;
                l = ptrace(req, pid, (void*) source, NULL);
                if (errno != 0)
                        return -errno;

                memcpy(destination, &l, MIN(length, sizeof(l)));

                if (length <= sizeof(l))
                        break;

                length -= sizeof(l);
                source += sizeof(l);
                destination = (uint8_t*) destination + sizeof(l);
        }

        return 0;
}

static int minidump_read_memory(struct context *c, unsigned long source, void *destination, size_t length) {
        assert(c);
        assert(destination);
        assert(length > 0);
        assert(c->minidump_fd >= 0);

        /* FIXME */

        return -ENOTSUP;
}

static int read_memory(struct context *c, unsigned long source, void *destination, size_t length) {
        int r;

        assert(c);
        assert(destination);
        assert(length > 0);

        if (HAVE_COREDUMP(c)) {
                r = coredump_read_memory(c->coredump_fd, &c->coredump_header, source, destination, length);

                if (r != 0)
                        return r;
        }

        if (HAVE_MINIDUMP(c)) {
                r = minidump_read_memory(c, source, destination, length);

                if (r != 0)
                        return r;
        }

        if (HAVE_PROCESS(c))
                return ptrace_copy(PTRACE_PEEKDATA, c->pid, source, destination, length);

        return 0;
}

static int proc_read_buffer(const char *path, struct buffer *b) {
        assert(path);
        assert(b);

        if (b->data)
                return 0;

        return read_full_file(path, (void**) &b->data, &b->size);
}

static int proc_read_pid_buffer(pid_t pid, const char *field, struct buffer *b) {
        char *p;
        int r;

        assert(pid > 0);
        assert(field);
        assert(b);

        if (asprintf(&p, "/proc/%lu/%s", (unsigned long) pid, field) < 0)
                return -ENOMEM;

        r = proc_read_buffer(p, b);
        free(p);

        return r;
}

static int proc_readlink_pid_buffer(pid_t pid, const char *field, struct buffer *b) {
        char path[PATH_MAX];
        char *p;
        int r;

        assert(pid > 0);
        assert(b);

        if (b->data)
                return 0;

        if (asprintf(&p, "/proc/%lu/%s", (unsigned long) pid, field) < 0)
                return -ENOMEM;

        r = readlink(p, path, sizeof(path));
        free(p);

        if (r == 0)
                return 0;
        if (r < 0)
                return -errno;
        if (r == sizeof(path))
                return -E2BIG;

        p = memdup(path, r);
        if (!p)
                return -ENOMEM;

        b->data = p;
        b->size = r;

        return 0;
}

static int minidump_read_header(struct context *c) {
        ssize_t l;

        assert(c);
        assert(HAVE_MINIDUMP(c));

        l = pread(c->minidump_fd, &c->minidump_header, sizeof(c->minidump_header), 0);
        if (l < 0)
                return -errno;
        if (l != sizeof(c->minidump_header))
                return -EIO;

        if (c->minidump_header.signature != htole32(0x504d444d))
                return -EINVAL;

        c->have_minidump_header = true;

        return 0;
}

static int add_thread(struct context *c, struct thread_info *i) {
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

static int read_thread_info_ptrace(struct context *c, pid_t tid, struct thread_info *i) {
        int r;
        struct iovec iovec;

        assert(c);
        assert(HAVE_PROCESS(c));
        assert(tid > 0);
        assert(i);

        memset(i, 0, sizeof(*i));

        i->tid = tid;

        r = ptrace_copy(PTRACE_PEEKUSER, tid, 0, &i->user, sizeof(i->user));
        if (r < 0)
                return r;

        r = ptrace(PTRACE_GETSIGINFO, tid, NULL, &i->siginfo, sizeof(i->siginfo));
        if (r < 0)
                return r;

        /* Note: Asking the kernel for NT_PRSTATUS will actually give
         * us only the regs, not the full prstatus. The kernel is a
         * bit surprising sometimes. */
        iovec.iov_base = &i->regs;
        iovec.iov_len = sizeof(i->regs);
        r = ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iovec);
        if (r < 0)
                return r;
        if (iovec.iov_len != sizeof(i->regs))
                return -EIO;

        iovec.iov_base = &i->fpregs;
        iovec.iov_len = sizeof(i->fpregs);
        r = ptrace(PTRACE_GETREGSET, tid, NT_FPREGSET, &iovec);
        if (r < 0)
                return r;
        if (iovec.iov_len != sizeof(i->fpregs))
                return -EIO;

#ifdef __i386
        iovec.iov_base = &i->fpxregs;
        iovec.iov_len = sizeof(i->fpxregs);
        r = ptrace(PTRACE_GETREGSET, tid, NT_PRXFPREG, &iovec);
        if (r < 0)
                return r;
        if (iovec.iov_len != sizeof(i->fpxregs))
                return -EIO;
#endif

        i->have_siginfo = i->have_user = true;

        return 0;
}

static int proc_read_threads(struct context *c) {
        DIR *d = NULL;
        int r;

        assert(c);
        assert(HAVE_PROCESS(c));

        r = threads_begin(c->pid, &d);
        if (r < 0)
                return r;

        for (;;) {
                pid_t tid;
                struct thread_info i;

                r = threads_next(d, &tid);
                if (r < 0)
                        goto finish;

                if (r == 0)
                        break;

                r = read_thread_info_ptrace(c, tid, &i);
                if (r < 0)
                        goto finish;

                r = add_thread(c, &i);
                if (r < 0)
                        goto finish;

                /* FIXME: read name */
        }

        r = 0;

finish:
        if (d)
                closedir(d);

        return r;
}

static int coredump_read_threads(struct context *c) {
        off_t offset, length;
        int r;
        struct thread_info i;
        unsigned thread_count;
        bool found_prpsinfo = false, found_auxv = false;
        bool found_prstatus = false, found_fpregset = false;

        assert(c);
        assert(HAVE_COREDUMP(c));

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

                                add_thread(c, &i);
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

                        switch (note.n_type) {

                        case MINIDUMP_LINUX_MAPS:
                                b = &c->proc_maps;
                                break;
                        case MINIDUMP_LINUX_PROC_STATUS:
                                b = &c->proc_status;
                                break;
                        case MINIDUMP_LINUX_ENVIRON:
                                b = &c->proc_environ;
                                break;
                        case MINIDUMP_LINUX_CMD_LINE:
                                b = &c->proc_cmdline;
                                break;
                        case MINIDUMP_LINUX_COMM:
                                b = &c->proc_comm;
                                break;
                        case MINIDUMP_LINUX_ATTR_CURRENT:
                                b = &c->proc_attr_current;
                                break;
                        case MINIDUMP_LINUX_EXE:
                                b = &c->proc_exe;
                                break;
                        case MINIDUMP_LINUX_CPU_INFO:
                                b = &c->proc_cpuinfo;
                                break;
                        case MINIDUMP_LINUX_LSB_RELEASE:
                                b = &c->lsb_release;
                                break;
                        case MINIDUMP_LINUX_OS_RELEASE:
                                b = &c->os_release;
                                break;
                        default:
                                b = NULL;
                                break;
                        }

                        if (b) {
                                void *p;

                                p = malloc(note.n_descsz);
                                if (!p)
                                        return -ENOMEM;

                                l = pread(c->coredump_fd, p, note.n_descsz, descriptor_offset);
                                if (l < 0) {
                                        free(p);
                                        return -errno;
                                }
                                if (l != note.n_descsz) {
                                        free(p);
                                        return -EIO;
                                }

                                free(b->data);
                                b->data = p;
                                b->size = note.n_descsz;
                        }
                }
        }

        if (thread_count > 0) {
                if (!found_prstatus || !found_fpregset)
                        return -EIO;

                i.have_prstatus = true;

                add_thread(c, &i);
        }

        if (!found_prpsinfo || !found_auxv)
                return -EIO;

        c->have_prpsinfo = true;

        return 0;
}

static int minidump_read_threads(struct context *c) {
        assert(c);

        /* FIXME */

        return -ENOTSUP;
}

static int add_mapping(struct context *c, unsigned long start, unsigned long end, const char *name) {
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

static int proc_read_maps(struct context *c) {
        char *p;
        FILE *f;
        int r;

        assert(c);
        assert(HAVE_PROCESS(c));

        if (asprintf(&p, "/proc/%lu/maps", (unsigned long) c->pid) < 0)
                return -ENOMEM;

        f = fopen(p, "re");
        free(p);

        if (!f)
                return -errno;

        while (!feof(f)) {
                int k;
                char line[LINE_MAX];
                unsigned long start, end;
                int j;

                if (!fgets(line, sizeof(line), f)) {
                        if (ferror(f)) {
                                r = -errno;
                                goto finish;
                        }

                        break;
                }

                line[strcspn(line, "\n\r")] = 0;

                k = sscanf(line, "%lx-%lx %*s %*x %*x:%*x %*u %n", &start, &end, &j);
                if (k != 2) {
                        r = -EIO;
                        break;
                }

                r = add_mapping(c, start, end, line[j] == 0 ? NULL : line + j);
                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        if (f)
                fclose(f);

        return r;
}

static struct map_info *find_map_info(struct map_info *m, unsigned n, unsigned long address) {
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

static int coredump_read_maps(struct context *c) {
        unsigned long i;
        int r;

        assert(c);
        assert(HAVE_COREDUMP(c));

        for (i = 0; i < c->coredump_header.e_phnum; i++) {
                ElfW(Phdr) segment;

                r = coredump_read_segment_header(c->coredump_fd, &c->coredump_header, i, &segment);
                if (r < 0)
                        return r;

                if (segment.p_type != PT_LOAD)
                        continue;

                r = add_mapping(c, segment.p_vaddr, segment.p_vaddr+segment.p_filesz, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int minidump_read_maps(struct context *c) {
        assert(c);

        /* FIXME */

        return -ENOTSUP;
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

                m[1].extent.address = t->stack_pointer;
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

static int reserve_bytes(struct context *c, size_t bytes, void **ptr, size_t *offset) {
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

static int append_bytes(struct context *c, const void *data, size_t bytes, size_t *offset) {
        void *p;
        int r;

        assert(c);
        assert(data || bytes <= 0);

        r = reserve_bytes(c, bytes, &p, offset);
        if (r < 0)
                return r;

        if (bytes > 0)
                memcpy(p, data, bytes);

        return r;
}

static int null_bytes(struct context *c, size_t bytes, size_t *offset) {
        void *p;
        int r;

        assert(c);

        r = reserve_bytes(c, bytes, &p, offset);
        if (r < 0)
                return r;

        if (bytes > 0)
                memset(p, 0, bytes);

        return r;
}

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

        r = reserve_bytes(c, n, &p, offset);
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

        r = append_bytes(c, buffer, size, &offset);
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

static int append_concat_string(struct context *c, size_t *offset, size_t *size, ...) {
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
                r = append_bytes(c, p, l, first ? &o : NULL);
                if (r < 0)
                        goto finish;

                sum += l;
                first = false;
        }

        r = append_bytes(c, "", 1, first ? &o : NULL);
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

        r = append_concat_string(c,
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
                r = append_bytes(c, &context, sizeof(context), &offset);
                if (r < 0)
                        return r;

                memset(b, 0, sizeof(*b));
                b->thread_id = htole32(a->tid);
                b->thread_context.rva = htole32(offset);
                b->thread_context.data_size = htole32(sizeof(context));

                m = find_map_info(c->write_maps, c->n_write_maps, a->stack_pointer);
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

                r = reserve_bytes(c, a->extent.size, &p, &offset);
                if (r < 0)
                        return r;

                r = read_memory(c, a->extent.address, p, a->extent.size);
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

        r = append_bytes(c, c->minidump_directory, sizeof(struct minidump_directory) * c->minidump_n_streams, &offset);
        if (r < 0)
                return r;

        /* The beginning of the minidump is definitely aligned, so we
         * access it directly and patch in the directory data. */
        h = c->output;
        h->number_of_streams = htole32(c->minidump_n_streams);
        h->stream_directory_rva = htole32((uint32_t) offset);

        return 0;
}

static int write_minidump(struct context *c) {
        struct minidump_header h;
        int r;

        assert(c);

        memset(&h, 0, sizeof(h));
        h.signature = htole32(0x504d444d);
        h.version = htole32(0x0000a793);
        h.time_date_stamp = htole32(time(NULL));

        r = append_bytes(c, &h, sizeof(h), NULL);
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

                r = reserve_bytes(c, a->extent.size, &p, &offset);
                if (r < 0)
                        return r;

                r = read_memory(c, a->extent.address, p, a->extent.size);
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

        r = append_bytes(c, &nh, sizeof(nh), NULL);
        if (r < 0)
                return r;

        r = append_bytes(c, name, nh.n_namesz, NULL);
        if (r < 0)
                return r;

        r = null_bytes(c, roundup(nh.n_namesz, sizeof(int)) - nh.n_namesz, NULL);
        if (r < 0)
                return r;

        r = append_bytes(c, data, nh.n_descsz, NULL);
        if (r < 0)
                return r;

        r = null_bytes(c, roundup(nh.n_descsz, sizeof(int)) - nh.n_descsz, NULL);
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

        r = append_bytes(c, c->minicore_phs, sizeof(ElfW(Phdr)) * c->minicore_n_phs, &offset);
        if (r < 0)
                return r;

        h = c->output;
        h->e_phnum = c->minicore_n_phs;
        h->e_phoff = offset;

        return 0;
}

static int write_minicore(struct context *c) {
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

#if __i386
        h.e_machine = EM_386;
#elif __x86_64
        h.e_machine = EM_X86_64;
#else
#error "Unknown machine."
#endif
        h.e_version = EV_CURRENT;

        r = append_bytes(c, &h, sizeof(h), NULL);
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

static void context_show(FILE *f, struct context *c) {
        unsigned i;
        unsigned long sum;

        assert(f);
        assert(c);

        fputs("-- Available Maps\n", f);
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

static int proc_load_fields(struct context *c) {
        int r;

        assert(c);
        assert(c->pid >= 0);

        /* These ones matter */
        r = proc_read_pid_buffer(c->pid, "maps", &c->proc_maps);
        if (r < 0)
                return r;

        r = proc_read_pid_buffer(c->pid, "auxv", &c->auxv);
        if (r < 0)
                return r;

        /* The following ones don't really matter, so don't check return values */
        proc_read_pid_buffer(c->pid, "status", &c->proc_status);
        proc_read_pid_buffer(c->pid, "cmdline", &c->proc_cmdline);
        proc_read_pid_buffer(c->pid, "environ", &c->proc_environ);
        proc_read_pid_buffer(c->pid, "comm", &c->proc_comm);
        proc_read_pid_buffer(c->pid, "attr/current", &c->proc_attr_current);
        proc_readlink_pid_buffer(c->pid, "exe", &c->proc_exe);

        proc_read_buffer("/proc/cpuinfo", &c->proc_cpuinfo);
        /* This is an Ubuntuism, but Google is doing this, hence let's stay compatible here */
        proc_read_buffer("/etc/lsb-release", &c->lsb_release);
        /* It's much nicer to write /etc/os-release instead, which is more widely supported */
        proc_read_buffer("/etc/os-release", &c->os_release);

        return 0;
}

static int map_compare(const void *_a, const void *_b) {
        const struct map_info *a = _a, *b = _b;

        if (a->extent.address < b->extent.address)
                return -1;

        if (a->extent.address >= b->extent.address)
                return 1;

        return 0;
}

static int context_load(struct context *c) {
        int r;

        assert(c);

        if (HAVE_MINIDUMP(c)) {
                r = minidump_read_header(c);
                if (r < 0)
                        return r;

                r = minidump_read_maps(c);
                if (r < 0)
                        return r;

                r = minidump_read_threads(c);
                if (r < 0)
                        return r;
        }

        if (HAVE_COREDUMP(c)) {
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

        if (HAVE_PROCESS(c)) {
                if (kill(c->pid, 0) < 0)
                        return -errno;

                r = attach_threads(c);
                if (r < 0)
                        return r;

                r = proc_read_maps(c);
                if (r < 0)
                        return r;

                r = proc_read_threads(c);
                if (r < 0)
                        return r;

                r = proc_load_fields(c);
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

static void context_release(struct context *c) {
        unsigned j;

        assert(c);

        if (HAVE_PROCESS(c))
                detach_threads(c);

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

int minidump_make(pid_t pid, int fd, void **minidump, size_t *size) {
        return make(pid, fd, minidump, size, write_minidump);
}

int minicore_make(pid_t pid, int fd, void **minicore, size_t *size) {
        return make(pid, fd, minicore, size, write_minicore);
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

int minidump_show(FILE *f, int minidump_fd) {
        return show(f, 0, -1, minidump_fd);
}

int coredump_show(FILE *f, pid_t pid, int coredump_fd) {
        return show(f, pid, coredump_fd, -1);
}

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

        r = write_minicore(&c);
        if (r < 0)
                goto finish;

        *output = c.output;
        *output_size = c.output_size;
        c.output = NULL;

finish:
        context_release(&c);
        return r;
}
