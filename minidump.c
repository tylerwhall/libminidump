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

#include "coredump.h"
#include "format.h"
#include "minidump.h"

#define MINIDUMP_STREAMS_MAX 17

struct thread_info {
        pid_t tid;
        unsigned long stack_pointer;

        struct elf_prstatus prstatus;         /* only available on coredumps */
        siginfo_t siginfo;                    /* only available on ptrace */
        struct user user;                     /* only available on ptrace */

        struct user_regs_struct regs;
        struct user_fpregs_struct fpregs;
#ifdef __i386
        struct user_fpxregs_struct fpxregs;
#endif
};

struct context {
        pid_t pid;
        int fd;

        ElfW(Ehdr) header;                    /* only available on coredumps */
        struct elf_prpsinfo prpsinfo;         /* only available on coredumps */
        ElfW(auxv_t) *auxv;
        size_t auxv_size;

        void *minidump;
        size_t minidump_size;
        size_t minidump_allocated;
        size_t ninidump_offset;

        struct minidump_directory minidump_directory[MINIDUMP_STREAMS_MAX];
        uint32_t minidump_n_streams;
};

#define HAVE_PROCESS(c) ((c)->pid > 0)
#define HAVE_COREDUMP(c) ((c)->fd >= 0)

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

static int read_memory(struct context *c, unsigned long source, void *destination, size_t length) {
        assert(c);
        assert(destination);
        assert(length > 0);

        if (HAVE_COREDUMP(c))
                return coredump_read_memory(c->fd, &c->header, source, destination, length);

        return ptrace_copy(PTRACE_PEEKDATA, c->pid, source, destination, length);
}

static int proc_read_auxv(struct context *c) {
        int r;
        char *p;

        assert(c);

        if (asprintf(&p, "/proc/%lu/auxv", (unsigned long) c->pid) < 0)
                return -ENOMEM;

        r = read_full_file(p, (void**) &c->auxv, &c->auxv_size);
        free(p);

        return r;
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

        return 0;
}

static int work_thread_info(struct context *c, struct thread_info *i) {
        assert(c);
        assert(i);

#if defined(__i386)
        i->stack_pointer = (unsigned long) i->regs.esp;
#elif defined(__x86_64)
        i->stack_pointer = (unsigned long) i->regs.rsp;
#else
#error "I need porting to your architecture"
#endif

        fprintf(stderr, "thread %lu (sp=%0lx)\n", (unsigned long) i->tid, (unsigned long) i->stack_pointer);
        return 0;
}

static int foreach_thread_ptrace(struct context *c) {
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

                r = work_thread_info(c, &i);
                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        if (d)
                closedir(d);

        return r;
}

static int foreach_thread_core(struct context *c) {
        off_t offset, length;
        int r;
        struct thread_info i;
        unsigned thread_count;
        bool found_prpsinfo = false, found_auxv = false;
        bool found_prstatus = false, found_fpregset = false;

        assert(c);
        assert(HAVE_COREDUMP(c));

        r = coredump_find_note_segment(c->fd, &c->header, &offset, &length);
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

                r = coredump_next_note(c->fd, &offset, &length, &note, &name_offset, &descriptor_offset);
                if (r < 0)
                        return r;

                if (note.n_namesz >= sizeof(name))
                        continue;

                l = pread(c->fd, name, note.n_namesz, name_offset);
                if (l < 0)
                        return -errno;
                if (l != note.n_namesz)
                        return -EIO;

                name[l] = 0;

                if (strcmp(name, "CORE") == 0 &&
                    note.n_type == NT_PRSTATUS) {

                        if (thread_count > 0) {
                                if (!found_prstatus || !found_fpregset)
                                        return -EIO;

                                work_thread_info(c, &i);
                        }

                        memset(&i, 0, sizeof(i));
                        thread_count ++;
                        found_prstatus = true;
                        found_fpregset = false;

                        if (note.n_descsz != sizeof(i.prstatus))
                                return -EIO;

                        l = pread(c->fd, &i.prstatus, sizeof(i.prstatus), descriptor_offset);
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

                        l = pread(c->fd, &c->prpsinfo, sizeof(c->prpsinfo), descriptor_offset);
                        if (l < 0)
                                return -errno;
                        if (l != sizeof(c->prpsinfo))
                                return -EIO;

                } else if (strcmp(name, "CORE") == 0 &&
                           note.n_type == NT_AUXV) {

                        if (found_auxv)
                                return -EIO;

                        found_auxv = true;

                        c->auxv = malloc(note.n_descsz);
                        if (!c->auxv)
                                return -ENOMEM;

                        l = pread(c->fd, c->auxv, note.n_descsz, descriptor_offset);
                        if (l < 0)
                                return -errno;
                        if (l != note.n_descsz)
                                return -EIO;

                        c->auxv_size = note.n_descsz;

                } else if (strcmp(name, "CORE") == 0 &&
                           note.n_type == NT_FPREGSET) {

                        if (found_fpregset)
                                return -EIO;

                        found_fpregset = true;

                        if (note.n_descsz != sizeof(i.fpregs))
                                return -EIO;

                        l = pread(c->fd, &i.fpregs, sizeof(i.fpregs), descriptor_offset);
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
                }
        }

        if (thread_count > 0) {
                if (!found_prstatus || !found_fpregset)
                        return -EIO;

                work_thread_info(c, &i);
        }

        if (!found_prpsinfo || !found_auxv)
                return -EIO;

        return 0;
}

static int foreach_thread(struct context *c) {
        assert(c);

        if (HAVE_COREDUMP(c))
                return foreach_thread_core(c);

        return foreach_thread_ptrace(c);
}

static int append_bytes(struct context *c, const void *data, size_t bytes, size_t *offset) {
        void *p;

        assert(c);

        if (c->minidump_size + bytes > c->minidump_allocated) {
                size_t l;

                l = (c->minidump_size + bytes) * 2;
                if (l < 4096)
                        l = 4096;

                p = realloc(c->minidump, l);
                if (!p)
                        return -ENOMEM;

                c->minidump = p;
                c->minidump_allocated = l;
        }

        p = (uint8_t*) c->minidump + c->minidump_size;
        memcpy(p, data, bytes);

        if (offset)
                *offset = c->minidump_size;

        c->minidump_size += bytes;
        return 0;
}

static int append_directory(struct context *c, uint32_t stream_type, size_t offset, size_t size) {
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

static int write_blob_stream(struct context *c, uint32_t stream_type, const void *buffer, size_t size) {
        int r;
        size_t offset;

        assert(c);
        assert(buffer);
        assert(size > 0);

        r = append_bytes(c, buffer, size, &offset);
        if (r < 0)
                return r;

        r = append_directory(c, stream_type, offset, size);
        if (r < 0)
                return r;

        return r;
}

static int write_file_stream(struct context *c, uint32_t stream_type, const char *path) {
        int r;
        char *buffer = NULL;
        size_t size = 0;

        assert(c);
        assert(path);

        r = read_full_file(path, (void**) &buffer, &size);
        if (r < 0)
                return r;

        r = write_blob_stream(c, stream_type, buffer, size);
        free(buffer);

        return r;
}

static int write_proc_file_stream(struct context *c, uint32_t stream_type, const char *fname) {
        char *p;
        int r;

        assert(c);

        if (!HAVE_PROCESS(c))
                return 0;

        if (asprintf(&p, "/proc/%lu/%s", (unsigned long) c->pid, fname) < 0)
                return -ENOMEM;

        r = write_file_stream(c, stream_type, p);
        free(p);

        return r;
}

static int write_proc_readlink_stream(struct context *c, uint32_t stream_type, const char *fname) {
        char *p;
        int r;
        char path[PATH_MAX];

        assert(c);

        if (!HAVE_PROCESS(c))
                return 0;

        if (asprintf(&p, "/proc/%lu/%s", (unsigned long) c->pid, fname) < 0)
                return -ENOMEM;

        r = readlink(p, path, sizeof(path));
        free(p);

        if (r < 0)
                return -errno;
        if (r == sizeof(path))
                return -E2BIG;

        return write_blob_stream(c, stream_type, path, r);
}

static int write_directory(struct context *c) {
        size_t offset;
        struct minidump_header *h;
        int r;

        assert(c);

        r = append_bytes(c, c->minidump_directory, sizeof(struct minidump_directory) * c->minidump_n_streams, &offset);
        if (r < 0)
                return r;

        /* The beginning of the minidump is definitely aligned, so we
         * access it directly and patch in the directory data. */
        h = c->minidump;
        h->number_of_streams = htole32(c->minidump_n_streams);
        h->stream_directory_rva = htole32((uint32_t) offset);

        return 0;
}

static int write_dump(struct context *c) {
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

        r = foreach_thread(c);
        if (r < 0)
                return r;

        /* write thread list */
        /* write mappings */
        /* write memory list */
        /* write exception */
        /* write system info */
        /* write rpm info */
        /* write debug */

        /* This is a Ubuntuism, but Google is doing this, hence let's stay compatible here */
        write_file_stream(c, MINIDUMP_LINUX_LSB_RELEASE, "/etc/lsb-release");
        /* It's much nicer to write /etc/os-release instead, which is more widely supported */
        write_file_stream(c, MINIDUMP_LINUX_OS_RELEASE, "/etc/os-release");

        write_file_stream(c, MINIDUMP_LINUX_CPU_INFO, "/proc/cpuinfo");

        write_proc_file_stream(c, MINIDUMP_LINUX_PROC_STATUS, "status");
        write_proc_file_stream(c, MINIDUMP_LINUX_CMD_LINE, "cmdline");
        write_proc_file_stream(c, MINIDUMP_LINUX_ENVIRON, "environ");
        write_proc_file_stream(c, MINIDUMP_LINUX_COMM, "comm");
        write_proc_readlink_stream(c, MINIDUMP_LINUX_EXE, "exe");

        r = write_proc_file_stream(c, MINIDUMP_LINUX_MAPS, "maps");
        if (r < 0)
                return r;

        if (c->auxv) {
                r = write_blob_stream(c, MINIDUMP_LINUX_AUXV, c->auxv, c->auxv_size);
                if (r < 0)
                        return r;
        }

        if (HAVE_COREDUMP(c)) {
                r = write_blob_stream(c, MINIDUMP_LINUX_PRPSINFO, &c->prpsinfo, sizeof(c->prpsinfo));
                if (r < 0)
                        return r;

                r = write_blob_stream(c, MINIDUMP_LINUX_CORE_EHDR, &c->header, sizeof(c->header));
                if (r < 0)
                        return r;
        }

        r = write_directory(c);
        if (r < 0)
                return r;

        return 0;
}

int minidump_make(pid_t pid, int fd, void **minidump, size_t *size) {
        struct context c;
        int r;

        if (pid <= 0 && fd < 0)
                return -EINVAL;

        if (!minidump)
                return -EINVAL;

        if (!size)
                return -EINVAL;

        if (pid > 0)
                if (kill(pid, 0) < 0)
                        return -errno;

        memset(&c, 0, sizeof(c));

        c.pid = pid;
        c.fd = fd;

        if (HAVE_PROCESS(&c)) {
                r = attach_threads(&c);
                if (r < 0)
                        goto finish;

                r = proc_read_auxv(&c);
                if (r < 0)
                        goto finish;
        }

        if (HAVE_COREDUMP(&c)) {
                r = coredump_read_header(fd, &c.header);
                if (r < 0)
                        return r;
        }

        r = write_dump(&c);
        if (r < 0)
                goto finish;


        *minidump = c.minidump;
        *size = c.minidump_size;

        c.minidump = NULL;

        r = 0;

finish:
        if (HAVE_PROCESS(&c))
                detach_threads(&c);

        free(c.minidump);
        free(c.auxv);

        return r;
}
