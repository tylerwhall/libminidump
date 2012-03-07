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

#include "minidump.h"
#include "coredump.h"

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

        ElfW(Ehdr) header;

        minidump_write_t write;
        void *userdata;
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

static int attach_threads(struct context *c, bool b) {
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

                if (ptrace(b ? PTRACE_ATTACH : PTRACE_DETACH, tid, NULL, NULL) < 0) {

                        if (errno == ESRCH)
                                continue;

                        r = -errno;
                        goto finish;
                }

                if (b) {
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

static int read_thread_info_core(struct context *c, pid_t tid, struct thread_info *i) {
        int r;

        assert(c);
        assert(c->fd >= 0);
        assert(tid > 0);
        assert(i);

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

        printf("thread %lu (sp=%0lx)\n", (unsigned long) i->tid, (unsigned long) i->stack_pointer);
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

        assert(c);
        assert(HAVE_COREDUMP(c));

        r = coredump_find_note_segment(c->fd, &c->header, &offset, &length);
        if (r < 0)
                return r;
        if (r == 0)
                return -EIO;

        memset(&i, 0, sizeof(i));
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
                                work_thread_info(c, &i);
                                memset(&i, 0, sizeof(i));
                        }

                        thread_count ++;

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
                           note.n_type == NT_FPREGSET) {

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

        if (thread_count > 0)
                work_thread_info(c, &i);

        return 0;
}

static int foreach_thread(struct context *c) {
        assert(c);

        if (HAVE_COREDUMP(c))
                return foreach_thread_core(c);

        return foreach_thread_ptrace(c);
}

int minidump_make(pid_t pid, int fd, minidump_write_t cb, void *userdata) {
        struct context c;
        int r;

        if (pid <= 0 && fd < 0)
                return -EINVAL;

        if (!cb)
                return -EINVAL;

        if (pid > 0)
                if (kill(pid, 0) < 0)
                        return -errno;

        memset(&c, 0, sizeof(c));

        c.pid = pid;
        c.fd = fd;
        c.write = cb;
        c.userdata = userdata;

        if (HAVE_PROCESS(&c)) {
                r = attach_threads(&c, true);
                if (r < 0)
                        goto finish;
        }

        if (HAVE_COREDUMP(&c)) {
                r = coredump_read_header(fd, &c.header);
                if (r < 0)
                        return r;
        }

        r = foreach_thread(&c);
        if (r < 0)
                goto finish;

        r = 0;

finish:
        if (HAVE_PROCESS(&c))
                attach_threads(&c, false);

        return r;
}
