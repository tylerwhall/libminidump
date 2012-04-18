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

#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>
#include <sys/uio.h>

#include "read-process.h"
#include "util.h"

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

int process_attach(struct context *c) {
        DIR* d = NULL;
        int r;

        assert(c);
        assert(CONTEXT_HAVE_PROCESS(c));

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

int process_detach(struct context *c) {
        DIR* d = NULL;
        int r;

        assert(c);
        assert(CONTEXT_HAVE_PROCESS(c));

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

int process_read_memory(struct context *c, unsigned long source, void *destination, size_t length) {
        assert(c);
        assert(CONTEXT_HAVE_PROCESS(c));

        return ptrace_copy(PTRACE_PEEKDATA, c->pid, source, destination, length);
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

static int read_thread_info_ptrace(struct context *c, pid_t tid, struct thread_info *i) {
        int r;
        struct iovec iovec;

        assert(c);
        assert(CONTEXT_HAVE_PROCESS(c));
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

int process_read_threads(struct context *c) {
        DIR *d = NULL;
        int r;

        assert(c);
        assert(CONTEXT_HAVE_PROCESS(c));

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

                r = context_add_thread(c, &i);
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

int process_read_maps(struct context *c) {
        char *p;
        FILE *f;
        int r;

        assert(c);
        assert(CONTEXT_HAVE_PROCESS(c));

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

                r = context_add_mapping(c, start, end, line[j] == 0 ? NULL : line + j);
                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        if (f)
                fclose(f);

        return r;
}

int process_read_fields(struct context *c) {
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
