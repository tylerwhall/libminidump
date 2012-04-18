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

#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>

static void *hang(void *arg) {
        pause();
        return NULL;
}

static void crash(void) {
        int *p = 0;
        *p = 1;
}

static void b(void) {
        crash();
}

static void a(void) {
        b();
}

int main(int argc, char *argv[]) {
        struct rlimit rl;
        char path[PATH_MAX];
        unsigned i;

        /* Create 8 threads to make things more interesting */
        for (i = 0; i < 8; i++) {
                pthread_t t;
                int r;

                r = pthread_create(&t, NULL, hang, NULL);
                if (r != 0) {
                        fprintf(stderr, "failed to create thread: %s", strerror(r));
                        return EXIT_FAILURE;
                }
        }

        if (getrlimit(RLIMIT_CORE, &rl) < 0) {
                fprintf(stderr, "getrlimit() failed: %m");
                return EXIT_FAILURE;
        }

        rl.rlim_cur = 1024UL*1024UL*1024UL;
        if (setrlimit(RLIMIT_CORE, &rl) < 0) {
                fprintf(stderr, "setrlimit() failed: %m");
                return EXIT_FAILURE;
        }

        unlink("core");

        snprintf(path, sizeof(path), "core.%lu", (unsigned long) getpid());
        path[sizeof(path)-1] = 0;

        if (symlink(path, "core") < 0) {
                fprintf(stderr, "symlink() failed: %m");
                return EXIT_FAILURE;
        }

        a();
        return 0;
}
