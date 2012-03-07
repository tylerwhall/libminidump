/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

int main(int argc, char *argv[]) {
        int *p = 0;
        struct rlimit rl;
        char path[PATH_MAX];

        if (getrlimit(RLIMIT_CORE, &rl) < 0) {
                fprintf(stderr, "getrlimit() failed: %m");
                return EXIT_FAILURE;
        }

        rl.rlim_cur = 1024UL*1024UL*1024UL;
        if (setrlimit(RLIMIT_CORE, &rl) < 0) {
                fprintf(stderr, "setrlimit() failed: %m");
                return EXIT_FAILURE;
        }

        unlink("coredump");

        snprintf(path, sizeof(path), "core.%lu", (unsigned long) getpid());
        path[sizeof(path)-1] = 0;

        if (symlink(path, "core") < 0) {
                fprintf(stderr, "symlink() failed: %m");
                return EXIT_FAILURE;
        }

        *p = 1;
        return 0;
}
