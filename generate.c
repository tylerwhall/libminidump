/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "minidump.h"

int main(int argc, char *argv[]) {
        int r;
        int fd = -1;
        unsigned long l;
        char *p = NULL;
        void *minidump = NULL;
        size_t minidump_size = 0;

        if (argc != 2) {
                fprintf(stderr, "Expecting file name as sole argument.\n");
                r = -EINVAL;
                goto fail;
        }

        errno = 0;
        l = strtoul(argv[1], &p, 10);
        if (errno == 0 && p && *p == 0 && l > 0)
                r = minidump_make((pid_t) l, -1, &minidump, &minidump_size);
        else {
                fd = open(argc >= 2 ? argv[1] : "core", O_RDONLY|O_CLOEXEC);
                if (fd < 0) {
                        fprintf(stderr, "Failed to open core dump: %m\n");
                        r = -errno;
                        goto fail;
                }

                r = minidump_make(0, fd, &minidump, &minidump_size);
        }
        if (r < 0) {
                fprintf(stderr, "Failed to generate minidump: %s\n", strerror(-r));
                goto fail;
        }

        fwrite(minidump, 1, minidump_size, stdout);
        fflush(stdout);

        if (ferror(stdout)) {
                fprintf(stderr, "Failed to write minidump: %m\n");
                r = -errno;
                goto fail;
        }

        r = 0;

fail:
        if (fd >= 0)
                close(fd);

        free(minidump);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
