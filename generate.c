/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

#include "coredump.h"
#include "minidump.h"

static int write_cb(const void *data, size_t length, void *userdata) {
        fwrite(data, 1, length, userdata);

        return 0;
}

int main(int argc, char *argv[]) {
        int r;
        int fd = -1;
        unsigned long l;
        char *p = NULL;
        ElfW(Ehdr) header;
        ElfW(Phdr) segment;

        if (argc != 2) {
                fprintf(stderr, "Expecting file name as sole argument.\n");
                return EXIT_FAILURE;
        }

        errno = 0;
        l = strtoul(argv[1], &p, 10);
        if (errno == 0 && p && *p == 0 && l > 0)
                r = minidump_make((pid_t) l, -1, write_cb, stdout);
        else {
                fd = open(argc >= 2 ? argv[1] : "core", O_RDONLY|O_CLOEXEC);

                if (fd < 0) {
                        fprintf(stderr, "Failed to open core dump: %m\n");
                        r = -errno;
                        goto fail;
                }

                r = minidump_make(0, fd, write_cb, stdout);
        }

        if (r < 0) {
                fprintf(stderr, "Failed to generate minidump: %s\n", strerror(-r));
                goto fail;
        }

        /* r = coredump_read_header(fd, &header); */
        /* if (r < 0) { */
        /*         fprintf(stderr, "Failed to read ELF header: %s\n", strerror(-r)); */
        /*         goto fail; */
        /* } */

        /* printf("segments = %lu\n", (unsigned long) header.e_phnum); */

        /* for (i = 0; i < header.e_phnum; i++) { */

        /*         r = coredump_read_segment_header(fd, &header, i, &segment); */
        /*         if (r < 0) { */
        /*                 fprintf(stderr, "Failed to read ELF segment: %s\n", strerror(-r)); */
        /*                 goto fail; */
        /*         } */

        /*         printf("segment type = %lu\n", (unsigned long) segment.p_type); */
        /* } */


fail:
        if (fd >= 0)
                close(fd);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
