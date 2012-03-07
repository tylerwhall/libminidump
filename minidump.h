#ifndef foominidumphfoo
#define foominidumphfoo

#include <sys/types.h>

typedef int (*minidump_write_t)(const void *data, size_t length, void *userdata);

/* Pass the PID and/or a seekable fd for the coredump. */

int minidump_make(pid_t pid, int coredump_fd, minidump_write_t cb, void *userdata);

#endif
