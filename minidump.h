#ifndef foominidumphfoo
#define foominidumphfoo

#include <sys/types.h>

/* Pass the PID and/or a seekable fd for the coredump. */

int minidump_make(pid_t pid, int coredump_fd, void **minidump, size_t *size);

#endif
