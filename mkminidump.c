/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include "minidump.h"

static char *arg_source = NULL;
static pid_t arg_pid = 0;
static char *arg_minidump = NULL;
static char *arg_minicore = NULL;

static int help(void) {

        printf("%s [OPTIONS...] [FILE]\n\n"
               "Generate, convert or show contents of a minidump or minicore/coredump.\n\n"
               "  -h --help             Show this help\n"
               "  -p --pid=PID          Generate from PID\n"
               "  -d --minidump[=FILE]  Generate a minidump\n"
               "  -c --minicore[=FILE]  Generate a minicore\n\n"
               "Examples:\n\n"
               "    Generate a minidump from PID 4711\n"
               "    # mkminidump --pid=4711 --minidump=foobar.dmp\n\n"
               "    Generate a minicore from PID 815\n"
               "    # mkminidump --pid=815 --minicore=foobar.core\n\n"
               "    Convert a coredump to a minidump\n"
               "    # mkminidump foobar.core --minidump=foobar.dmp\n\n"
               "    Convert a minidump to a minicore\n"
               "    # mkminidump foobar.dmp --minicore=foobar.core\n\n"
               "    Show contents of a minidump\n"
               "    # mkminidump fooobar.dmp\n\n"
               "    Show contents of a coredump\n"
               "    # mkminidump foobar.core\n\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "pid",       required_argument, NULL, 'p'           },
                { "minidump",  optional_argument, NULL, 'd'           },
                { "minicore",  optional_argument, NULL, 'c'           },
                { NULL,        0,                 NULL, 0             }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp:d::c::", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case 'p': {
                        unsigned long ul;
                        char *e;

                        errno = 0;
                        ul = strtoul(optarg, &e, 10);
                        if (errno != 0 || !e || *e || ul <= 0) {
                                fprintf(stderr, "Failed to parse PID argument.\n");
                                return -EINVAL;
                        }

                        arg_pid = (pid_t) ul;
                        break;
                }

                case 'd':
                        arg_minidump = optarg ? optarg : "-";
                        break;

                case 'c':
                        arg_minicore = optarg ? optarg : "-";
                        break;

                case '?':
                        return -EINVAL;

                default:
                        fprintf(stderr, "Unknown option code %c\n", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc && !arg_pid) {
                /* No source arguments specified at all */
                help();
                return 0;
        }

        if (argc > optind+1) {
                /* More than one source argument specified */
                help();
                return -EINVAL;
        }

        if (optind < argc)
                arg_source = argv[optind];

        return 1;
}

static int output_and_free(const char *path, void **buffer, size_t *buffer_size) {
        FILE *f, *toclose = NULL;
        int r = 0;

        assert(buffer);
        assert(*buffer);
        assert(buffer_size);
        assert(*buffer_size > 0);

        if (!path || strcmp(path, "-") == 0)
                f = stdout;
        else {
                f = fopen(path, "we");
                if (!f) {
                        r = -errno;
                        fprintf(stderr, "Failed to write output: %m\n");
                        goto finish;
                }
                toclose = f;
        }

        fwrite(*buffer, 1, *buffer_size, f);
        fflush(f);

        if (ferror(f)) {
                r = -errno;
                fprintf(stderr, "Failed to write output: %m\n");
                goto finish;
        }

        free(*buffer);
        *buffer = NULL;
        *buffer_size = 0;

finish:
        if (toclose)
                fclose(toclose);

        return r;
}

int main(int argc, char *argv[]) {
        int r;
        int fd = -1;
        void *buffer = NULL;
        size_t buffer_size = 0;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        if (arg_source) {
                if (strcmp(arg_source, "-") == 0)
                        fd = STDIN_FILENO;
                else {
                        fd = open(arg_source, O_RDONLY|O_CLOEXEC);

                        if (fd < 0) {
                                r = -errno;
                                fprintf(stderr, "Failed to open source file: %m\n");
                                goto finish;
                        }
                }
        }

        if (arg_pid > 0) {
                /* If a PID specified, the fd definitely refers to a
                 * process or a coredump of some kind */

                if (arg_minidump) {
                        r = minidump_make(arg_pid, fd, &buffer, &buffer_size);
                        if (r < 0) {
                                fprintf(stderr, "Failed to generate minidump: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = output_and_free(arg_minidump, &buffer, &buffer_size);
                        if (r < 0)
                                goto finish;
                }

                if (arg_minicore) {
                        r = minicore_make(arg_pid, fd, &buffer, &buffer_size);
                        if (r < 0) {
                                fprintf(stderr, "Failed to generate minicore: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = output_and_free(arg_minidump, &buffer, &buffer_size);
                        if (r < 0)
                                goto finish;
                }

                if (!arg_minidump && !arg_minicore) {
                        r = coredump_show(stdout, arg_pid, fd);
                        if (r < 0) {
                                fprintf(stderr, "Failed to decode coredump: %s\n", strerror(-r));
                                goto finish;
                        }
                }
        } else {
                assert(fd >= 0);

                /* No PID specified, so let's guess by the output
                 * parameters */

                if (arg_minicore && arg_minidump) {
                        fprintf(stderr, "Can't convert file into its own type.\n");
                        r = -EINVAL;
                        goto finish;
                }

                if (arg_minicore) {
                        r = minidump_to_minicore(fd, &buffer, &buffer_size);
                        if (r < 0) {
                                fprintf(stderr, "Failed to convert minidump: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = output_and_free(arg_minicore, &buffer, &buffer_size);
                        if (r < 0)
                                goto finish;
                }

                if (arg_minidump) {
                        r = minidump_make(0, fd, &buffer, &buffer_size);
                        if (r < 0) {
                                fprintf(stderr, "Failed to convert coredump: %s\n", strerror(-r));
                                goto finish;
                        }

                        r = output_and_free(arg_minidump, &buffer, &buffer_size);
                        if (r < 0)
                                goto finish;
                }

                if (!arg_minidump && !arg_minicore) {

                        r = minidump_show(stdout, fd);
                        if (r == -EINVAL)
                                r = coredump_show(stdout, 0, fd);

                        if (r < 0) {
                                fprintf(stderr, "Failed to decode coredump or minidump: %s\n", strerror(-r));
                                goto finish;
                        }
                }
        }

        r = 0;

finish:
        if (fd > 2)
                close(fd);

        free(buffer);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
