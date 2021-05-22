/* Copyright @ Github.com/Rsysz */

#include "cmd_line.h"
#include <pthread.h>

static void
get_arg();

static void
help_usage();

static void
check_flags();

static void
get_parse_errors();

static void
FatalError();

void *
parse_cmd_line(void *) {
        while (1) {
                // get_arg();
        }
        pthread_exit(NULL);
}
