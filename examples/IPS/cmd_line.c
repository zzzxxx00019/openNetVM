/* Copyright @ Github.com/Rsysz */

#include "cmd_line.h"

static inline void
get_arg();

static inline void
help_usage();

static inline void
check_flags();

static inline void
get_parse_errors();

static inline void
FatalError();

static inline void
set_cpu(int id) {
        cpu_set_t mask;

        CPU_ZERO(&mask);
        CPU_SET(id, &mask);
        cout << "Command line thread " << pthread_self() << " Core " << id << endl;
        if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) != 0) {
                cerr << "ERROR: Unable to assign command line thread to specifiy core. Exiting." << endl;
                exit(-1);
        }
}

void *
parse_cmd_line(void *arg) {
        rte_delay_us_block(1000);
        set_cpu(CPU_ID);
        string input;
        while (1) {
                cout << "IPS:/> ";
                cin >> input;
                cout << input << endl;
                // get_arg();
        }
        pthread_exit(NULL);
}
