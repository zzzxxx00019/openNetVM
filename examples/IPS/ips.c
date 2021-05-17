/* Copyright @ Github.com/Rsysz */

#include <pthread.h>
#include "cmd_line.h"
#include "flow_parser.h"
#include "ips_common.h"
#include "parse_rules.h"

#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define NF_TAG "IPS"

extern struct port_info *ports;
struct rte_mempool *pktmbuf_pool;

/* user defined settings */
string patternFile = "rules/snort3-community.rules";
static uint32_t destination = (uint16_t)-1;

// Shared Library
RulesHashMp *Rules;

static int
parse_app_args(int argc, char *argv[], const char *progname) {
        return 0;
}

// Process packet
static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx) {
        struct onvm_nf *nf = nf_local_ctx->nf;
        return 0;
}

// Setup for each thread
void
nf_setup(struct onvm_nf_local_ctx *nf_local_ctx) {
        struct onvm_nf *nf = nf_local_ctx->nf;
        Flow *parser = (Flow *)rte_malloc(NULL, sizeof(Flow), 0);
        new (parser) Flow(*Rules);
        nf->data = (void *)parser;
}

// Main entry point.
int
main(int argc, char **argv) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        int arg_offset;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
        nf_function_table->setup = &nf_setup;

        // Process command line arguments.
        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        argc -= arg_offset;
        argv += arg_offset;

        /* Parse application arguments. */
        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);

        if (!pktmbuf_pool) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        /* Build database from pattern file */
        Rules = databasesFromFile(patternFile.c_str());

        /* Setup cmd interface */
        pthread_t cmd_line;  // pthread variable
        if (pthread_create(&cmd_line, NULL, parse_cmd_line, NULL)) {
                perror("pthread_create error");
        }
        pthread_detach(cmd_line);

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);

        printf("If we reach here, program is ending\n");
        return 0;
}
