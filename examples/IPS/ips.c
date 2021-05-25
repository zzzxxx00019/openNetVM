/* Copyright @ Github.com/Rsysz */

#include <pthread.h>
#include "cmd_line.h"
#include "flow_parser.h"
#include "ips_common.h"
#include "parse_rules.h"

#define NF_TAG "IPS"

extern struct port_info *ports;
struct rte_mempool *pktmbuf_pool;

/* user defined settings */
// string patternFile = "rules/snort3-community.rules";
string logFile = "logs/log.txt";
string patternFile = "rules/snort3-http.rules";
static uint32_t destination = (uint16_t)-1;

// Shared Library
FILE *file;
RulesHashMp *Rules;

static void
usage(const char *prog) {
        cerr << "Usage: " << prog << " ./go.sh [From] -d [To]" << endl;
}

static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;
        while ((c = getopt(argc, argv, "d:w")) != -1) {
                switch (c) {
                        case 'w':  // not need for now
                                break;
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                RTE_LOG(INFO, APP, "destination nf = %d\n", destination);
                                break;
                        case '?':  // Fall through
                        default:
                                usage(progname);
                                return -1;
                }
        }
        return optind;
}

// Process packet
static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx) {
        Flow *parser = (Flow *)nf_local_ctx->nf->data;
        parser->scanFlow(pkt);
        // Add backpressure
#ifdef _BACK_PRESSURE
        if (parser->drop()) {
                struct onvm_flow_entry *flow_entry = NULL;
                int ret = onvm_flow_dir_get_pkt(pkt, &flow_entry);
                if (ret >= 0) {
                        printf("Error happend, flow table can not hit\n");
                        onvm_pkt_set_action(pkt, ONVM_NF_ACTION_DROP, 0);
                } else {
                        ret = onvm_flow_dir_add_pkt(pkt, &flow_entry);
                        if (ret < 0) {
                                printf("add entry fail, drop the pkt\n");
                                onvm_pkt_set_action(pkt, ONVM_NF_ACTION_DROP, 0);
                        }
                        memset(flow_entry, 0, sizeof(struct onvm_flow_entry));
                        flow_entry->sc = onvm_sc_create();
                        onvm_sc_set_entry(flow_entry->sc, 0, ONVM_NF_ACTION_DROP, 0);
                        // onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF, 3);
                        // onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF, 4);
                        onvm_pkt_set_action(pkt, ONVM_NF_ACTION_DROP, 0);
                }
                return 0;
        }
#else
        // Drop
        if (parser->drop()) {
                onvm_pkt_set_action(pkt, ONVM_NF_ACTION_DROP, 0);
                return 0;
        }
#endif
        // Pass
        if (destination != (uint16_t)-1) {
                onvm_pkt_set_action(pkt, ONVM_NF_ACTION_TONF, destination);
        } else {
                if (onvm_pkt_swap_src_mac_addr(pkt, meta->destination, ports) != 0) {
                        RTE_LOG(INFO, APP, "ERROR: Failed to swap src mac with dst mac!\n");
                }
                onvm_pkt_set_action(pkt, ONVM_NF_ACTION_OUT, pkt->port);
        }
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

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_CLONE_POOL_NAME);

        if (!pktmbuf_pool) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        /* Build database from pattern file */
        Rules = databasesFromFile(patternFile.c_str());
        /* Open log file */
        file = fopen(logFile.c_str(), "w");

        /* Setup cmd interface */
        /*
        pthread_t cmd_line;  // pthread variable
        if (pthread_create(&cmd_line, NULL, parse_cmd_line, NULL)) {
                perror("pthread_create error");
        }
        pthread_detach(cmd_line);
        */
        struct onvm_nf *parent_nf = nf_local_ctx->nf;
        parent_nf->handle_rate = 1000000;
#ifdef _BACK_PRESSURE
        /* Map the sdn_ft table */
        onvm_flow_dir_nf_init();
#endif
        onvm_nflib_run(nf_local_ctx);
        onvm_nflib_stop(nf_local_ctx);

        fclose(file);
        printf("If we reach here, program is ending\n");
        return 0;
}
