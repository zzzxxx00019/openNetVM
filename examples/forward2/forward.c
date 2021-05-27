#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define PKTMBUF_CLONE_POOL_NAME "Mproc_pktmbuf_clone_pool"
#define NF_TAG "parallel_fwd_2"

static uint32_t print_delay = 10000000;
static uint64_t last_cycle;
static uint64_t cur_cycles;
static uint8_t destination = 0;

struct rte_mempool *pktmbuf_pool;

extern struct port_info *ports;

static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt(argc, argv, "d:p")) != -1) {
                switch (c) {
			case 'd':
				destination = strtoul(optarg, NULL, 10);
				RTE_LOG(INFO, APP, "Sending packets to service ID %d\n",destination);
				break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                RTE_LOG(INFO, APP, "print_delay = %d\n", print_delay);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }
        return optind;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        (void) meta;

	static uint64_t counter = 0;
	static uint64_t start, end, cost, latency;
	start = rte_get_timer_cycles();

	while (onvm_pkt_check_meta_bit(meta->flags, PKT_META_PAYLOAD_READ));
	meta->flags = onvm_pkt_clear_meta_bit(meta->flags, PKT_META_PAYLOAD_WRITE);

	rte_delay_us_block(2);
	onvm_pkt_set_action(pkt, ONVM_NF_ACTION_TONF, destination);

	end = rte_get_timer_cycles();
	cost += (end - start);
	if ((++counter) == 10000000) {
		latency = (cost * 100) / rte_get_timer_hz();
		printf("cost %ld cycles - latency = %ld nanosecond\n", cost, latency);
		cost = 0;
		counter = 0;
	}

        return 0;
}

int
main(int argc, char *argv[]) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        int arg_offset;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;

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

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        cur_cycles = rte_get_tsc_cycles();
        last_cycle = rte_get_tsc_cycles();

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_CLONE_POOL_NAME);	
	if (pktmbuf_pool == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

	struct onvm_nf *parent_nf = nf_local_ctx->nf;
	parent_nf->handle_rate = 350000;
	onvm_flow_dir_nf_init();

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
