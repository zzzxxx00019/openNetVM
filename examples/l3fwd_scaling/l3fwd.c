/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * scaling.c - Example usage of the provided scaling functionality.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_atomic.h>

#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "l3fwd.h"

#define NF_TAG "l3fwd_scaling"

#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKT_READ_SIZE ((uint16_t)32)
#define LOCAL_EXPERIMENTAL_ETHER 0x88B5
#define DEFAULT_PKT_NUM 128
#define MAX_PKT_NUM NF_QUEUE_RINGSIZE
#define DEFAULT_NUM_CHILDREN 1

static uint16_t destination;
static uint16_t num_children = DEFAULT_NUM_CHILDREN;
static uint8_t use_advanced_rings = 0;
static uint8_t use_shared_core_allocation = 0;

static uint8_t d_addr_bytes[RTE_ETHER_ADDR_LEN];
static uint16_t packet_size = RTE_ETHER_HDR_LEN;
static uint32_t packet_number = DEFAULT_PKT_NUM;

/* For advanced rings scaling */
rte_atomic16_t signal_exit_flag;
uint8_t ONVM_NF_SHARE_CORES;
struct child_spawn_info {
        struct onvm_nf_init_cfg *child_cfg;
        struct onvm_nf *parent;
};

void nf_setup(struct onvm_nf_local_ctx *nf_local_ctx);
void sig_handler(int sig);
void *start_child(void *arg);
int thread_main_loop(struct onvm_nf_local_ctx *nf_local_ctx);

static void run_advanced_rings(int argc, char *argv[]);

/* For l3fwd */
static void l3fwd_initialize_dst(struct state_info *stats);
static void l3fwd_initialize_ports(struct state_info *stats);
struct state_info *stats;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -d <destination> [-a]\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-d DST`: Destination Service ID, functionality depends on mode\n");
        printf(" - `-n NUM_CHILDREN`: Sets the number of children for the NF to spawn\n");
        printf(" - `-c`: Set NF core allocation to shared core\n");
        printf(" - `-a`: Use advanced rings interface instead of default `packet_handler`\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c ;

        while ((c = getopt(argc, argv, "n:p:ac")) != -1) {
                switch (c) {
                        case 'c':
                                use_shared_core_allocation = 1;
                                break;
                        case 'a':
                                use_advanced_rings = 1;
                                break;
                        case 'n':
                                num_children = strtoul(optarg, NULL, 10);
                                break;
                        case '?':
                                usage(progname);
                                if (isprint(optopt))
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

static void
l3fwd_initialize_ports(struct state_info *stats) {
        uint16_t i;
        for (i = 0; i < ports->num_ports; i++) {
                rte_eth_macaddr_get(ports->id[i], &stats->ports_eth_addr[ports->id[i]]);
                printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                        ports->id[i],
                        stats->ports_eth_addr[ports->id[i]].addr_bytes[0],
                        stats->ports_eth_addr[ports->id[i]].addr_bytes[1],
                        stats->ports_eth_addr[ports->id[i]].addr_bytes[2],
                        stats->ports_eth_addr[ports->id[i]].addr_bytes[3],
                        stats->ports_eth_addr[ports->id[i]].addr_bytes[4],
                        stats->ports_eth_addr[ports->id[i]].addr_bytes[5]);
        }
}

static void
l3fwd_initialize_dst(struct state_info *stats) {
        uint16_t i;
        for (i = 0; i < ports->num_ports; i++) {
                stats->dest_eth_addr[ports->id[i]] =
                        RTE_ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)ports->id[i] << 40);
                *(uint64_t *)(stats->val_eth + ports->id[i]) = stats->dest_eth_addr[ports->id[i]];
        }
}

/* Setup each instance */
void
nf_setup(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {        
        uint32_t i;
        struct rte_mempool *pktmbuf_pool;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if (pktmbuf_pool == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        for (i = 0; i < packet_number; ++i) {
                struct onvm_pkt_meta *pmeta;
                struct rte_ether_hdr *ehdr;
                int j;

                struct rte_mbuf *pkt = rte_pktmbuf_alloc(pktmbuf_pool);
                if (pkt == NULL)
                        break;

                /* set up ether header and set new packet size */
                ehdr = (struct rte_ether_hdr *)rte_pktmbuf_append(pkt, packet_size);

                /* Using manager mac addr for source*/
                if (onvm_get_macaddr(0, &ehdr->s_addr) == -1) {
                        onvm_get_fake_macaddr(&ehdr->s_addr);
                }
                for (j = 0; j < RTE_ETHER_ADDR_LEN; ++j) {
                        ehdr->d_addr.addr_bytes[j] = d_addr_bytes[j];
                }
                ehdr->ether_type = LOCAL_EXPERIMENTAL_ETHER;

                pmeta = onvm_get_pkt_meta(pkt);
                pmeta->destination = destination;
                pmeta->action = ONVM_NF_ACTION_TONF;
                pkt->hash.rss = i;
                pkt->port = 0;

                onvm_nflib_return_pkt(nf_local_ctx->nf, pkt);
        }        
}
/*
 * Basic packet handler, just forwards all packets to destination
 */
static int
packet_handler_fwd(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
                   __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        
        struct onvm_nf *nf = nf_local_ctx->nf;
        struct rte_ether_hdr *eth_hdr;
        struct ipv4_hdr *ipv4_hdr;
        uint16_t dst_port;

        eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
        if (onvm_pkt_is_ipv4(pkt)) {
                /* Handle IPv4 headers.*/
                ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,
                                                   sizeof(struct rte_ether_hdr));

#ifdef DO_RFC_1812_CHECKS
                /* Check to make sure the packet is valid (RFC1812) */
                if (is_valid_ipv4_pkt(ipv4_hdr, pkt->pkt_len) < 0) {
                        meta->action = ONVM_NF_ACTION_DROP;
                        packets_dropped++;
                        return 0;
                }
#endif
                if (stats->l3fwd_lpm_on) {
                        dst_port = lpm_get_ipv4_dst_port(ipv4_hdr, pkt->port, stats);
                } else {
                        dst_port = em_get_ipv4_dst_port(pkt, stats);
                }
                if (dst_port >= RTE_MAX_ETHPORTS ||
                        get_initialized_ports(dst_port) == 0)
                        dst_port = pkt->port;

#ifdef DO_RFC_1812_CHECKS
                /* Update time to live and header checksum */
                --(ipv4_hdr->time_to_live);
                ++(ipv4_hdr->hdr_checksum);
#endif
                /* dst addr */
                rte_ether_addr_copy(&ports->neighbor_mac[dst_port], &eth_hdr->d_addr);
                                
                /* src addr */
                rte_ether_addr_copy(&stats->ports_eth_addr[dst_port], &eth_hdr->s_addr);

                stats->port_statistics[dst_port]++;
                
                meta->destination = dst_port;
                meta->action = ONVM_NF_ACTION_OUT;
        } else {
                meta->action = ONVM_NF_ACTION_DROP;
                stats->packets_dropped++;
        }
        return 0;
}

void *
start_child(void *arg) {
        struct onvm_nf_local_ctx *child_local_ctx;
        struct onvm_nf_init_cfg *child_init_cfg;
        struct onvm_nf *parent;
        struct child_spawn_info *spawn_info;

        spawn_info = (struct child_spawn_info *)arg;
        child_init_cfg = spawn_info->child_cfg;
        parent = spawn_info->parent;
        child_local_ctx = onvm_nflib_init_nf_local_ctx();

        if (onvm_nflib_start_nf(child_local_ctx, child_init_cfg) < 0) {
                printf("Failed to spawn child NF\n");
                return NULL;
        }

        /* Keep track of parent for proper termination */
        child_local_ctx->nf->thread_info.parent = parent->instance_id;

        thread_main_loop(child_local_ctx);
        onvm_nflib_stop(child_local_ctx);
        free(spawn_info);
        return NULL;
}

int
thread_main_loop(struct onvm_nf_local_ctx *nf_local_ctx) {
        void *pkts[PKT_READ_SIZE];
        struct onvm_pkt_meta *meta;
        uint16_t i, nb_pkts;
        struct rte_mbuf *pktsTX[PKT_READ_SIZE];
        int tx_batch_size;
        struct rte_ring *rx_ring;
        struct rte_ring *msg_q;
        struct onvm_nf *nf;
        struct onvm_nf_msg *msg;
        struct rte_mempool *nf_msg_pool;

        nf = nf_local_ctx->nf;

        onvm_nflib_nf_ready(nf);
        nf_setup(nf_local_ctx);

        /* Get rings from nflib */
        rx_ring = nf->rx_q;
        msg_q = nf->msg_q;
        nf_msg_pool = rte_mempool_lookup(_NF_MSG_POOL_NAME);

        printf("Process %d handling packets using advanced rings\n", nf->instance_id);
        if (onvm_threading_core_affinitize(nf->thread_info.core) < 0)
                rte_exit(EXIT_FAILURE, "Failed to affinitize to core %d\n", nf->thread_info.core);

        while (!rte_atomic16_read(&signal_exit_flag)) {
                /* Check for a stop message from the manager */
                if (unlikely(rte_ring_count(msg_q) > 0)) {
                        msg = NULL;
                        rte_ring_dequeue(msg_q, (void **)(&msg));
                        if (msg->msg_type == MSG_STOP) {
                                rte_atomic16_set(&signal_exit_flag, 1);
                        } else {
                                printf("Received message %d, ignoring", msg->msg_type);
                        }
                        rte_mempool_put(nf_msg_pool, (void *)msg);
                }

                tx_batch_size = 0;
                /* Dequeue all packets in ring up to max possible */
                nb_pkts = rte_ring_dequeue_burst(rx_ring, pkts, PKT_READ_SIZE, NULL);

                if (unlikely(nb_pkts == 0)) {
                        if (ONVM_NF_SHARE_CORES) {
                                rte_atomic16_set(nf->shared_core.sleep_state, 1);
                                sem_wait(nf->shared_core.nf_mutex);
                        }
                        continue;
                }
                /* Process all the packets */
                for (i = 0; i < nb_pkts; i++) {
                        meta = onvm_get_pkt_meta((struct rte_mbuf *)pkts[i]);
                        packet_handler_fwd((struct rte_mbuf *)pkts[i], meta, nf_local_ctx);
                        pktsTX[tx_batch_size++] = pkts[i];
                }
                /* Process all packet actions */
                onvm_pkt_process_tx_batch(nf->nf_tx_mgr, pktsTX, tx_batch_size, nf);
                
                if (tx_batch_size < PACKET_READ_SIZE) {
                        onvm_pkt_flush_all_nfs(nf->nf_tx_mgr, nf);
                }
        }
        return 0;
}

void sig_handler(int sig) {
        if (sig != SIGINT && sig != SIGTERM)
                return;

        /* Will stop the processing for all spawned threads in advanced rings mode */
        rte_atomic16_set(&signal_exit_flag, 1);
}

static void
run_advanced_rings(int argc, char *argv[]) {
        pthread_t nf_thread[num_children];
        struct onvm_configuration *onvm_config;
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        struct onvm_nf *nf;
        const char *progname = argv[0];
        int arg_offset, i;

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        /* If we're using advanced rings also pass a custom cleanup function,
         * this can be used to handle NF specific (non onvm) cleanup logic */
        rte_atomic16_init(&signal_exit_flag);
        rte_atomic16_set(&signal_exit_flag, 0);
        onvm_nflib_start_signal_handler(nf_local_ctx, sig_handler);
        /* No need to define a function table as adv rings won't run onvm_nflib_run */
        nf_function_table = NULL;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return;
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
        
        /* initialize state_info configuration */
        stats = rte_calloc("state", 1, sizeof(struct state_info), 0);
        stats->l3fwd_lpm_on = 1;
        stats->l3fwd_em_on = 0;
        stats->hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;
        l3fwd_initialize_ports(stats);
        l3fwd_initialize_dst(stats);
        /*
         * Hash flags are valid only for exact macth,
         * reset them to default for longest-prefix match.
         */
        if (stats->l3fwd_lpm_on) {
                if (setup_lpm(stats) < 0) {
                     onvm_nflib_stop(nf_local_ctx);
                     rte_free(stats);
                     rte_exit(EXIT_FAILURE, "Unable to setup LPM\n");
                }
                stats->hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;
                printf("\nLongest prefix match enabled. \n");
        } else {
                if (setup_hash(stats) < 0) {
                     onvm_nflib_stop(nf_local_ctx);
                     rte_free(stats);
                     rte_exit(EXIT_FAILURE, "Unable to setup Hash\n");
                }
                printf("Hash table exact match enabled. \n");
                printf("Hash entry number set to: %d\n", stats->hash_entry_number);
        }        

        nf = nf_local_ctx->nf;

        if (ports->num_ports == 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "No Ethernet ports. Ensure ports binded to dpdk. - bye\n");
        }

        ports->neighbor_mac[0].addr_bytes[0] = 8 ;
        ports->neighbor_mac[0].addr_bytes[1] = 0 ;
        ports->neighbor_mac[0].addr_bytes[2] = 39 ;
        ports->neighbor_mac[0].addr_bytes[3] = 158 ;
        ports->neighbor_mac[0].addr_bytes[4] = 79 ;
        ports->neighbor_mac[0].addr_bytes[5] = 121 ;

        ports->neighbor_mac[1].addr_bytes[0] = 8 ;
        ports->neighbor_mac[1].addr_bytes[1] = 0 ;
        ports->neighbor_mac[1].addr_bytes[2] = 39 ;
        ports->neighbor_mac[1].addr_bytes[3] = 104 ;
        ports->neighbor_mac[1].addr_bytes[4] = 206 ;
        ports->neighbor_mac[1].addr_bytes[5] = 124 ;

        onvm_config = onvm_nflib_get_onvm_config();
        ONVM_NF_SHARE_CORES = onvm_config->flags.ONVM_NF_SHARE_CORES;

        for (i = 0; i < num_children; i++) {
                struct onvm_nf_init_cfg *child_cfg;
                child_cfg = onvm_nflib_init_nf_init_cfg(nf->tag);
                /* Prepare init data for the child */
                child_cfg->service_id = nf->service_id;
                struct child_spawn_info *child_data = malloc(sizeof(struct child_spawn_info));
                child_data->child_cfg = child_cfg;
                child_data->parent = nf;
                /* Increment the children count so that stats are displayed and NF does proper cleanup */
                rte_atomic16_inc(&nf->thread_info.children_cnt);
                pthread_create(&nf_thread[i], NULL, start_child, (void *)child_data);
        }

        thread_main_loop(nf_local_ctx);
        onvm_nflib_stop(nf_local_ctx);

        for (i = 0; i < num_children; i++) {
                pthread_join(nf_thread[i], NULL);
        }
}

int
main(int argc, char *argv[]) {
        run_advanced_rings(argc, argv);
        printf("If we reach here, program is ending\n");
        return 0;       
}

