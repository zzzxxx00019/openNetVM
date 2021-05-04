/*
 * Copyright (c) 2015-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Hyperscan example program 2: pcapscan
 *
 * This example is a very simple packet scanning benchmark. It scans a given
 * PCAP file full of network traffic against a group of regular expressions and
 * returns some coarse performance measurements.  This example provides a quick
 * way to examine the performance achievable on a particular combination of
 * platform, pattern set and input data.
 *
 * Build instructions:
 *
 *     g++ -std=c++11 -O2 -o pcapscan pcapscan.cc $(pkg-config --cflags --libs libhs) -lpcap
 *
 * Usage:
 *
 *     ./pcapscan [-n repeats] <pattern file> <pcap file>
 *
 * We recommend the use of a utility like 'taskset' on multiprocessor hosts to
 * pin execution to a single processor: this will remove processor migration
 * by the scheduler as a source of noise in the results.
 *
 */

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

// We use the BSD primitives throughout as they exist on both BSD and Linux.
#define __FAVOR_BSD
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#ifdef __cplusplus
}
#endif

#include "hyperscan.h"

#include <hs.h>
#include <pcap.h>

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::vector;

#define NF_TAG "IPS"

extern struct port_info *ports;

/* user defined settings */
static uint32_t destination = (uint16_t)-1;
//const char *patternFile = "rules/snort3-community.rules";
const char *patternFile = "/home/itlab/openNetVM/hyperscan/ptn";

/* Hyperscan Module */
hs_database_t *db_streaming;
Hyperscan *module;

// helper function - see end of file
static void
parseFile(const char *filename, vector<string> &patterns, vector<unsigned> &flags, vector<unsigned> &ids);

static hs_database_t *
buildDatabase(const vector<const char *> &expressions, const vector<unsigned> flags, const vector<unsigned> ids,
              unsigned int mode) {
        hs_database_t *db;
        hs_compile_error_t *compileErr;
        hs_error_t err;

        Clock clock;
        clock.start();

        err = hs_compile_multi(expressions.data(), flags.data(), ids.data(), expressions.size(), mode, nullptr, &db,
                               &compileErr);

        clock.stop();

        if (err != HS_SUCCESS) {
                if (compileErr->expression < 0) {
                        // The error does not refer to a particular expression.
                        cerr << "ERROR: " << compileErr->message << endl;
                } else {
                        cerr << "ERROR: Pattern '" << expressions[compileErr->expression]
                             << "' failed compilation with error: " << compileErr->message << endl;
                }
                // As the compileErr pointer points to dynamically allocated memory, if
                // we get an error, we must be sure to release it. This is not
                // necessary when no error is detected.
                hs_free_compile_error(compileErr);
                exit(-1);
        }

        cout << "Hyperscan " << (mode == HS_MODE_STREAM ? "streaming" : "block") << " mode database compiled in "
             << clock.seconds() << " seconds." << endl;

        return db;
}

/**
 * This function will read in the file with the specified name, with an
 * expression per line, ignoring lines starting with '#' and build a Hyperscan
 * database for it.
 */
static void
databasesFromFile(const char *filename, hs_database_t **db_streaming) {
        // hs_compile_multi requires three parallel arrays containing the patterns,
        // flags and ids that we want to work with. To achieve this we use
        // vectors and new entries onto each for each valid line of input from
        // the pattern file.
        vector<string> patterns;
        vector<unsigned> flags;
        vector<unsigned> ids;

        // do the actual file reading and string handling
        parseFile(filename, patterns, flags, ids);

        // Turn our vector of strings into a vector of char*'s to pass in to
        // hs_compile_multi. (This is just using the vector of strings as dynamic
        // storage.)
        vector<const char *> cstrPatterns;
        for (const auto &pattern : patterns) {
                cstrPatterns.push_back(pattern.c_str());
        }

        cout << "Compiling Hyperscan databases with " << patterns.size() << " patterns." << endl;

        *db_streaming = buildDatabase(cstrPatterns, flags, ids, HS_MODE_STREAM);
}

static void
usage(const char *prog) {
        cerr << "Usage: " << prog << " ./go.sh [FromNF] -d [ToNF]" << endl;
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
                                usage(progname);  // Don't want to log :)
                                return -1;
                }
        }
        return optind;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        u_char *packet = rte_pktmbuf_mtod(pkt, u_char *);
	cout << "Init Packet" << endl;
        module->scanStreams(packet);
	cout << "Scan" << endl;
        // Drop
        if (module->matches()) {
                module->clearMatches();
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        }

        if (destination != (uint16_t)-1) {
                meta->action = ONVM_NF_ACTION_TONF;
                meta->destination = destination;
        } else {
                meta->action = ONVM_NF_ACTION_OUT;
                meta->destination = pkt->port;

                if (onvm_pkt_swap_src_mac_addr(pkt, meta->destination, ports) != 0) {
                        RTE_LOG(INFO, APP, "ERROR: Failed to swap src mac with dst mac!\n");
                }
        }
        return 0;
}

void
nf_setup(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        // Read our pattern set in and build Hyperscan databases from it.
        cout << "Pattern file: " << patternFile << endl;
        databasesFromFile(patternFile, &db_streaming);
	
	// Setup Hyperscan engine
	Hyperscan engine(db_streaming);
	module = &engine;

        // Open Stream mode
       	module->openStreams();
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

        onvm_nflib_run(nf_local_ctx);

        // Close Hyperscan databases
        module->closeStreams();
        hs_free_database(db_streaming);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
        /*
        bench.displayStats();

        for (unsigned int i = 0; i < repeatCount; i++) {
                // Open streams.
                clock.start();
                bench.openStreams();
                clock.stop();
                secsStreamingOpenClose += clock.seconds();

                // Scan all our packets in streaming mode.
                clock.start();
                bench.scanStreams();
                clock.stop();
                secsStreamingScan += clock.seconds();

                // Close streams.
                clock.start();
                bench.closeStreams();
                clock.stop();
                secsStreamingOpenClose += clock.seconds();
        }

        // Collect data from streaming mode scans.
        size_t bytes = bench.bytes();
        double tputStreamScanning = (bytes * 8 * repeatCount) / secsStreamingScan;
        double tputStreamOverhead = (bytes * 8 * repeatCount) / (secsStreamingScan + secsStreamingOpenClose);
        size_t matchesStream = bench.matches();
        double matchRateStream = matchesStream / ((bytes * repeatCount) / 1024.0);  // matches per kilobyte

        // Scan all our packets in block mode.
        bench.clearMatches();
        clock.start();
        for (unsigned int i = 0; i < repeatCount; i++) {
                bench.scanBlock();
        }
        clock.stop();
        double secsScanBlock = clock.seconds();

        // Collect data from block mode scans.
        double tputBlockScanning = (bytes * 8 * repeatCount) / secsScanBlock;
        size_t matchesBlock = bench.matches();
        double matchRateBlock = matchesBlock / ((bytes * repeatCount) / 1024.0);  // matches per kilobyte

        cout << endl << "Streaming mode:" << endl << endl;
        cout << "  Total matches: " << matchesStream << endl;
        cout << std::fixed << std::setprecision(4);
        cout << "  Match rate:    " << matchRateStream << " matches/kilobyte" << endl;
        cout << std::fixed << std::setprecision(2);
        cout << "  Throughput (with stream overhead): " << tputStreamOverhead / 1000000 << " megabits/sec" << endl;
        cout << "  Throughput (no stream overhead):   " << tputStreamScanning / 1000000 << " megabits/sec" << endl;

        cout << endl << "Block mode:" << endl << endl;
        cout << "  Total matches: " << matchesBlock << endl;
        cout << std::fixed << std::setprecision(4);
        cout << "  Match rate:    " << matchRateBlock << " matches/kilobyte" << endl;
        cout << std::fixed << std::setprecision(2);
        cout << "  Throughput:    " << tputBlockScanning / 1000000 << " megabits/sec" << endl;

        cout << endl;
        if (bytes < (2 * 1024 * 1024)) {
                cout << endl
                     << "WARNING: Input PCAP file is less than 2MB in size." << endl
                     << "This test may have been too short to calculate accurate results." << endl;
        }

        // Close Hyperscan databases
        hs_free_database(db_streaming);
        hs_free_database(db_block);

        return 0;
        */
}

static unsigned
parseFlags(const string &flagsStr) {
        unsigned flags = 0;
        for (const auto &c : flagsStr) {
                switch (c) {
                        case 'i':
                                flags |= HS_FLAG_CASELESS;
                                break;
                        case 'm':
                                flags |= HS_FLAG_MULTILINE;
                                break;
                        case 's':
                                flags |= HS_FLAG_DOTALL;
                                break;
                        case 'H':
                                flags |= HS_FLAG_SINGLEMATCH;
                                break;
                        case 'V':
                                flags |= HS_FLAG_ALLOWEMPTY;
                                break;
                        case '8':
                                flags |= HS_FLAG_UTF8;
                                break;
                        case 'W':
                                flags |= HS_FLAG_UCP;
                                break;
                        case '\r':  // stray carriage-return
                                break;
                        default:
                                cerr << "Unsupported flag \'" << c << "\'" << endl;
                                exit(-1);
                }
        }
        return flags;
}

static void
parseFile(const char *filename, vector<string> &patterns, vector<unsigned> &flags, vector<unsigned> &ids) {
        ifstream inFile(filename);
        if (!inFile.good()) {
                cerr << "ERROR: Can't open pattern file \"" << filename << "\"" << endl;
                exit(-1);
        }

        for (unsigned i = 1; !inFile.eof(); ++i) {
                string line;
                getline(inFile, line);

                // if line is empty, or a comment, we can skip it
                if (line.empty() || line[0] == '#') {
                        continue;
                }

                // otherwise, it should be ID:PCRE, e.g.
                //  10001:/foobar/is

                size_t colonIdx = line.find_first_of(':');
                if (colonIdx == string::npos) {
                        cerr << "ERROR: Could not parse line " << i << endl;
                        exit(-1);
                }

                // we should have an unsigned int as an ID, before the colon
                unsigned id = std::stoi(line.substr(0, colonIdx).c_str());

                // rest of the expression is the PCRE
                const string expr(line.substr(colonIdx + 1));

                size_t flagsStart = expr.find_last_of('/');
                if (flagsStart == string::npos) {
                        cerr << "ERROR: no trailing '/' char" << endl;
                        exit(-1);
                }

                string pcre(expr.substr(1, flagsStart - 1));
                string flagsStr(expr.substr(flagsStart + 1, expr.size() - flagsStart));
                unsigned flag = parseFlags(flagsStr);

                patterns.push_back(pcre);
                flags.push_back(flag);
                ids.push_back(id);
        }
}
