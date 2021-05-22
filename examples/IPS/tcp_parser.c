#include "tcp_parser.h"

Tcp::Tcp(ProtocolHashMp &rules, hs_scratch_t **scratch, size_t *matchCount, bool *dropFlag)
    : scratch(scratch), tcp_rules(&rules), matchCount(matchCount), dropFlag(dropFlag) {
        stream_map.resize(rules.size());
        streams.reserve(rules.size());
        for (auto &r : rules) {
                vector<hs_stream_t *> stream;
                stream.resize(TCP_FLOW_NUMS);
                for (auto &n : stream) {
                        hs_error_t err = hs_open_stream(r.second.db, 0, &n);
                        if (err != HS_SUCCESS) {
                                cerr << "ERROR: Unable to open tcp_stream. Exiting." << endl;
                                exit(-1);
                        }
                }
                streams.push_back(stream);
        }
}

// Match event handler: called every time Hyperscan finds a match.
static int
onMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *ctx) {
        // Our context points to a size_t storing the match count
        Tcp *parser = (Tcp *)ctx;
        logStream(parser, id);
        return 0;  // continue matching, not 0 mean terminated
}

void
Tcp::scanStream(const struct rte_mbuf *pkt) {
        const struct rte_ipv4_hdr *ipv4 =
            (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr));
        const struct rte_tcp_hdr *tcp =
            (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_ipv4_hdr));
        const char *payload = rte_pktmbuf_mtod(pkt, char *) + sizeof(struct rte_ether_hdr) +
                              sizeof(struct rte_ipv4_hdr) + sizeof(rte_tcp_hdr);

        const size_t length = rte_be_to_cpu_16(ipv4->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(rte_tcp_hdr);
        const FlowTuple header(ipv4, tcp->src_port, tcp->dst_port);
        hs_error_t err;

        hdr = &header;
        if (flow_table.find(header) == flow_table.end()) {
                int index = 0;
                for (it = tcp_rules->begin(); it != tcp_rules->end(); ++it, ++index) {
                        if (parseRule(it->first, header)) {
                                flow_table[header].push_back(index);
                        }
                }
        }
        for (auto &index : flow_table.at(header)) {
                it = next(tcp_rules->begin(), index);
                stream_map[index].insert(make_pair(header, stream_map[index].size()));
                err = hs_scan_stream(streams[index][stream_map[index].size()], payload, length, 0, *scratch, onMatch,
                                     this);
                if (err != HS_SUCCESS) {
                        cerr << "ERROR: Unable to scan tcp packet. Exiting." << endl;
                        exit(-1);
                }
        }
        /*
        for (it = tcp_rules->begin(); it != tcp_rules->end(); ++it, ++index) {
                if (parseRule(it->first, header)) {
                        // cout << "Matching..." << endl;
                        stream_map[index].insert(make_pair(header, stream_map[index].size()));
                        err = hs_scan_stream(streams[index][stream_map[index].size()], payload, length, 0, *scratch,
                                             onMatch, this);
                        if (err != HS_SUCCESS || err != HS_SCAN_TERMINATED) {
                                cerr << "ERROR: Unable to scan tcp packet. Exiting." << endl;
                                exit(-1);
                        }
                }
        }
        */
}
