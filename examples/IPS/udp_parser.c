#include "udp_parser.h"

Udp::Udp(ProtocolHashMp &rules, hs_scratch_t **scratch, size_t *matchCount, bool *dropFlag)
    : scratch(scratch), udp_rules(&rules), matchCount(matchCount), dropFlag(dropFlag) {
        stream_map.resize(rules.size());
        streams.reserve(rules.size());
        for (auto &r : rules) {
                vector<hs_stream_t *> stream;
                stream.resize(UDP_FLOW_NUMS);
                for (auto &n : stream) {
                        hs_error_t err = hs_open_stream(r.second.db, 0, &n);
                        if (err != HS_SUCCESS) {
                                cerr << "ERROR: Unable to open udp_stream. Exiting." << endl;
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
        Udp *parser = (Udp *)ctx;
        logStream(parser, id);
        return 0;  // continue matching, not 0 mean terminated
}

void
Udp::scanStream(const struct rte_mbuf *pkt) {
        const struct rte_ipv4_hdr *ipv4 =
            (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr));
        const struct rte_udp_hdr *udp =
            (struct rte_udp_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_ipv4_hdr));
        const char *payload = rte_pktmbuf_mtod(pkt, char *) + sizeof(struct rte_ether_hdr) +
                              sizeof(struct rte_ipv4_hdr) + sizeof(rte_udp_hdr);

        const size_t length = rte_be_to_cpu_16(udp->dgram_len) - sizeof(rte_udp_hdr);
        const FlowTuple header(ipv4, udp->src_port, udp->dst_port);
        hs_error_t err;

        packet = pkt;
        hdr = &header;
        if (flow_map.find(header) == flow_map.end()) {
                int index = 0;
                for (it = udp_rules->begin(); it != udp_rules->end(); ++it, ++index) {
                        if (parseRule(it->first, header)) {
                                flow_map[header].push_back(index);
                        }
                }
        }
        for (auto &index : flow_map.at(header)) {
                it = next(udp_rules->begin(), index);
                stream_map[index].insert(make_pair(header, stream_map[index].size()));
                err = hs_scan_stream(streams[index][stream_map[index].size()], payload, length, 0, *scratch, onMatch,
                                     this);
                if (err != HS_SUCCESS) {
                        cerr << "ERROR: Unable to scan udp packet. Exiting." << endl;
                        exit(-1);
                }
        }
}
