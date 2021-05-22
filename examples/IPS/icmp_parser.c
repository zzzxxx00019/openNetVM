#include "icmp_parser.h"

Icmp::Icmp(ProtocolHashMp &rules, hs_scratch_t **scratch, size_t *matchCount, bool *dropFlag)
    : scratch(scratch), icmp_rules(&rules), matchCount(matchCount), dropFlag(dropFlag) {
}

// Match event handler: called every time Hyperscan finds a match.
static int
onMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *ctx) {
        // Our context points to a size_t storing the match count
        Icmp *parser = (Icmp *)ctx;
        ProtocolHashMp::const_iterator it = parser->getIter();
        const FlowTuple *hdr = parser->getHeader();
        parser->setdropFlag();

        char srcAddr[INET_ADDRSTRLEN];
        char dstAddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hdr->srcAddr, srcAddr, sizeof(srcAddr));
        inet_ntop(AF_INET, &hdr->dstAddr, dstAddr, sizeof(dstAddr));
        clog << "WRANING!!" << endl;
        clog << it->second.info[id].action << " " << srcAddr << " -> " << dstAddr << endl;
        clog << it->second.info[id].msg << endl;
        return 0;  // continue matching
}

void
Icmp::scanBlock(const struct rte_mbuf *pkt) {
        const struct rte_ipv4_hdr *ipv4 =
            (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr));
        const struct rte_icmp_hdr *icmp =
            (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) +
                                    sizeof(struct rte_ipv4_hdr));
        const char *payload = rte_pktmbuf_mtod(pkt, char *) + sizeof(struct rte_ether_hdr) +
                              sizeof(struct rte_ipv4_hdr) + sizeof(rte_icmp_hdr);

        const size_t length = rte_be_to_cpu_16(ipv4->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(rte_icmp_hdr);
        const FlowTuple header(ipv4, 0, 0);
        hs_error_t err;

        hdr = &header;
        for (it = icmp_rules->begin(); it != icmp_rules->end(); ++it) {
                if (parseRule(it->first, header)) {
                        err = hs_scan(it->second.db, payload, length, 0, *scratch, onMatch, this);
                        if (err != HS_SUCCESS) {
                                cerr << "ERROR: Unable to scan tcp packet. Exiting." << endl;
                                exit(-1);
                        }
                }
        }
}
