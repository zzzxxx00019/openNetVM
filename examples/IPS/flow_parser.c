#include "flow_parser.h"

Flow::Flow(RulesHashMp &Rules) : tcp_parser(NULL), matchCount(0), dropCount(0) {
        /*
        Rules.at(IP_PROTOCOL_TCP)
        Rules.at(IP_PROTOCOL_UDP)
        Rules.at(IP_PROTOCOL_ICMP)
        */
        hs_error_t err;
        if (Rules.find(IP_PROTOCOL_TCP) != Rules.end()) {
                for (auto &n : Rules.at(IP_PROTOCOL_TCP))
                        err = hs_alloc_scratch(n.second.db, &scratch);
                tcp_parser = new Tcp(Rules.at(IP_PROTOCOL_TCP), &scratch, &matchCount, &dropFlag);
        }
        if (Rules.find(IP_PROTOCOL_UDP) != Rules.end()) {
                for (auto &n : Rules.at(IP_PROTOCOL_UDP))
                        err = hs_alloc_scratch(n.second.db, &scratch);
                udp_parser = new Udp(Rules.at(IP_PROTOCOL_TCP), &scratch, &matchCount, &dropFlag);
        }
        if (Rules.find(IP_PROTOCOL_ICMP) != Rules.end()) {
                for (auto &n : Rules.at(IP_PROTOCOL_ICMP))
                        err = hs_alloc_scratch(n.second.db, &scratch);
                icmp_parser = new Icmp(Rules.at(IP_PROTOCOL_ICMP), &scratch, &matchCount, &dropFlag);
        }
        if (err != HS_SUCCESS) {
                cout << err << endl;
                cerr << "ERROR: could not allocate scratch space. Exiting." << endl;
                exit(-1);
        }
        /* allocate scratch space */
}

Flow::~Flow() {
        delete tcp_parser;
        delete udp_parser;
        delete icmp_parser;
        // delete ip_parser;
}

void
Flow::scanFlow(struct rte_mbuf *pkt) {
        struct rte_ipv4_hdr *ipv4 = onvm_pkt_ipv4_hdr(pkt);
        if (ipv4) {
                dropFlag = false;
                if (ipv4->next_proto_id == IP_PROTOCOL_TCP) {
                        if (tcp_parser)
                                tcp_parser->scanStream(pkt);
                } else if (ipv4->next_proto_id == IP_PROTOCOL_UDP) {
                        if (udp_parser)
                                udp_parser->scanStream(pkt);
                } else if (ipv4->next_proto_id == IP_PROTOCOL_ICMP) {
                        if (icmp_parser)
                                icmp_parser->scanBlock(pkt);
                } else {
                        // scanIp(pkt);
                }
                if (dropFlag)
                        dropCount++;
        }
}
