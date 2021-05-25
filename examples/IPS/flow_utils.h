/* Copyright @ Github.com/Rsysz */

#ifndef FLOW_UTILS_H_
#define FLOW_UTILS_H_

#include "ips_common.h"
#include "parse_rules.h"

extern FILE *file;

// Key for identifying a flow
struct FlowTuple {
        rte_be32_t srcAddr;
        rte_be16_t srcPort;
        rte_be32_t dstAddr;
        rte_be16_t dstPort;

        FlowTuple(const struct rte_ipv4_hdr *ipv4, const rte_be16_t srcPort, const rte_be16_t dstPort)
            : srcAddr(ipv4->src_addr), dstAddr(ipv4->dst_addr), srcPort(srcPort), dstPort(dstPort){};

        bool
        operator==(const FlowTuple &a) const {
                return srcAddr == a.srcAddr && srcPort == a.srcPort && dstAddr == a.dstAddr && dstPort == a.dstPort;
        }
};

// A *very* simple hash function, used when we create an unordered_map
struct FlowTupleHash {
        size_t
        operator()(const FlowTuple &x) const {
                return x.srcAddr ^ x.srcPort ^ x.dstAddr ^ x.dstPort;
        }
};

/* since order is BE, min max reverse */
static inline bool
cmpPort(const vector<uint16_t> &max, const vector<uint16_t> &min, const rte_be16_t &port) {
        if (max[0] == 0)
                return true;
        for (uint16_t i = 0; i < max.size(); i++) {
                uint16_t inPort = port;
                if (max[i] >= inPort && inPort >= min[i])
                        return true;
        }
        return false;
}

static inline bool
cmpAddr(const vector<uint32_t> &ip, const vector<uint32_t> &mask, const rte_be32_t &addr) {
        for (uint16_t i = 0; i < ip.size(); i++) {
                uint32_t inAddr = addr & mask[i];
                if (ip[i] == inAddr)
                        return true;
        }
        return false;
}

inline bool
parseRule(const RuleTuple &rule, const FlowTuple &header) {
        if (cmpAddr(rule.srcIp, rule.srcMask, header.srcAddr) &&
            cmpPort(rule.srcMinPort, rule.srcMaxPort, header.srcPort) &&
            cmpAddr(rule.dstIp, rule.dstMask, header.dstAddr) &&
            cmpPort(rule.dstMinPort, rule.dstMaxPort, header.dstPort)) {
                return true;
        }
        return false;
}

template <class T>
void
logStream(T *parser, const unsigned int id) {
        ProtocolHashMp::const_iterator it = parser->getIter();
        const FlowTuple *hdr = parser->getHeader();

        uint16_t srcPort = rte_be_to_cpu_16(hdr->srcPort);
        uint16_t dstPort = rte_be_to_cpu_16(hdr->dstPort);
        char srcAddr[INET_ADDRSTRLEN];
        char dstAddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hdr->srcAddr, srcAddr, sizeof(srcAddr));
        inet_ntop(AF_INET, &hdr->dstAddr, dstAddr, sizeof(dstAddr));
        Clock clock;

        switch (it->second.info[id].action) {
                case ACTION_REJECT:
                        // rst packet
                case ACTION_DROP:
                        // drop packet
                case ACTION_ALERT:
#ifdef _BACK_PRESSURE
                        parser->setdropFlag();
#endif
                        // need to modify after cmd line done!
                        // cout << "alert!!" << endl;
                        fprintf(file, "===============================================================\n");
                        fprintf(file, "[**]%s[**]\n", it->second.info[id].msg.c_str());
                        fprintf(file, "%s\n", clock.getTime().c_str());
                        fprintf(file, "%s %s:%d -> %s:%d\n", parser->getProto().c_str(), srcAddr, srcPort, dstAddr,
                                dstPort);
                        fprintf(file, "PCRE:\"/%s/%d\"\n", it->second.info[id].pattern.c_str(),
                                it->second.info[id].flags);
                case ACTION_LOG:
                        rte_pktmbuf_dump(file, parser->getPkt(), rte_pktmbuf_pkt_len(parser->getPkt()));
                        break;
                default:
                        parser->setdropFlag();
        }
}

#endif /* FLOW_UTILS_H_ */
