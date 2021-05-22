/* Copyright @ Github.com/Rsysz */

#ifndef ICMP_PARSER_H_
#define ICMP_PARSER_H_

#include "flow_utils.h"
#include "ips_common.h"
#include "parse_rules.h"

/*rte_be32_t 	src_addr
 *rte_be16_t 	src_port
 *rte_be32_t 	dst_addr
 *rte_be16_t 	dst_port
 */

class Icmp {
       private:
        // Tcp Rule Databases
        ProtocolHashMp *icmp_rules;
        // Hyperscan temporary scratch space
        hs_scratch_t **scratch;

        const string protocol = "ICMP";
        const FlowTuple *hdr;
        size_t *matchCount;
        bool *dropFlag;
        ProtocolHashMp::const_iterator it;

       public:
        Icmp(ProtocolHashMp &rules, hs_scratch_t **scratch, size_t *matchCount, bool *dropFlag);
        ~Icmp(){};

        inline ProtocolHashMp::const_iterator
        getIter() {
                return it;
        }

        inline const FlowTuple *
        getHeader() {
                return hdr;
        }

        inline const string
        getProto() {
                return protocol;
        }

        inline void
        setdropFlag() {
                *dropFlag = true;
        }

        void
        scanBlock(const struct rte_mbuf *pkt);
};

#endif /* ICMP_PARSER_H_ */
