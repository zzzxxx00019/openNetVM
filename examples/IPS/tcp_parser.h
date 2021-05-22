/* Copyright @ Github.com/Rsysz */

#ifndef TCP_PARSER_H_
#define TCP_PARSER_H_

#include "flow_utils.h"
#include "ips_common.h"
#include "parse_rules.h"

/*rte_be32_t 	src_addr
 *rte_be16_t 	src_port
 *rte_be32_t 	dst_addr
 *rte_be16_t 	dst_port
 */

class Tcp {
       private:
        // Tcp Rule Databases
        ProtocolHashMp *tcp_rules;
        // Map used to construct multiple stream_ids
        vector<unordered_map<FlowTuple, size_t, FlowTupleHash>> stream_map;
        // Hyperscan temporary scratch space
        hs_scratch_t **scratch;
        // Vector of Hyperscan stream state
        vector<vector<hs_stream_t *>> streams;

        unordered_map<FlowTuple, vector<int>, FlowTupleHash> flow_table;
        const string protocol = "TCP";
        const FlowTuple *hdr;
        size_t *matchCount;
        bool *dropFlag;
        ProtocolHashMp::const_iterator it;

       public:
        Tcp(ProtocolHashMp &rules, hs_scratch_t **scratch, size_t *matchCount, bool *dropFlag);
        ~Tcp(){};

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
        scanStream(const struct rte_mbuf *pkt);
};

#endif /* TCP_PARSER_H_ */
