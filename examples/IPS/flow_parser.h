/* Copyright @ Github.com/Rsysz */

#ifndef FLOW_PARSER_H_
#define FLOW_PARSER_H_

#include "icmp_parser.h"
#include "ips_common.h"
#include "tcp_parser.h"
#include "udp_parser.h"

class Flow {
       private:
        Tcp *tcp_parser;
        Udp *udp_parser;
        Icmp *icmp_parser;
        // Ip *ip_parser;
        hs_scratch_t *scratch;
        // Count of matches found during scanning
        size_t matchCount;
        size_t dropCount;
        bool dropFlag;

       public:
        Flow(RulesHashMp &Rules);
        ~Flow();

        void
        scanFlow(struct rte_mbuf *pkt);

        inline bool
        drop() {
                return dropFlag;
        }
};

#endif /* FLOW_PARSER_H_ */