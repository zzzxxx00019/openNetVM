/* Copyright @ Github.com/Rsysz */

#ifndef PARSE_RULES_H_
#define PARSE_RULES_H_

#include "ips_common.h"
/* clang-format off */

/* <action> <protocol> <src_ip> <src_port> <direction> <dst_ip> <dst_port> (<rules>) */

/**
 * alert - generate an alert using the selected alert method, and then log the packet
 * log - log the packet
 * drop - block and log the packet
 * reject - block the packet, log it, and then send a TCP reset if the protocol is TCP or an ICMP port unreachable message if the protocol is UDP. 
 * sdrop - block the packet but do not log it.
 */

/* ACTION */
#define ACTION_ALERT 0x00
#define ACTION_LOG 0x01
#define ACTION_DROP 0x02
#define ACTION_REJECT 0x03
#define ACTION_SDROP 0x04

/* PROTOCOL */
#define IP_PROTOCOL_ICMP 0x01
#define IP_PROTOCOL_OTHER 0xFF

const unordered_map<string, uint8_t> ACTION_MAP = {
    {"alert", ACTION_ALERT},   
    {"log", ACTION_LOG},     
    {"drop", ACTION_DROP},
    {"reject", ACTION_REJECT}, 
    {"sdrop", ACTION_SDROP},
};

const unordered_map<string, uint8_t> PROTO_MAP = {
    {"tcp", IP_PROTOCOL_TCP},
    {"udp", IP_PROTOCOL_UDP},
    {"icmp", IP_PROTOCOL_ICMP},
    {"ip", IP_PROTOCOL_OTHER},
};

/* VARIABLE */
const unordered_map<string, string> VAR_MAP = {
    {"any", "0"},
    /* NET */
    {"$HOME_NET", "192.168.2.0/24"},
    {"$EXTERNAL_NET", "192.168.1.0/24"},
    /* SERVERS */
    {"$HTTP_SERVERS", "192.168.2.200"},
    {"$SQL_SERVERS", "192.168.2.200"},
    {"$SMTP_SERVERS", "192.168.2.200"},
    {"$DNS_SERVERS", "192.168.2.200"},
    {"$TELNET_SERVERS", "192.168.2.200"},
    {"$SNMP_SERVERS", "192.168.2.200"},
    /* PORTS */
    {"$HTTP_PORTS", "80"},
    {"$FILE_DATA_PORTS", "0"},
    {"$SHELLCODE_PORTS", "0"},
    {"$ORACLE_PORTS", "0"},
};
/* clang-format on */

// Key for identifying a rule
struct RuleTuple {
        string srcAddr;
        vector<uint32_t> srcIp;
        vector<uint32_t> srcMask;

        string srcBus;
        vector<uint16_t> srcMinPort;  // LE order
        vector<uint16_t> srcMaxPort;

        string dstAddr;
        vector<uint32_t> dstIp;
        vector<uint32_t> dstMask;

        string dstBus;
        vector<uint16_t> dstMinPort;
        vector<uint16_t> dstMaxPort;

        RuleTuple(vector<string> &rule);

        bool
        operator==(const RuleTuple &a) const {
                return srcAddr == a.srcAddr && srcBus == a.srcBus && dstAddr == a.dstAddr && dstBus == a.dstBus;
        }
};

// A *very* simple hash function, used when we create an unordered_map
struct RuleTupleHash {
        size_t
        operator()(const RuleTuple &x) const {
                return hash<string>()(x.srcAddr) ^ hash<string>()(x.srcBus) ^ hash<string>()(x.dstAddr) ^
                       hash<string>()(x.dstBus);
        }
};

struct RuleInfo {
        uint8_t action;
        string msg;
        string pattern;
        unsigned flags;

        RuleInfo(const uint8_t &a, const string &m, const string &p, const unsigned &f)
            : action(a), msg(m), pattern(p), flags(f){};
};

struct RuleDB {
        vector<RuleInfo> info;
        hs_database_t *db;
};

typedef unordered_map<RuleTuple, RuleDB, RuleTupleHash> ProtocolHashMp;
typedef unordered_map<uint8_t, ProtocolHashMp> RulesHashMp;

/**
 * Generate databases from rules
 */
RulesHashMp *
databasesFromFile(const char *filename);

#endif /* PARSE_RULES_H_ */
