#include "hyperscan.h"

#include <iostream>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#ifdef __cplusplus
}
#endif

#include <hs.h>

using std::cerr;
using std::cout;
using std::endl;
using std::string;

extern unordered_map<string, vector<string>> alert_msg;

// Match event handler: called every time Hyperscan finds a match.
static int
onTcpMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *ctx) {
        // Our context points to a size_t storing the match count
        bool *matches = (bool *)ctx;
        (*matches) = true;
        cout << alert_msg["tcp"][id] << endl;
        return 0;  // continue matching
}
static int
onUdpMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *ctx) {
        // Our context points to a size_t storing the match count
        bool *matches = (bool *)ctx;
        (*matches) = true;
        cout << alert_msg["udp"][id] << endl;
        return 0;  // continue matching
}
static int
onIcmpMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *ctx) {
        // Our context points to a size_t storing the match count
        bool *matches = (bool *)ctx;
        (*matches) = true;
        cout << alert_msg["icmp"][id] << endl;
        return 0;  // continue matching
}

template <typename T>  // Since T is written with C, so i call it typename
KeyTuple::KeyTuple(const struct rte_ipv4_hdr *iphdr, const T *hdr) {
        // IP fields
        srcAddr = iphdr->src_addr;
        dstAddr = iphdr->dst_addr;

        // UDP/TCP ports
        srcPort = hdr->src_port;
        dstPort = hdr->dst_port;
}

bool
KeyTuple::operator==(const KeyTuple &a) const {
        return srcAddr == a.srcAddr && srcPort == a.srcPort && dstAddr == a.dstAddr && dstPort == a.dstPort;
}

size_t
KeyTupleHash::operator()(const KeyTuple &x) const {
        return x.srcAddr ^ x.dstAddr ^ x.srcPort ^ x.dstPort;
}

Hyperscan::Hyperscan(const hs_database_t *db_tcp, const hs_database_t *db_udp, const hs_database_t *db_icmp,
                     const hs_database_t *db_ip)
    : db_tcp(db_tcp),
      db_udp(db_udp),
      db_icmp(db_icmp),
      db_ip(db_ip),
      scratch(nullptr),
      matchCount(0),
      matchFlag(false) {
        // Allocate enough scratch space to handle either streaming or block
        // mode, so we only need the one scratch region.
        hs_error_t err;
        if (db_tcp)
                err = hs_alloc_scratch(db_tcp, &scratch);
        if (db_udp)
                err = hs_alloc_scratch(db_udp, &scratch);
        if (db_icmp)
                err = hs_alloc_scratch(db_icmp, &scratch);
        if (db_ip)
                err = hs_alloc_scratch(db_ip, &scratch);
        if (err != HS_SUCCESS) {
                cout << err << endl;
                cerr << "ERROR: could not allocate scratch space. Exiting." << endl;
                exit(-1);
        }
}

Hyperscan::~Hyperscan() {
        // Free scratch region
        hs_free_scratch(scratch);
}

void
Hyperscan::initModule() {
        if (db_tcp) {
                tcp_streams.resize(TCP_FLOW_NUMS);
                for (auto &stream : tcp_streams) {
                        hs_error_t err = hs_open_stream(db_tcp, 0, &stream);
                        if (err != HS_SUCCESS) {
                                cerr << "ERROR: Unable to open tcp_stream. Exiting." << endl;
                                exit(-1);
                        }
                }
        }
        if (db_udp) {
                udp_streams.resize(UDP_FLOW_NUMS);
                for (auto &stream : udp_streams) {
                        hs_error_t err = hs_open_stream(db_udp, 0, &stream);
                        if (err != HS_SUCCESS) {
                                cerr << "ERROR: Unable to open udp_stream. Exiting." << endl;
                                exit(-1);
                        }
                }
        }
        hs_error_t err = hs_open_stream(db_icmp, 0, &icmp_block);
        if (err != HS_SUCCESS) {
                cerr << "ERROR: Unable to open udp_stream. Exiting." << endl;
                exit(-1);
        }
}

void
Hyperscan::closeModule() {
        for (auto &stream : tcp_streams) {
                hs_error_t err = hs_close_stream(stream, scratch, onTcpMatch, &matchCount);
                if (err != HS_SUCCESS) {
                        cerr << "ERROR: Unable to close stream. Exiting." << endl;
                        exit(-1);
                }
        }
        for (auto &stream : udp_streams) {
                hs_error_t err = hs_close_stream(stream, scratch, onUdpMatch, &matchCount);
                if (err != HS_SUCCESS) {
                        cerr << "ERROR: Unable to close stream. Exiting." << endl;
                        exit(-1);
                }
        }
}

void
Hyperscan::scanModule(struct rte_mbuf *pkt) {
        struct rte_ipv4_hdr *ipv4 = onvm_pkt_ipv4_hdr(pkt);
        if (ipv4) {
                matchFlag = false;
                if (ipv4->next_proto_id == IP_PROTOCOL_TCP && db_tcp) {
                        scanTcpStream(pkt);
                } else if (ipv4->next_proto_id == IP_PROTOCOL_UDP && db_udp) {
                        scanUdpStream(pkt);
                } else if (ipv4->next_proto_id == IP_PROTOCOL_ICMP && db_icmp) {
                        scanIcmpBlock(pkt);
                }
                if (matchFlag)
                        matchCount++;
        }
}

// TCP, UDP
void
Hyperscan::scanTcpStream(const struct rte_mbuf *pkt) {
        const struct rte_ipv4_hdr *ipv4 =
            (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr));
        const struct rte_tcp_hdr *tcp =
            (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_ipv4_hdr));
        const char *payload = rte_pktmbuf_mtod(pkt, char *) + sizeof(struct rte_ether_hdr) +
                              sizeof(struct rte_ipv4_hdr) + sizeof(rte_tcp_hdr);

        const size_t length = rte_be_to_cpu_16(ipv4->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(rte_tcp_hdr);
        size_t id = tcp_stream_map.insert(std::make_pair(KeyTuple(ipv4, tcp), tcp_stream_map.size())).first->second;
        if (id > TCP_FLOW_NUMS)
                id %= TCP_FLOW_NUMS;
        hs_error_t err = hs_scan_stream(tcp_streams[id], payload, length, 0, scratch, onTcpMatch, &matchFlag);
        if (err != HS_SUCCESS) {
                cerr << "ERROR: Unable to scan tcp packet. Exiting." << endl;
                exit(-1);
        }
}
void
Hyperscan::scanUdpStream(const struct rte_mbuf *pkt) {
        const struct rte_ipv4_hdr *ipv4 =
            (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr));
        const struct rte_udp_hdr *udp =
            (struct rte_udp_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) +
                                   sizeof(struct rte_ipv4_hdr));
        const char *payload = rte_pktmbuf_mtod(pkt, char *) + sizeof(struct rte_ether_hdr) +
                              sizeof(struct rte_ipv4_hdr) + sizeof(rte_udp_hdr);

        const size_t length = rte_be_to_cpu_16(ipv4->total_length) - sizeof(rte_ipv4_hdr) - sizeof(rte_udp_hdr);
        size_t id = udp_stream_map.insert(std::make_pair(KeyTuple(ipv4, udp), udp_stream_map.size())).first->second;
        if (id > UDP_FLOW_NUMS)
                id %= UDP_FLOW_NUMS;
        hs_error_t err = hs_scan_stream(udp_streams[id], payload, length, 0, scratch, onUdpMatch, &matchFlag);
        if (err != HS_SUCCESS) {
                cerr << "ERROR: Unable to scan udp packet. Exiting." << endl;
                exit(-1);
        }
}
void
Hyperscan::scanIcmpBlock(const struct rte_mbuf *pkt) {
        const struct rte_ipv4_hdr *ipv4 =
            (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr));
        const struct rte_icmp_hdr *icmp =
            (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(pkt, uint8_t *) + sizeof(struct rte_ether_hdr) +
                                    sizeof(struct rte_ipv4_hdr));
        const char *payload = rte_pktmbuf_mtod(pkt, char *) + sizeof(struct rte_ether_hdr) +
                              sizeof(struct rte_ipv4_hdr) + sizeof(rte_icmp_hdr);
        // const size_t length = strlen(payload);
        const size_t length = rte_be_to_cpu_16(ipv4->total_length) - sizeof(rte_ipv4_hdr) - sizeof(rte_icmp_hdr);

        hs_error_t err = hs_scan_stream(icmp_block, payload, length, 0, scratch, onIcmpMatch, &matchFlag);
        if (err != HS_SUCCESS) {
                cerr << "ERROR: Unable to scan icmp packet. Exiting." << endl;
                exit(-1);
        }
}

void
Hyperscan::displayStats() {
        cout << "DisplayStats" << endl;
        /*
                size_t numPackets = packets.size();
                size_t numStreams = stream_map.size();
                size_t numBytes = bytes();
                hs_error_t err;

                cout << numPackets << " packets in " << numStreams << " streams, totalling " << numBytes << "
           bytes."
                     << endl;
                cout << "Average packet length: " << numBytes / numPackets << " bytes." << endl;
                cout << "Average stream length: " << numBytes / numStreams << " bytes." << endl;
                cout << endl;

                size_t dbStream_size = 0;
                err = hs_database_size(db_streaming, &dbStream_size);
                if (err == HS_SUCCESS) {
                        cout << "Streaming mode Hyperscan database size    : " << dbStream_size << " bytes." <<
           endl; } else { cout << "Error getting streaming mode Hyperscan database size" << endl;
                }

                size_t dbBlock_size = 0;
                err = hs_database_size(db_block, &dbBlock_size);
                if (err == HS_SUCCESS) {
                        cout << "Block mode Hyperscan database size        : " << dbBlock_size << " bytes." <<
           endl; } else { cout << "Error getting block mode Hyperscan database size" << endl;
                }

                size_t stream_size = 0;
                err = hs_stream_size(db_streaming, &stream_size);
                if (err == HS_SUCCESS) {
                        cout << "Streaming mode Hyperscan stream state size: " << stream_size << " bytes (per
           stream)."
                             << endl;
                } else {
                        cout << "Error getting stream state size" << endl;
                }
        */
}
