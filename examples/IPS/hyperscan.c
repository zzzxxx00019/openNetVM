#include "hyperscan.h"

#include <iostream>

// We use the BSD primitives throughout as they exist on both BSD and Linux.
#define __FAVOR_BSD
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <hs.h>

using std::cerr;
using std::cout;
using std::endl;

// Helper function. See end of file.
static bool
payloadOffset(const unsigned char *pkt_data, unsigned int *offset, unsigned int *length);

// Match event handler: called every time Hyperscan finds a match.
static int
onMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *ctx) {
        // Our context points to a size_t storing the match count
        size_t *matches = (size_t *)ctx;
        (*matches)++;
        return 0;  // continue matching
}

FiveTuple::FiveTuple(const struct ip *iphdr) {
        // IP fields
        protocol = iphdr->ip_p;
        srcAddr = iphdr->ip_src.s_addr;
        dstAddr = iphdr->ip_dst.s_addr;

        // UDP/TCP ports
        const struct udphdr *uh = (const struct udphdr *)(((const char *)iphdr) + (iphdr->ip_hl * 4));
        srcPort = uh->uh_sport;
        dstPort = uh->uh_dport;
}

bool
FiveTuple::operator==(const FiveTuple &a) const {
        return protocol == a.protocol && srcAddr == a.srcAddr && srcPort == a.srcPort && dstAddr == a.dstAddr &&
               dstPort == a.dstPort;
}

size_t
FiveTupleHash::operator()(const FiveTuple &x) const {
        return x.srcAddr ^ x.dstAddr ^ x.protocol ^ x.srcPort ^ x.dstPort;
}

Hyperscan::Hyperscan(const hs_database_t *streaming) : db_streaming(streaming), scratch(nullptr), matchCount(0) {
        // Allocate enough scratch space to handle either streaming or block
        // mode, so we only need the one scratch region.
        hs_error_t err = hs_alloc_scratch(db_streaming, &scratch);
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
Hyperscan::openStreams() {
        streams.resize(stream_map.size());
        for (auto &stream : streams) {
                hs_error_t err = hs_open_stream(db_streaming, 0, &stream);
                if (err != HS_SUCCESS) {
                        cerr << "ERROR: Unable to open stream. Exiting." << endl;
                        exit(-1);
                }
        }
}

void
Hyperscan::closeStreams() {
        for (auto &stream : streams) {
                hs_error_t err = hs_close_stream(stream, scratch, onMatch, &matchCount);
                if (err != HS_SUCCESS) {
                        cerr << "ERROR: Unable to close stream. Exiting." << endl;
                        exit(-1);
                }
        }
}

void
Hyperscan::scanStreams(const u_char *pktData) {
        unsigned int offset = 0, length = 0;
        if (!payloadOffset(pktData, &offset, &length))
                return;
        // Valid TCP or UDP packet
        const struct ip *iphdr = (const struct ip *)(pktData + sizeof(struct ether_header));
        const char *payload = (const char *)pktData + offset;

        size_t id = stream_map.insert(std::make_pair(FiveTuple(iphdr), stream_map.size())).first->second;

        hs_error_t err = hs_scan_stream(streams[id], payload, length, 0, scratch, onMatch, &matchCount);

        if (err != HS_SUCCESS) {
                cerr << "ERROR: Unable to scan packet. Exiting." << endl;
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

                cout << numPackets << " packets in " << numStreams << " streams, totalling " << numBytes << " bytes."
                     << endl;
                cout << "Average packet length: " << numBytes / numPackets << " bytes." << endl;
                cout << "Average stream length: " << numBytes / numStreams << " bytes." << endl;
                cout << endl;

                size_t dbStream_size = 0;
                err = hs_database_size(db_streaming, &dbStream_size);
                if (err == HS_SUCCESS) {
                        cout << "Streaming mode Hyperscan database size    : " << dbStream_size << " bytes." << endl;
                } else {
                        cout << "Error getting streaming mode Hyperscan database size" << endl;
                }

                size_t dbBlock_size = 0;
                err = hs_database_size(db_block, &dbBlock_size);
                if (err == HS_SUCCESS) {
                        cout << "Block mode Hyperscan database size        : " << dbBlock_size << " bytes." << endl;
                } else {
                        cout << "Error getting block mode Hyperscan database size" << endl;
                }

                size_t stream_size = 0;
                err = hs_stream_size(db_streaming, &stream_size);
                if (err == HS_SUCCESS) {
                        cout << "Streaming mode Hyperscan stream state size: " << stream_size << " bytes (per stream)."
                             << endl;
                } else {
                        cout << "Error getting stream state size" << endl;
                }
        */
}

/**
 * Helper function to locate the offset of the first byte of the payload in the
 * given ethernet frame. Offset into the packet, and the length of the payload
 * are returned in the arguments @a offset and @a length.
 */
static bool
payloadOffset(const unsigned char *pkt_data, unsigned int *offset, unsigned int *length) {
        const ip *iph = (const ip *)(pkt_data + sizeof(ether_header));
        const tcphdr *th = nullptr;

        // Ignore packets that aren't IPv4
        if (iph->ip_v != 4) {
                return false;
        }

        // Ignore fragmented packets.
        if (iph->ip_off & htons(IP_MF | IP_OFFMASK)) {
                return false;
        }

        // IP header length, and transport header length.
        unsigned int ihlen = iph->ip_hl * 4;
        unsigned int thlen = 0;

        switch (iph->ip_p) {
                case IPPROTO_TCP:
                        th = (const tcphdr *)((const char *)iph + ihlen);
                        thlen = th->th_off * 4;
                        break;
                case IPPROTO_UDP:
                        thlen = sizeof(udphdr);
                        break;
                default:
                        return false;
        }

        *offset = sizeof(ether_header) + ihlen + thlen;
        *length = sizeof(ether_header) + ntohs(iph->ip_len) - *offset;

        return *length != 0;
}
