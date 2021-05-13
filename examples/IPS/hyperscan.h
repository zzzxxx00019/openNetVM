
#ifndef HYPERSCAN_CLASS_H
#define HYPERSCAN_CLASS_H

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

#include <hs.h>

#define TCP_FLOW_NUMS 10000
#define UDP_FLOW_NUMS 10000
#define IP_PROTOCOL_ICMP 0x01

using std::unordered_map;
using std::vector;

// Key for identifying a stream in our pcap input data, using data from its IP
// headers.
struct KeyTuple {
        unsigned int srcAddr;
        unsigned int srcPort;
        unsigned int dstAddr;
        unsigned int dstPort;

        // Construct a KeyTuple from a TCP or UDP packet.
        template <class T>
        KeyTuple(const struct rte_ipv4_hdr *iphdr, const T *hdr);

        bool
        operator==(const KeyTuple &a) const;
};

// A *very* simple hash function, used when we create an unordered_map of
// KeyTuple objects.
struct KeyTupleHash {
        size_t
        operator()(const KeyTuple &x) const;
};

// Simple timing class
class Clock {
       public:
        void
        start() {
                time_start = std::chrono::system_clock::now();
        }

        void
        stop() {
                time_end = std::chrono::system_clock::now();
        }

        double
        seconds() const {
                std::chrono::duration<double> delta = time_end - time_start;
                return delta.count();
        }

       private:
        std::chrono::time_point<std::chrono::system_clock> time_start, time_end;
};

// Class wrapping all state associated with the Hyperscan
class Hyperscan {
       private:
        // Map used to construct stream_ids
        unordered_map<KeyTuple, size_t, KeyTupleHash> tcp_stream_map;
        unordered_map<KeyTuple, size_t, KeyTupleHash> udp_stream_map;

        // Hyperscan compiled database (streaming mode)
        const hs_database_t *db_tcp;
        const hs_database_t *db_udp;
        const hs_database_t *db_icmp;
        const hs_database_t *db_ip;

        // Hyperscan temporary scratch space (used in both modes)
        hs_scratch_t *scratch;

        // Vector of Hyperscan stream state (used in streaming mode)
        vector<hs_stream_t *> tcp_streams;
        vector<hs_stream_t *> udp_streams;
        hs_stream_t *icmp_block;

        // Count of matches found during scanning
        size_t matchCount;
        bool matchFlag;

       public:
        Hyperscan(const hs_database_t *db_tcp, const hs_database_t *db_udp, const hs_database_t *db_icmp,
                  const hs_database_t *db_ip);
        ~Hyperscan();

        bool
        matchSignal() const {
                return matchFlag;
        }

        // Return the number of matches found.
        size_t
        matches() const {
                return matchCount;
        }

        // Clear the number of matches found.
        void
        clearMatches() {
                matchCount = 0;
        }

        // Open a Hyperscan stream for each stream in stream_ids
        void
        initModule();

        // Close all open Hyperscan streams (potentially generating any
        // end-anchored matches)
        void
        closeModule();

        // Scan each packet (in the ordering given in the PCAP file) through
        // Hyperscan using the streaming interface.
        void
        scanModule(struct rte_mbuf *pkt);

        void
        scanTcpStream(const struct rte_mbuf *pkt);

        void
        scanUdpStream(const struct rte_mbuf *pkt);

        void
        scanIcmpBlock(const struct rte_mbuf *pkt);

        // Display some information about the compiled database and scanned data.
        void
        displayStats();
};

#endif
