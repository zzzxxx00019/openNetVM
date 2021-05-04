
#ifndef HYPERSCAN_CLASS_H
#define HYPERSCAN_CLASS_H

#include <chrono>
#include <unordered_map>
#include <vector>

#include <hs.h>

using std::unordered_map;
using std::vector;

// Key for identifying a stream in our pcap input data, using data from its IP
// headers.
struct FiveTuple {
        unsigned int protocol;
        unsigned int srcAddr;
        unsigned int srcPort;
        unsigned int dstAddr;
        unsigned int dstPort;

        // Construct a FiveTuple from a TCP or UDP packet.
        FiveTuple(const struct ip *iphdr);

        bool
        operator==(const FiveTuple &a) const;
};

// A *very* simple hash function, used when we create an unordered_map of
// FiveTuple objects.
struct FiveTupleHash {
        size_t
        operator()(const FiveTuple &x) const;
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
        unordered_map<FiveTuple, size_t, FiveTupleHash> stream_map;

        // Hyperscan compiled database (streaming mode)
        const hs_database_t *db_streaming;

        // Hyperscan temporary scratch space (used in both modes)
        hs_scratch_t *scratch;

        // Vector of Hyperscan stream state (used in streaming mode)
        vector<hs_stream_t *> streams;

        // Count of matches found during scanning
        size_t matchCount;

       public:
        Hyperscan(const hs_database_t *streaming);
        ~Hyperscan();

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
        openStreams();

        // Close all open Hyperscan streams (potentially generating any
        // end-anchored matches)
        void
        closeStreams();

        // Scan each packet (in the ordering given in the PCAP file) through
        // Hyperscan using the streaming interface.
        void
        scanStreams(const u_char *pktData);

        // Display some information about the compiled database and scanned data.
        void
        displayStats();
};

#endif
