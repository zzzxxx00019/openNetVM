/* Copyright @ Github.com/Rsysz */

#ifndef IPS_COMMON_H_
#define IPS_COMMON_H_

#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#ifdef __cplusplus
} /* extern "C" */
#endif

#include <hs.h>
#include <pcap.h>

using namespace std;

/* MAXIMUM FLOW_NUMS */
#define TCP_FLOW_NUMS 250000
#define UDP_FLOW_NUMS 250000

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
                chrono::duration<double> delta = time_end - time_start;
                return delta.count();
        }

        string
        getTime() const {
                auto tt = chrono::system_clock::to_time_t(chrono::system_clock::now());
                struct tm *ptm = localtime(&tt);
                char date[60] = {0};
                sprintf(date, "%d-%02d-%02d-%02d.%02d.%02d", (int)ptm->tm_year + 1900, (int)ptm->tm_mon + 1,
                        (int)ptm->tm_mday, (int)ptm->tm_hour, (int)ptm->tm_min, (int)ptm->tm_sec);
                return string(date);
        }

       private:
        chrono::time_point<std::chrono::system_clock> time_start, time_end;
};

#endif /* IPS_COMMON_H_ */
