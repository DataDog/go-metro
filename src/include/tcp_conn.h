#ifndef _TCP_CONN_H
#define _TCP_CONN_H

#include <vector>
#include <unordered_map>
#include <string>

#include "netdefs.h"

using namespace std;

class tcp_conn {
    public:
        tcp_conn(string src, u_int sport, string dst, u_int dport, int n=30);
        tcp_conn(tcp_conn const &t);

        void add_ts(pair<int,int> p);
        float calculate_rtt(void);
        bool ack_seen(tcp_seq seq);
        void reg_ack(tcp_seq ks, tcp_seq vs);

    private:
        vector< pair<int,int> > ts_hist;
        unordered_map<tcp_seq, tcp_seq> acks; //turn this into a timed_cache

        string src;
        u_int sport;
        string dst;
        u_int dport;

        int nelem;
        float rtt;
};

#endif /* _TCP_CONN_H */
