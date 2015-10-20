#include <string>
#include "tcp_conn.h"


tcp_conn::tcp_conn(string src, u_int sport, string dst, u_int dport, int n)
: src(src)
, sport(sport)
, dst(dst)
, dport(dport)
, nelem(n)
, rtt(0.0f) {
    //nothing here
}

tcp_conn::tcp_conn(tcp_conn const &t)
: src(t.src)
, sport(t.sport)
, dst(t.dst)
, dport(t.dport)
, nelem(t.nelem)
, rtt(t.rtt) {
}

void tcp_conn::add_ts(pair<int,int> p) {

    if(ts_hist.size() >= nelem) {
        ts_hist.pop_back();
    }
    ts_hist.push_back(p);
    return;
}

float tcp_conn::calculate_rtt(void) {
    float rttm = 0.0f;

    vector< pair<int,int> >::iterator it(ts_hist.begin());
    for ( ; it != ts_hist.end() ; it++) {
        int ts = it->first;
        int tsecr = it->second;
        rttm += (ts-tsecr)*2;
    }
    rtt =  (rttm / ts_hist.size());
    return rtt;
}

bool tcp_conn::ack_seen(tcp_seq seq) {
    unordered_map<tcp_seq,tcp_seq>::const_iterator it(acks.find(seq));
    return (it != acks.end());
}

void tcp_conn::reg_ack(tcp_seq ks, tcp_seq vs) {
    acks[ks] = vs;
}
