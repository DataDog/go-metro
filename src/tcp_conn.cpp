#include <string>
#include "tcp_conn.h"


tcp_conn::tcp_conn(string host, int n)
: rtt(0.0)
, nelem(n) {
    //nothing here
}

void tcp_conn::add_ts(pair<int,int> p) {
    if(ts_hist.size() >= nelem) {
        ts_hist.pop();
    }
    ts_hist.push(p);
    return;
}

float tcp_conn::calculate_rtt(void) {
    float rttm = 0.0f;

    vector< pair<int,int> >::iterator it(ts_hist.begin());
    for ( ; it != ts_hist.end() ; it++) {
        int ts = it.first;
        int tsecr = it.second;
        rttm += (ts-tsecr)*2;
    }
    rtt =  (rttm / ts_hist.size());
    return rtt;
}
