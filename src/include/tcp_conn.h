#ifndef _TCP_CONN_H
#define _TCP_CONN_H

#include <vector>
#include <string>

using namespace std;

class tcp_conn {
    public:
        tcp_conn(string host, int n);

        void add_ts(pair<int,int> p);
        float calculate_rtt(void);

    private:
        vector< pair<int,int> > ts_hist;
        string host;
        float rtt;
        int nelem;
}

#endif /* _TCP_CONN_H */
