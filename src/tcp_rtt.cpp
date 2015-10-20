#include <iostream>
#include <sstream>
#include <cstdlib>
#include <unordered_map>

#include <arpa/inet.h>
#include <pcap.h>

#include "tcp_conn.h"
#include "netdefs.h"

#define SNAPLEN 240 /*We only really need the headers...*/

using namespace std;

static unordered_map<string, tcp_conn> connections;

int main(int argc, char **argv) {
    char *dev;
    pcap_t *handle;
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    bpf_u_int32 net;        /* Our IP */
    bpf_u_int32 mask;       /* Our netmask */
    char * filter_exp;   /* The filter expression */
    struct bpf_program fp;     /* The compiled filter */
    char errbuf[PCAP_ERRBUF_SIZE];

    clock_t start, end;
    int duration = 0;
    string iface;
    char * buff = NULL;

    stringstream ss; //use this guy to build strings.

    if(argc<3) {
        return -1;
    }

    //change this for setopt once this works.
    duration = atoi(argv[1]);

    iface.assign(argv[2]);

    /* Find the properties for the device */
    if (pcap_lookupnet(iface.c_str(), &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    cout << "Net: " << net << " Mask: " << mask << endl;

    handle = pcap_open_live(iface.c_str(), SNAPLEN, 0, 1000, errbuf);
    if (handle == NULL) {
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }
    if(net) {
        char * ip_c = (char *)&net;
#if 0
        ss << "dst host " << +ip_c[0]
            << "." << +ip_c[1]
            << "." << +ip_c[2]
            << "." << +ip_c[3]
            << " " << "and tcp";
#endif
        ss << "tcp";
    } else {
        ss << "tcp";
    }

    string filter(ss.str());
    filter_exp = new char[filter.length() + 1];
    strcpy(filter_exp, filter.c_str());

    cout << "Setting filter expression: " + filter;

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    start = clock();
    do {
        end = clock();
        /* Grab a packet */
        if(!(packet = pcap_next(handle, &header))) {
            continue;
        }

        cout << "got packet!" << endl;

        ss.str("");
        ss.clear();

        /* let's look at the tcp portion, all our packets will be TCP due to filter*/
        struct sniff_ethernet * ether_hdr = (struct sniff_ethernet *) packet;
        struct sniff_ip *  ip_hdr = (struct sniff_ip *)(packet + SIZE_ETHERNET);

        int size_ip = IP_HL(ip_hdr) * 4;
        if(size_ip < 20) {
            cerr << "Bogus IP header size, skipping" << endl;
            continue;
        }
        struct sniff_tcp * tcp_hdr = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
        if ( TH_OFF(tcp_hdr)*4 <= TCP_MIN_LEN) {
            cerr << "packet doesn't contain ops: " << TH_OFF(tcp_hdr)*4 << "bytes" << endl;
            continue;
        }

        /* search for TSopt */
        int optoff = TCP_MIN_LEN;
        bool found = false;
        while(!found && optoff < TH_OFF(tcp_hdr) * 4){
            buff = (char *)tcp_hdr + optoff;
#define TSOPT_KIND 8
#define NOP_KIND   1
            if(buff[0] == TSOPT_KIND) { //Do I have to change endianess here - debug it?
                found = true;
            } else if(buff[0] == NOP_KIND){
                optoff++;
            } else {
                optoff += buff[1];
            }
        }

        if (found) {
            cout << "Found timestamps options..." << endl;
            buff += optoff + 2;
            int ts = (int)(*buff);
            buff += 4;
            int tsecr = (int)(*buff);

            ss << inet_ntoa(ip_hdr->ip_src) << ":" << tcp_hdr->th_sport;
            string src(ss.str());

            ss.str("");
            ss.clear();

            ss << inet_ntoa(ip_hdr->ip_dst) << ":" << tcp_hdr->th_dport;
            string dst(ss.str());

            string key(src+"-"+dst);

            // Have we seen this ACK already?
            unordered_map<string, tcp_conn>::iterator got(connections.find (key));
            if(got != connections.end()) {

                tcp_conn& conn(got->second);

                if(conn.ack_seen(tcp_hdr->th_ack)){
                    continue;
                }

                conn.add_ts(pair<int,int>(ts, tsecr));
                conn.reg_ack(tcp_hdr->th_ack, tcp_hdr->th_seq);
            } else {
                string s(src.substr(src.find(":")));
                string d(src.substr(src.find(":")));

                tcp_conn t(s, tcp_hdr->th_sport, d, tcp_hdr->th_dport);
                connections.insert(std::make_pair< std::string, tcp_conn >(key, t));

                connections.at(key).add_ts(pair<int,int>(ts, tsecr));
                connections.at(key).reg_ack(tcp_hdr->th_ack, tcp_hdr->th_seq);
            }
        }

    } while((duration && (end-start)<duration*1000) || !duration );

    cout << "capture finished" << endl;

    cout << "RTTMs calculated with inbound traffic: " << endl;
    unordered_map<string, tcp_conn>::iterator it(connections.begin());
    for ( ; it != connections.end() ; it++) {
        cout << it->first << " RRTM: " << it->second.calculate_rtt() << endl;
    }

    delete[] filter_exp;
    return 0;
}
