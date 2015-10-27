// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// synscan implements a TCP syn scanner on top of pcap.
// It's more complicated than arpscan, since it has to handle sending packets
// outside the local network, requiring some routing and ARP work.
//
// Since this is just an example program, it aims for simplicity over
// performance.  It doesn't handle sending packets very quickly, it scans IPs
// serially instead of in parallel, and uses gopacket.Packet instead of
// gopacket.DecodingLayerParser for packet processing.  We also make use of very
// simple timeout logic with time.Since.
//
// Making it blazingly fast is left as an exercise to the reader.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "en0", "Interface to get packets from")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var soften = flag.Bool("t", false, "Soften RTTM")
var logAllPackets = flag.Bool("v", false, "Log whenever we see a packet")
var getMinRTT = flag.Bool("m", false, "Return the minimum RTT we have for a given connection.")
var packetCount = flag.Int("c", -1, `
Quit after processing this many packets, flushing all currently buffered
connections.  If negative, this is infinite`)

// scanner handles scanning a single IP address.
type TCPRTT struct {
	// destination, gateway (if applicable), and soruce IP addresses to use.
	Dst, Src     net.IP
	Dport, Sport layers.TCPPort

	SRTT      uint64
	TS, TSecr uint32
	Seen      map[uint32]bool
	Timed     map[uint32]int64
	Sampled   uint32
	Seq       uint32
	NextSeq   uint32
	LastSz    uint32
}

// New creates a new stream.  It's called whenever the assembler sees a stream
// it isn't currently following.
func NewTCPRTT(src net.IP, dst net.IP, sport layers.TCPPort, dport layers.TCPPort) *TCPRTT {
	//log.Printf("new stream %v:%v started", net, transport)
	t := &TCPRTT{
		Dst:     dst,
		Src:     src,
		Dport:   dport,
		Sport:   sport,
		SRTT:    0,
		Sampled: 0,
		TS:      0,
		TSecr:   0,
		Seq:     0,
		Seen:    make(map[uint32]bool),
		Timed:   make(map[uint32]int64),
	}

	return t
}

func read_uint32(data []byte) (ret uint32) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return
}

func main() {

	flag.Parse()

	log.Printf("Will attempt sniffing off interface %q", *iface)
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error getting interface details: ", err)
	}

	var iface_details pcap.Interface
	for i := range ifaces {
		if ifaces[i].Name == *iface {
			iface_details = ifaces[i]
		}
	}

	log.Printf("starting capture on interface %q", *iface)
	log.Printf("About to analyze %v packets", *packetCount)
	// Set up pcap packet capture
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, 0)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}

	// lets sniff when we're the destination side to work over  TSECR
	host_ips := make(map[string]bool)
	var ip_filter string
	for i := range iface_details.Addresses {
		if i < len(iface_details.Addresses)-1 {
			ip_filter += fmt.Sprintf("host %s or ", iface_details.Addresses[i].IP)
		} else {
			ip_filter += fmt.Sprintf("host %s", iface_details.Addresses[i].IP)
		}
		host_ips[iface_details.Addresses[i].IP.String()] = true
	}

	*filter += " and " + " (" + ip_filter + ")"
	log.Printf("Setting BPF filter: %s", *filter)
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	log.Println("reading in packets")

	// We use a DecodingLayerParser here instead of a simpler PacketSource.
	// This approach should be measurably faster, but is also more rigid.
	// PacketSource will handle any known type of packet safely and easily,
	// but DecodingLayerParser will only handle those packet types we
	// specifically pass in.  This trade-off can be quite useful, though, in
	// high-throughput situations.
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var ip6extensions layers.IPv6ExtensionSkipper
	var tcp layers.TCP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &ip6, &ip6extensions, &tcp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)

	var byteCount int64

	flows := make(map[string]*TCPRTT)
	for ; *packetCount != 0; *packetCount-- {
		// To speed things up, we're also using the ZeroCopy method for
		// reading packet data.  This method is faster than the normal
		// ReadPacketData, but the returned bytes in 'data' are
		// invalidated by any subsequent ZeroCopyReadPacketData call.
		// Note that tcpassembly is entirely compatible with this packet
		// reading method.  This is another trade-off which might be
		// appropriate for high-throughput sniffing:  it avoids a packet
		// copy, but its cost is much more careful handling of the
		// resulting byte slice.
		data, _, err := handle.ZeroCopyReadPacketData()
		//data, _, err := handle.ReadPacketData()

		if err != nil {
			log.Printf("error getting packet: %v", err)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Printf("error decoding packet: %v", err)
			continue
		}
		if *logAllPackets {
			log.Printf("decoded the following layers: %v", decoded)
		}
		byteCount += int64(len(data))
		// Find either the IPv4 or IPv6 address to use as our network
		// layer.
		foundNetLayer := false
		foundIPv4Layer := false
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeIPv4:
				foundNetLayer = true
				foundIPv4Layer = true
			case layers.LayerTypeIPv6:
				foundNetLayer = true
			case layers.LayerTypeTCP:
				if foundNetLayer && foundIPv4Layer {
					//do we have this flow? Build key
					var src, dst string
					our_ip := host_ips[ip4.SrcIP.String()]
					if our_ip == false {
						src = net.JoinHostPort(ip4.SrcIP.String(), strconv.Itoa(int(tcp.SrcPort)))
						dst = net.JoinHostPort(ip4.DstIP.String(), strconv.Itoa(int(tcp.DstPort)))
					} else {
						// We always consider ourselves the "destination" with respect to the key.
						src = net.JoinHostPort(ip4.DstIP.String(), strconv.Itoa(int(tcp.DstPort)))
						dst = net.JoinHostPort(ip4.SrcIP.String(), strconv.Itoa(int(tcp.SrcPort)))
					}

					found := flows[src+"-"+dst]
					if found == nil {
						if our_ip == false {
							found = NewTCPRTT(ip4.SrcIP, ip4.DstIP, tcp.SrcPort, tcp.DstPort)
						} else {
							found = NewTCPRTT(ip4.DstIP, ip4.SrcIP, tcp.DstPort, tcp.SrcPort)
						}
					}

					flows[src+"-"+dst] = found

					//tcp_payload_sz := uint32(ip4.Length) - uint32((ip4.IHL+tcp.DataOffset)*4)
					if our_ip {
						//do we have to add an entry?
						if found.Timed[tcp.Seq] == 0 {
							found.Timed[tcp.Seq] = time.Now().UnixNano()
						}
					} else if found.Timed[tcp.Ack] != 0 {
						if found.Seen[tcp.Ack] == false && tcp.ACK {
							//we can't receive an ACK for packet we haven't seen sent - we're the source
							rtt := uint64(time.Now().UnixNano() - found.Timed[tcp.Ack])
							if rtt < 1000 {
								rtt = 1000
							}

							if found.SRTT == 0 {
								found.SRTT = rtt
							} else if *soften {
								found.SRTT -= (found.SRTT >> 3)
								found.SRTT += rtt >> 3
							} else {
								found.SRTT += rtt
							}
							found.Sampled++
						}
						found.Seen[tcp.Ack] = true
					}
				}
			}
		}
	}

	for k, flow := range flows {
		if len(flow.Seen) > 1 {
			if *soften {
				log.Printf("Flow %s\t w/ %d packets\tRTT:%6.2f ms", k, flow.Sampled, float64(int64(flow.SRTT)*int64(time.Nanosecond))/float64(time.Millisecond))
			} else {
				log.Printf("Flow %s\t w/ %d packets\tRTT:%6.2f ms", k, flow.Sampled, float64(flow.SRTT)/float64(flow.Sampled)*float64(time.Nanosecond)/float64(time.Millisecond))
			}
		}
	}
}
