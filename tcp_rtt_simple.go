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
	"log"
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "en0", "Interface to get packets from")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Log whenever we see a packet")
var packetCount = flag.Int("c", -1, `
Quit after processing this many packets, flushing all currently buffered
connections.  If negative, this is infinite`)

// scanner handles scanning a single IP address.
type TCPRTT struct {
	// destination, gateway (if applicable), and soruce IP addresses to use.
	Dst, Src     net.IP
	Dport, Sport layers.TCPPort

	RTT       float64
	TS, TSecr uint32
	Seen      map[uint32]bool
	Seq       uint32
}

// New creates a new stream.  It's called whenever the assembler sees a stream
// it isn't currently following.
func NewTCPRTT(src net.IP, dst net.IP, sport layers.TCPPort, dport layers.TCPPort) *TCPRTT {
	//log.Printf("new stream %v:%v started", net, transport)
	t := &TCPRTT{
		Dst:   dst,
		Src:   src,
		Dport: dport,
		Sport: sport,
		RTT:   0.0,
		TS:    0,
		TSecr: 0,
		Seen:  make(map[uint32]bool),
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

	log.Printf("starting capture on interface %q", *iface)
	log.Printf("About to analyze %v packets", *packetCount)
	// Set up pcap packet capture
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, 0)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
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
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeIPv4:
				foundNetLayer = true
			case layers.LayerTypeIPv6:
				foundNetLayer = true
			case layers.LayerTypeTCP:
				if foundNetLayer {
					//do we have this flow? Build key
					src := net.JoinHostPort(ip4.SrcIP.String(), strconv.Itoa(int(tcp.SrcPort)))
					dst := net.JoinHostPort(ip4.DstIP.String(), strconv.Itoa(int(tcp.DstPort)))
					found := flows[src+"-"+dst]
					if found == nil {
						found = NewTCPRTT(ip4.SrcIP, ip4.DstIP, tcp.SrcPort, tcp.DstPort)
					}
					flows[src+"-"+dst] = found

					//ignore duplicates and out of orders for now...
					if found.Seen[tcp.Seq] == false || tcp.Seq < found.Seq {
						for i := range tcp.Options {
							if tcp.Options[i].OptionType == 8 {
								ts := read_uint32(tcp.Options[i].OptionData[:4])
								tsecr := read_uint32(tcp.Options[i].OptionData[4:])
								found.Seen[tcp.Seq] = true
								if len(found.Seen) == 1 {
									found.RTT = float64(ts - found.TS)
								} else if len(found.Seen) > 1 {
									found.RTT *= float64(len(found.Seen) - 2)
									found.RTT += float64(ts - found.TS)
									found.RTT /= float64((len(found.Seen) - 1))
								}
								found.TS = ts
								found.TSecr = tsecr
								found.Seq = tcp.Seq
								found.Seen[tcp.Seq] = true
								break
							}
						}
					}
				}
				break
			}
		}
	}

	for k, flow := range flows {
		log.Printf("Flow %s RTT:\t%6.3f", k, flow.RTT)
	}
}
