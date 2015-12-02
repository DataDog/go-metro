package ddsniff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"gopkg.in/tomb.v2"

	"github.com/Datadog/dd-tcp-rtt/ddtypes"
	"github.com/Datadog/dd-tcp-rtt/reporter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DatadogSniffer struct {
	Iface       string
	Snaplen     int
	Filter      string
	Exp_ttl     int
	Idle_ttl    int
	Soften      bool
	statsd_ip   string
	statsd_port int32
	flows       *ddtypes.FlowMap
	reporter    *reporter.Client
	t           tomb.Tomb
}

func NewDatadogSniffer(iface string, snaplen int, filter string, exp_ttl int, idle_ttl int, statsd_ip string, statsd_port int32) *DatadogSniffer {
	//log.Printf("new stream %v:%v started", net, transport)
	d := &DatadogSniffer{
		Iface:       iface,
		Snaplen:     snaplen,
		Filter:      filter,
		Exp_ttl:     exp_ttl,
		Idle_ttl:    idle_ttl,
		Soften:      false,
		statsd_ip:   statsd_ip,
		statsd_port: statsd_port,
		flows:       ddtypes.NewFlowMap(),
	}
	d.reporter = reporter.NewClient(net.ParseIP(d.statsd_ip), d.statsd_port, reporter.Statsd_sleep, d.flows)
	d.t.Go(d.Sniff)

	return d
}

func read_uint32(data []byte) (ret uint32) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return
}

func GetTimestamps(tcp *layers.TCP) (uint32, uint32, error) {
	for i := range tcp.Options {
		if tcp.Options[i].OptionType == 8 {
			ts := read_uint32(tcp.Options[i].OptionData[:4])
			tsecr := read_uint32(tcp.Options[i].OptionData[4:])
			return ts, tsecr, nil
		}
	}
	return 0, 0, errors.New("No TCP timestamp Options!")
}

func (d *DatadogSniffer) Stop() error {
	d.t.Kill(nil)
	return d.t.Wait()
}

func (d *DatadogSniffer) Sniff() error {

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error getting interface details: ", err)
	}

	iface_details := make([]pcap.Interface, len(ifaces)-1)
	for i := range ifaces {
		if ifaces[i].Name == d.Iface {
			iface_details[i] = ifaces[i]
		}
	}

	log.Printf("starting capture on interface %q", d.Iface)

	// Set up pcap packet capture
	inactive, err := pcap.NewInactiveHandle(d.Iface)
	if err != nil {
		d.reporter.Stop()
		log.Fatal("error creating inactive handle: ", err)
	}
	defer inactive.CleanUp()

	inactive.SetSnapLen(d.Snaplen)
	inactive.SetPromisc(false)
	inactive.SetTimeout(time.Second)

	// Maybe we should make the timestamp source selectable - Not all OS will allow that.
	//ts_sources := inactive.SupportedTimestamps()
	//for i := range ts_sources {
	//	log.Printf("TS source: %v:%v", ts_sources[i], ts_sources[i].String())
	//}

	handle, err := inactive.Activate()
	if err != nil {
		d.reporter.Stop()
		log.Fatal("error opening pcap handle: ", err)
	}

	host_ips := make(map[string]bool)

	// lets sniff when we're the destination side to work over TSECR
	hosts := make([]string, 0)
	for i := range iface_details {
		for j := range iface_details[i].Addresses {
			ip_str := iface_details[i].Addresses[j].IP.String()
			if strings.Contains(ip_str, "::") {
				log.Printf("IPv6 currently unsupported ignoring: %s", ip_str)
			} else {
				hosts = append(hosts, fmt.Sprintf("host %s", ip_str))
				host_ips[ip_str] = true
			}
		}
	}
	bpf_filter := strings.Join(hosts, " or ")

	d.Filter += " and not host 127.0.0.1"
	if len(hosts) > 0 {
		d.Filter += " and " + " (" + bpf_filter + ")"
	}

	log.Printf("Setting BPF filter: %s", d.Filter)
	if err := handle.SetBPFFilter(d.Filter); err != nil {
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

	//timebombs := make(map[string]*time.Timer)

	quit := false
	for !quit {

		// To speed things up, we're also using the ZeroCopy method for
		// reading packet data.  This method is faster than the normal
		// ReadPacketData, but the returned bytes in 'data' are
		// invalidated by any subsequent ZeroCopyReadPacketData call.
		// Note that tcpassembly is entirely compatible with this packet
		// reading method.  This is another trade-off which might be
		// appropriate for high-throughput sniffing:  it avoids a packet
		// copy, but its cost is much more careful handling of the
		// resulting byte slice.
		data, ci, err := handle.ReadPacketData()

		if err == nil {
			err = parser.DecodeLayers(data, &decoded)
			if err != nil {
				log.Printf("error decoding packet: %v", err)
				continue
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

						// consider us always the SRC (this will help us keep just one tag for
						// all comms between two ip's
						if our_ip {
							src = net.JoinHostPort(ip4.SrcIP.String(), strconv.Itoa(int(tcp.SrcPort)))
							dst = net.JoinHostPort(ip4.DstIP.String(), strconv.Itoa(int(tcp.DstPort)))
						} else {
							src = net.JoinHostPort(ip4.DstIP.String(), strconv.Itoa(int(tcp.DstPort)))
							dst = net.JoinHostPort(ip4.SrcIP.String(), strconv.Itoa(int(tcp.SrcPort)))
						}

						idle := time.Duration(d.Idle_ttl * int(time.Second))
						found, exists := d.flows.Get(src + "-" + dst)
						if exists == false {
							// TCPAccounting objects self-expire if they are inactive for a period of time >idle
							// FIXME: refactor this
							if our_ip {
								found = ddtypes.NewTCPAccounting(ip4.SrcIP, ip4.DstIP, tcp.SrcPort, tcp.DstPort, idle, func() {
									d.flows.Delete(src + "-" + dst)
									log.Printf("%v flow annihilated.", src+"-"+dst)
								})
							} else {
								found = ddtypes.NewTCPAccounting(ip4.DstIP, ip4.SrcIP, tcp.DstPort, tcp.SrcPort, idle, func() {
									d.flows.Delete(src + "-" + dst)
									log.Printf("%v flow annihilated.", src+"-"+dst)
								})
							}
							d.flows.Add(src+"-"+dst, found)
						} else {
							//flow still alive - reset timer
							found.Alive.Reset(idle)
						}

						if d.Exp_ttl > 0 && tcp.ACK && tcp.FIN && !found.Done {
							found.Done = true

							//ttl := time.Duration(d.Exp_ttl * int(time.Second))

							// Here we clean up flows that have expired by the book - that is, we have seen
							// the TCP stream come to an end FIN/ACK and have kept these around so short-lived
							// flows actually get reported.

							//set timer
							// timebombs[src+"-"+dst] = time.AfterFunc(ttl, func() {
							// 	d.flows.Delete(src + "-" + dst)
							// 	delete(timebombs, src+"-"+dst)
							// 	log.Printf("%v flow expired.", src+"-"+dst)
							// })

							// Immediately expire flow.
							d.flows.Delete(src + "-" + dst)

						}

						tcp_payload_sz := uint32(ip4.Length) - uint32((ip4.IHL+tcp.DataOffset)*4)
						if our_ip && tcp_payload_sz > 0 {
							var t ddtypes.TCPKey
							//get the TS
							ts, _, _ := GetTimestamps(&tcp)
							t.TS = ts
							t.Seq = tcp.Seq

							//insert or update
							found.Timed[t] = ci.Timestamp.UnixNano()

						} else if !our_ip {
							var t ddtypes.TCPKey
							//get the TS
							_, tsecr, _ := GetTimestamps(&tcp)
							t.TS = tsecr
							t.Seq = tcp.Ack

							if found.Timed[t] != 0 {
								if found.Seen[tcp.Ack] == false && tcp.ACK {
									//we can't receive an ACK for packet we haven't seen sent - we're the source
									rtt := uint64(ci.Timestamp.UnixNano() - found.Timed[t])
									found.CalcSRTT(rtt, d.Soften)
									found.MaxRTT(rtt)
									found.MinRTT(rtt)
									found.Sampled++
								}
								found.Seen[tcp.Ack] = true
							}
						}
					}
				}
			}
		}
		select {
		case <-d.t.Dying():
			log.Printf("Done sniffing.")
			quit = true
		default:
			continue
		}
	}

	for k := range d.flows.FlowMapKeyIterator() {
		flow, e := d.flows.Get(k)
		if e && flow.Sampled > 0 {
			if d.Soften {
				log.Printf("Flow %s\t w/ %d packets\tRTT:%6.2f ms", k, flow.Sampled, float64(int64(flow.SRTT)*int64(time.Nanosecond))/float64(time.Millisecond))
			} else {
				log.Printf("Flow %s\t w/ %d packets\tRTT:%6.2f ms", k, flow.Sampled, float64(flow.SRTT)/float64(flow.Sampled)*float64(time.Nanosecond)/float64(time.Millisecond))
			}
		}
	}

	//Shutdown reported thread
	return d.reporter.Stop()
}
