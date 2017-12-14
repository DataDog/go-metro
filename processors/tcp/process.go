

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/tomb.v2"

	"github.com/DataDog/go-metro"
	log "github.com/cihub/seelog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	reportInterval = 30
	processorName  = "tcp-rtt"
	inflight       = 10000
)

var (
	supportedReporters = []string{"statsd"}
)

type MetroDecoder struct {
	eth           layers.Ethernet
	dot1q         layers.Dot1Q
	ip4           layers.IPv4
	ip6           layers.IPv6
	ip6extensions layers.IPv6ExtensionSkipper
	tcp           layers.TCP
	payload       gopacket.Payload
	parser        *gopacket.DecodingLayerParser
	decoded       []gopacket.LayerType
}

func NewMetroDecoder() *MetroDecoder {
	d := &MetroDecoder{
		decoded: make([]gopacket.LayerType, 0, 4),
	}
	d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&d.eth, &d.dot1q, &d.ip4, &d.ip6,
		&d.ip6extensions, &d.tcp, &d.payload)

	return d
}

// We use a DecodingLayerParser here instead of a simpler PacketSource.
// This approach should be measurably faster, but is also more rigid.
// PacketSource will handle any known type of packet safely and easily,
// but DecodingLayerParser will only handle those packet types we
// specifically pass in.  This trade-off can be quite useful, though, in
// high-throughput situations.
type MetroSniffer struct {
	ExpTTL         int
	IdleTTL        int
	Soften         bool
	decoder        *MetroDecoder
	hostIPs        map[string]bool
	nameLookup     map[string]string
	sampleTS       int64
	sampleDeadline int64
	flows          *FlowMap
	reporters      map[string]metro.Reporter
	reportIval     time.Duration
	config         MetroTCPConfig
	packets        chan PacketWrapper
	to             chan struct{}
	t              tomb.Tomb
}

type PacketWrapper struct {
	packet []byte
	info   *gopacket.CaptureInfo
}

func NewSnifferFromYAML(path string) (metro.Processor, error) {
	//Parse config
	filename, _ := filepath.Abs(path)

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.New("configuration file not found")
	}

	var cfg MetroTCPConfig
	err = cfg.Parse(yamlFile)
	if err != nil {
		log.Criticalf("Error parsing configuration file: %s ", err)
		return nil, err
	}

	if len(cfg.Ips) == 0 && len(cfg.Hosts) == 0 {
		err := fmt.Errorf("Whitelists must be enabled for go-metro to run (you may whitelist by IP or hostname in config file).")
		log.Errorf("%v", err)
		return nil, err
	}

	return NewMetroSniffer(cfg)

}

func NewMetroSniffer(cfg MetroTCPConfig) (*MetroSniffer, error) {
	d := &MetroSniffer{
		ExpTTL:     cfg.ExpTTL,
		IdleTTL:    cfg.IdleTTL,
		Soften:     false,
		hostIPs:    make(map[string]bool),
		nameLookup: make(map[string]string),
		reporters:  make(map[string]metro.Reporter),
		reportIval: time.Duration(reportInterval) * time.Second,
		sampleTS:   time.Now().UnixNano(),
		flows:      NewFlowMap(),
		config:     cfg,
		packets:    make(chan PacketWrapper, inflight),
	}
	d.sampleDeadline = d.sampleTS + int64(d.config.SampleDuration)*time.Second.Nanoseconds()
	d.decoder = NewMetroDecoder()

	return d, nil
}

func readUint32(data []byte) (ret uint32) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return
}

func GetTimestamps(tcp *layers.TCP) (uint32, uint32, error) {
	for i := range tcp.Options {
		if tcp.Options[i].OptionType == 8 {
			ts := readUint32(tcp.Options[i].OptionData[:4])
			tsecr := readUint32(tcp.Options[i].OptionData[4:])
			return ts, tsecr, nil
		}
	}
	return 0, 0, errors.New("No TCP timestamp Options!")
}

func (d *MetroSniffer) Start() error {
	d.t.Go(d.Report)
	d.t.Go(d.Process)

	return nil
}

func (d *MetroSniffer) Stop() error {
	d.t.Kill(nil)
	return d.t.Wait()
}

func (d *MetroSniffer) Running() bool {
	return d.t.Alive()
}

func (d *MetroSniffer) RegisterReporter(id string, reporter metro.Reporter) error {
	if _, ok := d.reporters[id]; ok {
		return errors.New("Reporter already registered")
	}

	d.reporters[id] = reporter
	return nil
}

func (d *MetroSniffer) die(err error) {
	d.t.Kill(err)
}

func (d *MetroSniffer) handlePacket(data []byte, ci *gopacket.CaptureInfo) error {
	var buffer bytes.Buffer

	err := d.decoder.parser.DecodeLayers(data, &d.decoder.decoded)
	if err != nil {
		log.Infof("error decoding packet: %v", err)
		return err
	}
	// Find either the IPv4 or IPv6 address to use as our network
	// layer.
	foundNetLayer := false
	foundIPv4Layer := false
	for _, typ := range d.decoder.decoded {
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
				ourIP := d.hostIPs[d.decoder.ip4.SrcIP.String()]

				// consider us always the SRC (this will help us keep just one tag for
				// all comms between two ip's
				if ourIP {
					src = net.JoinHostPort(d.decoder.ip4.SrcIP.String(), strconv.Itoa(int(d.decoder.tcp.SrcPort)))
					dst = net.JoinHostPort(d.decoder.ip4.DstIP.String(), strconv.Itoa(int(d.decoder.tcp.DstPort)))
				} else {
					src = net.JoinHostPort(d.decoder.ip4.DstIP.String(), strconv.Itoa(int(d.decoder.tcp.DstPort)))
					dst = net.JoinHostPort(d.decoder.ip4.SrcIP.String(), strconv.Itoa(int(d.decoder.tcp.SrcPort)))
				}

				buffer.Reset()
				buffer.WriteString(src)
				buffer.WriteString("-")
				buffer.WriteString(dst)
				flowkey := buffer.String()

				idle := time.Duration(d.IdleTTL * int(time.Second))
				flow, exists := d.flows.Get(flowkey)
				if exists == false {
					// TCPAccounting objects self-expire if they are inactive for a period of time >idle
					if ourIP {
						flow = NewTCPAccounting(d.decoder.ip4.SrcIP, d.decoder.ip4.DstIP, d.decoder.tcp.SrcPort, d.decoder.tcp.DstPort, idle, &d.flows.Expire)
					} else {
						flow = NewTCPAccounting(d.decoder.ip4.DstIP, d.decoder.ip4.SrcIP, d.decoder.tcp.DstPort, d.decoder.tcp.SrcPort, idle, &d.flows.Expire)
					}
					flow.Lock()
					d.flows.Add(flowkey, flow)
					flow.SetExpiration(idle, flowkey)
				} else {
					//flow still alive - reset timer
					flow.Lock()
					flow.Alive.Reset(idle)
				}

				if d.ExpTTL > 0 && d.decoder.tcp.ACK && d.decoder.tcp.FIN && !flow.Done {
					expTTL := time.Duration(d.ExpTTL * int(time.Second))

					// Here we clean up flows that have expired by the book - that is, we have seen
					// the TCP stream come to an end FIN/ACK and have kept these around so short-lived
					// flows actually get reported.

					//set timer
					flow.Done = true
					flow.SetExpiration(expTTL, flowkey)
				}

				tcp_payload_sz := uint32(d.decoder.ip4.Length) - uint32((d.decoder.ip4.IHL+d.decoder.tcp.DataOffset)*4)
				if ourIP && tcp_payload_sz > 0 {
					var t TCPKey
					//get the TS
					ts, _, _ := GetTimestamps(&d.decoder.tcp)
					t.TS = ts
					t.Seq = d.decoder.tcp.Seq

					//insert or update
					flow.Timed[t] = ci.Timestamp.UnixNano()

				} else if !ourIP {
					var t TCPKey
					//get the TS
					_, tsecr, _ := GetTimestamps(&d.decoder.tcp)
					t.TS = tsecr
					t.Seq = d.decoder.tcp.Ack

					if flow.Timed[t] != 0 {
						if _, ok := flow.Seen[d.decoder.tcp.Ack]; !ok && d.decoder.tcp.ACK {
							//we can't receive an ACK for packet we haven't seen sent - we're the source
							rtt := uint64(ci.Timestamp.UnixNano() - flow.Timed[t])
							flow.CalcSRTT(rtt, d.Soften)
							flow.CalcJitter(rtt, d.Soften)
							flow.MaxRTT(rtt)
							flow.MinRTT(rtt)
							flow.Last = rtt
							flow.Sampled++

							//we can clean-up
							delete(flow.Timed, t)
						}
						flow.Seen[d.decoder.tcp.Ack] = struct{}{}
					}
				}
				flow.Unlock()
			}
		}
	}
	return nil
}

// Blocking Operation
func (d *MetroSniffer) EnqueuePacket(data []byte, info interface{}) error {
	ci, ok := info.(*gopacket.CaptureInfo)
	if !ok {
		return fmt.Errorf("unexpected info format")
	}

	pkt := PacketWrapper{packet: data, info: ci}
	select {
	case d.packets <- pkt:
	default:
		err := fmt.Errorf("Queue is full dropping packet...")
		log.Warnf("%v", err)
		return err

	}
	return nil
}

// Blocking Operation
func (d *MetroSniffer) DequeuePacket() ([]byte, *gopacket.CaptureInfo, error) {
	select {
	case pkt := <-d.packets:
		return pkt.packet, pkt.info, nil
	case <-time.After(time.Second):
	}
	return nil, nil, fmt.Errorf("no packets available")
}

func (d *MetroSniffer) Work() {

	quit := false
	for !quit {

		// Although desirable we're currently unable to use the ZeroCopy method
		// for reading packet data. Unfortunately successive calls invalidate the
		// data slice we're operating on. Giving place to bad results.
		// Keep this in mind as a viable optimization for the future:
		//   - packet retrieval using  ZeroCopyReadPacketData.
		data, ci, err := d.DequeuePacket()
		if err == nil {
			if d.config.Sample {
				ts := ci.Timestamp.UnixNano()
				if ts < d.sampleTS {
					//don't sleep to empty pcap buffer
				} else if ts > d.sampleDeadline {
					log.Debugf("Updating next sample period: %v", time.Unix(0, ts))
					d.sampleTS = d.sampleDeadline + (int64(d.config.SampleInterval) * time.Second.Nanoseconds())
					d.sampleDeadline = d.sampleTS + (int64(d.config.SampleDuration) * time.Second.Nanoseconds())
				} else {
					if err == nil {
						d.handlePacket(data, ci)
					}
				}
			} else {
				if err == nil {
					d.handlePacket(data, ci)
				}
			}

		}

		select {
		case <-d.t.Dying():
			log.Infof("Done sniffing.")
			quit = true
		default:
			continue
		}
	}
}

func (d *MetroSniffer) Process() error {

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Criticalf("Error getting interface details: %s", err)
		panic(err)
	}

	// we need to identify if we're the source/destination
	for _, iface := range ifaces {
		for _, address := range iface.Addresses {
			ipStr := address.IP.String()
			if strings.Contains(ipStr, "::") {
				log.Infof("IPv6 currently unsupported ignoring: %s", ipStr)
			} else {
				d.hostIPs[ipStr] = true
			}
		}
	}

	for i := range d.config.Hosts {
		hostIPs, err := net.LookupHost(d.config.Hosts[i])
		if err != nil {
			log.Errorf("Error resolving name for: %s", d.config.Hosts[i])
			continue
		}
		for k := range hostIPs {
			d.config.Ips = append(d.config.Ips, hostIPs[k])
			d.nameLookup[hostIPs[k]] = d.config.Hosts[i]
			log.Infof("%s resolving to: %s", d.config.Hosts[i], hostIPs[k])
		}
	}

	for i := range d.config.Ips {

		//add posible missing hostnames
		_, ok := d.nameLookup[d.config.Ips[i]]
		if !ok {
			hostnames, err := net.LookupAddr(d.config.Ips[i])
			if err != nil {
				log.Errorf("Problem looking up hostnames for: %s", d.config.Ips[i])
				continue
			}
			for j := range hostnames {
				d.nameLookup[d.config.Ips[i]] = hostnames[j]
				log.Infof("%s resolving to: %s", hostnames[j], d.config.Ips[i])
			}
		}
	}

	d.Work()

	for k := range d.flows.FlowMapKeyIterator() {
		flow, e := d.flows.Get(k)
		if e && flow.Sampled > 0 {
			if d.Soften {
				log.Infof("Flow %s\t w/ %d packets\tRTT:%6.2f ms", k, flow.Sampled, float64(int64(flow.SRTT)*int64(time.Nanosecond))/float64(time.Millisecond))
			} else {
				log.Infof("Flow %s\t w/ %d packets\tRTT:%6.2f ms", k, flow.Sampled, float64(flow.SRTT)*float64(time.Nanosecond)/float64(time.Millisecond))
			}
		}
	}
	return nil
}

func (d *MetroSniffer) Name() string {
	return processorName
}

func Factory(p string) (metro.Processor, error) {
	return NewSnifferFromYAML(p)
}
