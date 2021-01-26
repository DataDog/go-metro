package dns

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"gopkg.in/tomb.v2"

	"github.com/DataDog/go-metro"
	log "github.com/cihub/seelog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	reportInterval = 1
	processorName  = "dns"
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
	udp           layers.UDP
	dns           layers.DNS
	payload       gopacket.Payload
	parser        *gopacket.DecodingLayerParser
	decoded       []gopacket.LayerType
}

func NewMetroDecoder() *MetroDecoder {
	d := &MetroDecoder{
		decoded: make([]gopacket.LayerType, 0, 4),
	}
	d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&d.eth, &d.dot1q, &d.ip4, &d.ip6, &d.ip6extensions,
		&d.tcp, &d.udp, &d.dns, &d.payload)

	return d
}

// We use a DecodingLayerParser here instead of a simpler PacketSource.
// This approach should be measurably faster, but is also more rigid.
// PacketSource will handle any known type of packet safely and easily,
// but DecodingLayerParser will only handle those packet types we
// specifically pass in.  This trade-off can be quite useful, though, in
// high-throughput situations.
type MetroDNSProcessor struct {
	decoder    *MetroDecoder
	requests   *DNSStats
	responses  *DNSStats
	reporters  map[string]metro.Reporter
	reportIval time.Duration
	config     MetroDNSConfig
	packets    chan PacketWrapper
	to         chan struct{}
	t          tomb.Tomb
}

type PacketWrapper struct {
	packet []byte
	info   *gopacket.CaptureInfo
}

func NewProcessorFromYAML(path string) (metro.Processor, error) {
	//Parse config
	filename, _ := filepath.Abs(path)

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.New("configuration file not found")
	}

	var cfg MetroDNSConfig
	err = cfg.Parse(yamlFile)
	if err != nil {
		log.Criticalf("Error parsing configuration file: %s ", err)
		return nil, err
	}

	return NewMetroDNSProcessor(cfg)

}

func NewMetroDNSProcessor(cfg MetroDNSConfig) (*MetroDNSProcessor, error) {
	d := &MetroDNSProcessor{
		requests:   NewDNSStats(),
		responses:  NewDNSStats(),
		reporters:  make(map[string]metro.Reporter),
		reportIval: time.Duration(reportInterval) * time.Second,
		config:     cfg,
		packets:    make(chan PacketWrapper, inflight),
	}
	d.decoder = NewMetroDecoder()

	return d, nil
}

func (d *MetroDNSProcessor) Start() error {
	d.t.Go(d.Report)
	d.t.Go(d.Process)

	return nil
}

func (d *MetroDNSProcessor) Stop() error {
	d.t.Kill(nil)
	return d.t.Wait()
}

func (d *MetroDNSProcessor) Running() bool {
	return d.t.Alive()
}

func (d *MetroDNSProcessor) RegisterReporter(id string, reporter metro.Reporter) error {
	if _, ok := d.reporters[id]; ok {
		return errors.New("Reporter already registered")
	}

	d.reporters[id] = reporter
	return nil
}

func (d *MetroDNSProcessor) die(err error) {
	d.t.Kill(err)
}

func (d *MetroDNSProcessor) handlePacket(data []byte, ci *gopacket.CaptureInfo) error {

	err := d.decoder.parser.DecodeLayers(data, &d.decoder.decoded)
	if err != nil {
		log.Infof("error decoding packet: %v", err)
		return err
	}
	// Find either the IPv4 or IPv6 address to use as our network
	// layer.
	foundNetLayer := false
	foundIPv4Layer := false
	foundIPv6Layer := false
	foundTransport := false
	for _, typ := range d.decoder.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			foundNetLayer = true
			foundIPv4Layer = true
		case layers.LayerTypeIPv6:
			foundNetLayer = true
			foundIPv6Layer = true
		case layers.LayerTypeUDP:
			foundTransport = true
		case layers.LayerTypeTCP:
			foundTransport = true
		case layers.LayerTypeDNS:
			isIP := foundIPv6Layer || foundIPv4Layer
			if foundNetLayer && foundTransport && isIP {
				// If the list of answers is 0 and no error-code assume its a request
				if len(d.decoder.dns.Answers) == 0 && len(d.decoder.dns.Questions) > 0 {
					d.requests.Increment(d.decoder.ip4.DstIP.String())
				} else {
					d.responses.Increment(d.decoder.ip4.DstIP.String())
				}
			}
		}
	}
	return nil
}

// Blocking Operation
func (d *MetroDNSProcessor) EnqueuePacket(data []byte, info interface{}) error {
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
func (d *MetroDNSProcessor) DequeuePacket() ([]byte, *gopacket.CaptureInfo, error) {
	select {
	case pkt := <-d.packets:
		return pkt.packet, pkt.info, nil
	case <-time.After(time.Second):
	}
	return nil, nil, fmt.Errorf("no packets available")
}

func (d *MetroDNSProcessor) Work() {

	quit := false
	for !quit {

		// Although desirable we're currently unable to use the ZeroCopy method
		// for reading packet data. Unfortunately successive calls invalidate the
		// data slice we're operating on. Giving place to bad results.
		// Keep this in mind as a viable optimization for the future:
		//   - packet retrieval using  ZeroCopyReadPacketData.
		data, ci, err := d.DequeuePacket()
		if err == nil {
			d.handlePacket(data, ci)
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

func (d *MetroDNSProcessor) Process() error {
	d.Work()

	return nil
}

func (d *MetroDNSProcessor) Name() string {
	return processorName
}

func Factory(p string) (metro.Processor, error) {
	return NewProcessorFromYAML(p)
}
