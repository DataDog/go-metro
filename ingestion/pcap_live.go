package ingestion

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/DataDog/go-metro"
	log "github.com/cihub/seelog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

const (
	fileInterface = "file"
	ingestorName  = "pcap"
)

var (
	CompatibleProcessors = []string{"tcp-rtt", "dns"}
)

type PcapConfig struct {
	Interface string   `yaml:"interface"`
	Pcap      string   `yaml:"pcap"`
	BPF       string   `yaml:"bpf_filter"`
	Snaplen   int      `yaml:"snaplen"`
	Ips       []string `yaml:"ips"`
	Hosts     []string `yaml:"hosts"`
}

type PcapSniffer struct {
	Iface      string
	Snaplen    int
	Filter     string
	Processors map[string]metro.Processor
	pcapHandle *pcap.Handle
	config     PcapConfig
	t          tomb.Tomb
}

func (c *PcapConfig) Parse(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}

	if c.Interface == "" {
		return errors.New("Error parsing configuration - empty iface field.")
	} else if c.Interface == fileInterface && c.Pcap == "" {
		return errors.New("Error parsing configuration - empty pcap field for file interface.")
	}

	return nil
}

func NewPcapSnifferFromYAML(path string) (*PcapSniffer, error) {
	//Parse config
	filename, _ := filepath.Abs(path)

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.New("configuration file not found")
	}

	var cfg PcapConfig
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

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Criticalf("Error getting interface details: %s", err)
		return nil, err
	}

	for j := range ifaces {
		if ifaces[j].Name == cfg.Interface {
			log.Infof("Will attempt sniffing off interface %q", cfg.Interface)
			return NewPcapSniffer(cfg)
		}
	}

	return nil, errors.New("Unable to find matching interface to sniff")
}

func NewPcapSniffer(cfg PcapConfig) (*PcapSniffer, error) {
	d := &PcapSniffer{
		Iface:      cfg.Interface,
		Snaplen:    cfg.Snaplen,
		Filter:     cfg.BPF,
		Processors: make(map[string]metro.Processor),
		pcapHandle: nil,
	}

	return d, nil
}

func (d *PcapSniffer) Start() error {
	log.Infof("Starting PCAP ingestor...")
	d.t.Go(d.Sniff)

	return nil
}

func (d *PcapSniffer) Stop() error {
	d.t.Kill(nil)
	return d.t.Wait()
}

func (d *PcapSniffer) Running() bool {
	return d.t.Alive()
}

func (d *PcapSniffer) die(err error) {
	d.t.Kill(err)
}

func (d *PcapSniffer) SetPcapHandle(handle *pcap.Handle) {
	d.pcapHandle = handle
}

func (d *PcapSniffer) SniffLive() {
	quit := false

	for !quit {

		// Although desirable we're currently unable to use the ZeroCopy method
		// for reading packet data. Unfortunately successive calls invalidate the
		// data slice we're operating on. Giving place to bad results.
		// Keep this in mind as a viable optimization for the future:
		//   - packet retrieval using  ZeroCopyReadPacketData.
		data, ci, err := d.pcapHandle.ReadPacketData()
		if err == nil {
			for _, p := range d.Processors {
				p.EnqueuePacket(data, &ci)
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

func (d *PcapSniffer) SniffOffline() {
	packetSource := gopacket.NewPacketSource(d.pcapHandle, d.pcapHandle.LinkType())

	for packet := range packetSource.Packets() {
		//Grab Packet CaptureInfo metadata
		ci := packet.Metadata().CaptureInfo
		for _, p := range d.Processors {
			p.EnqueuePacket(packet.Data(), &ci)
		}

		select {
		case <-d.t.Dying():
			log.Infof("Done sniffing.")
			break
		default:
			continue
		}
	}
}

func (d *PcapSniffer) Sniff() error {

	if d.pcapHandle == nil {

		log.Infof("starting capture on interface %q", d.Iface)

		if d.Iface != fileInterface {
			// Set up pcap packet capture
			inactive, err := pcap.NewInactiveHandle(d.Iface)
			if err != nil {
				log.Errorf("Unable to create inactive handle for %q", d.Iface)
				d.die(err)
				return err
			}
			defer inactive.CleanUp()

			inactive.SetSnapLen(d.Snaplen)
			inactive.SetPromisc(false)
			inactive.SetTimeout(time.Second)

			// TODO: Make the timestamp source selectable - Not all OS will allow that.
			//       call SupportedTimestamps() on handle to check what's available
			handle, err := inactive.Activate()
			if err != nil {
				log.Errorf("Unable to activate %q", d.Iface)
				d.die(err)
				return err
			}
			d.pcapHandle = handle
		} else {
			handle, err := pcap.OpenOffline(d.config.Pcap)
			if err != nil {
				log.Errorf("Unable to open pcap file %q", d.config.Pcap)
				d.die(err)
				return err
			}
			d.pcapHandle = handle
		}
	}

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Criticalf("Error getting interface details: %s", err)
		panic(err)
	}

	ifaceFound := false
	ifaceDetails := make([]pcap.Interface, len(ifaces)-1)
	for i := range ifaces {
		if ifaces[i].Name == d.Iface {
			ifaceDetails[i] = ifaces[i]
			ifaceFound = true
		}
	}

	if !ifaceFound && d.Iface != fileInterface {
		err = fmt.Errorf("Could not find interface details for: %s", d.Iface)
		log.Criticalf("%v", err)
		panic(err)
	}

	// translate hostnames to IP addresses
	for i := range d.config.Hosts {
		hostIPs, err := net.LookupHost(d.config.Hosts[i])
		if err != nil {
			log.Errorf("Error resolving name for: %s", d.config.Hosts[i])
			continue
		}
		for k := range hostIPs {
			d.config.Ips = append(d.config.Ips, hostIPs[k])
		}
	}

	// build additional BPF filter expressions
	hosts := make([]string, 0)
	for i := range d.config.Ips {
		hosts = append(hosts, fmt.Sprintf("host %s", d.config.Ips[i]))
	}

	//let's make sure they haven't just whitelisted local ips/hosts
	// localWhitelist := true
	// for _, host := range d.config.Ips {
	// 	_, local := d.hostIPs[host]
	// 	if !local {
	// 		localWhitelist = false
	// 	}
	// }
	// if localWhitelist {
	// 	err := errors.New("Whitelist cannot contain just local addresses! Bailing out")
	// 	log.Errorf("%v : %v", err, hosts)
	// 	d.die(err)
	// 	return err
	// }

	bpfFilter := ""
	if len(hosts) > 0 {
		bpfFilter = "(" + strings.Join(hosts, " or ") + ")"
	}

	d.Filter += " and not host 127.0.0.1"
	if len(hosts) > 0 {
		d.Filter += " and " + bpfFilter
	}

	log.Infof("Setting BPF filter: %s", d.Filter)
	if err := d.pcapHandle.SetBPFFilter(d.Filter); err != nil {
		log.Criticalf("error setting BPF filter: %s", err)
		panic(err)
	}

	log.Infof("reading in packets")
	if d.Iface == fileInterface {
		d.SniffOffline()
	} else {
		d.SniffLive()
	}

	return nil
}

func (d *PcapSniffer) RegisterProcessor(id string, p metro.Processor) error {
	if _, ok := d.Processors[id]; ok {
		return errors.New("Processor already registered.")
	}

	for _, supported := range CompatibleProcessors {
		if supported == p.Name() {
			d.Processors[id] = p
			return nil
		}
	}

	return errors.New("Unsupported processor - could not add.")
}

func (d *PcapSniffer) Name() string {
	return ingestorName
}

func PcapSnifferFactory(p string) (metro.Ingestor, error) {
	return NewPcapSnifferFromYAML(p)
}
