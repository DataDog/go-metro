package tcp

import (
	"errors"
	"gopkg.in/yaml.v2"
)

const fileInterface = "file"

type MetroTCPConfig struct {
	Interface      string   `yaml:"interface"`
	Pcap           string   `yaml:"pcap"`
	BPF            string   `yaml:"bpf_filter"`
	Snaplen        int      `yaml:"snaplen"`
	Sample         bool     `yaml:"sample"`
	SampleDuration int      `yaml:"sample_duration"`
	SampleInterval int      `yaml:"sample_interval"`
	IdleTTL        int      `yaml:"idle_ttl"`
	ExpTTL         int      `yaml:"expired_ttl"`
	Ips            []string `yaml:"ips"`
	Hosts          []string `yaml:"hosts"`
	Tags           []string `yaml:"tags"`
}

func (c *MetroTCPConfig) Parse(data []byte) error {
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
