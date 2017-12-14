package tcp

import (
	"gopkg.in/yaml.v2"
)

type MetroTCPConfig struct {
	Sample         bool `yaml:"sample"`
	SampleDuration int  `yaml:"sample_duration"`
	SampleInterval int  `yaml:"sample_interval"`
	IdleTTL        int  `yaml:"idle_ttl"`
	ExpTTL         int  `yaml:"expired_ttl"`
	// TODO: Check what we do with Ips and Hosts here
	Ips   []string `yaml:"ips"`
	Hosts []string `yaml:"hosts"`
	Tags  []string `yaml:"tags"`
}

func (c *MetroTCPConfig) Parse(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}

	return nil
}
