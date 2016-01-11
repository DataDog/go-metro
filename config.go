package main

import (
	"errors"
	"gopkg.in/yaml.v2"
)

const fileInterface = "file"

type InitConfig struct {
	Snaplen    int    `yaml:"snaplen"`
	IdleTTL    int    `yaml:"idle_ttl"`
	ExpTTL     int    `yaml:"expired_ttl"`
	StatsdIP   string `yaml:"statsd_ip"`
	StatsdPort int    `yaml:"statsd_port"`
	LogToFile  bool   `yaml:"log_to_file"`
	LogLevel   string `yaml:"log_level"`
}

type Config struct {
	Interface string   `yaml:"interface"`
	Pcap      string   `yaml:"pcap"`
	Ips       []string `yaml:"ips"`
	Tags      []string `yaml:"tags"`
}

type RTTConfig struct {
	InitConf InitConfig `yaml:"init_config"`
	Configs  []Config   `yaml:"config"`
}

func (c *RTTConfig) Parse(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}
	if len(c.Configs) == 0 {
		return errors.New("No sniffing interfaces specified.")
	}

	for i := range c.Configs {
		if c.Configs[i].Interface == "" {
			return errors.New("Error parsing configuration - empty iface field.")
		} else if c.Configs[i].Interface == fileInterface && c.Configs[i].Pcap == "" {
			return errors.New("Error parsing configuration - empty pcap field for file interface.")
		}
	}

	return nil
}
