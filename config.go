package main

import (
	"errors"
	"gopkg.in/yaml.v2"
)

type InitConfig struct {
	Snaplen     int    `yaml:"snaplen"`
	IdleTTL     int    `yaml:"idle_ttl"`
	ExpTTL      int    `yaml:"expired_ttl"`
	Statsd_IP   string `yaml:"statsd_ip"`
	Statsd_port int    `yaml:"statsd_port"`
	Log_level   string `yaml:"log_level"`
}

type Config struct {
	Interface string   `yamls:"interface"`
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
		}
	}

	return nil
}
