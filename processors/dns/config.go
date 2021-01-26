package dns

import (
	"gopkg.in/yaml.v2"
)

type MetroDNSConfig struct {
	Tags []string `yaml:"tags"`
}

func (c *MetroDNSConfig) Parse(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}

	return nil
}
