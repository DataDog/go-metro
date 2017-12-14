package metro

import (
	"errors"
	"gopkg.in/yaml.v2"
)

type ModuleConfig struct {
	Name         string `yaml:"plugin_name"`
	ModulePath   string `yaml:"plugin_path"`
	ModuleConfig string `yaml:"plugin_config_path"`
}

type Config struct {
	LogToFile        bool           `yaml:"log_to_file"`
	LogLevel         string         `yaml:"log_level"`
	ProcessModules   []ModuleConfig `yaml:"process_modules"`
	ReportModules    []ModuleConfig `yaml:"report_modules"`
	IngestionModules []ModuleConfig `yaml:"ingestion_modules"`
}

func (c *Config) Parse(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}
	if len(c.ProcessModules) == 0 {
		return errors.New("No process modules specified")
	}
	if len(c.ReportModules) == 0 {
		return errors.New("No report modules specified")
	}
	if len(c.IngestionModules) == 0 {
		return errors.New("No report modules specified")
	}

	return nil
}
