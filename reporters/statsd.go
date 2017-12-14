package reporters

import (
	"errors"
	"io/ioutil"
	"net"
	"path/filepath"
	"strconv"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/DataDog/go-metro"
	log "github.com/cihub/seelog"
	"gopkg.in/yaml.v2"
)

const (
	statsdBufflen = 5
	reporterName  = "statsd"
)

type StatsdConfig struct {
	IP   string `yaml:"ip"`
	Port int32  `yaml:"port"`
}

type StatsdClient struct {
	client *statsd.Client
	ip     net.IP
	port   int32
}

func (c *StatsdConfig) Parse(data []byte) error {
	if err := yaml.Unmarshal(data, c); err != nil {
		return err
	}

	return nil
}

func NewStatsdClientFromYAML(path string) (*StatsdClient, error) {
	filename, _ := filepath.Abs(path)

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.New("configuration file not found")
	}
	var cfg StatsdConfig
	err = cfg.Parse(yamlFile)
	if err != nil {
		log.Criticalf("Error parsing configuration file: %s ", err)
		return nil, err
	}

	ip := net.ParseIP(cfg.IP)
	return NewStatsdClient(ip, cfg.Port)
}

func NewStatsdClient(ip net.IP, port int32) (*StatsdClient, error) {
	cli, err := statsd.NewBuffered(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), statsdBufflen)
	if err != nil {
		cli = nil
		log.Errorf("Error instantiating stats Statter: %v", err)
		return nil, err
	}

	client := &StatsdClient{
		client: cli,
		ip:     ip,
		port:   port,
	}

	return client, nil
}

func (s *StatsdClient) Submit(key, metric string, value float64, tags []string, asHistogram bool) error {
	var err error
	if asHistogram {
		err = s.client.Histogram(metric, value, tags, 1)
	} else {
		err = s.client.Gauge(metric, value, tags, 1)
	}
	if err != nil {
		log.Infof("There was an issue reporting metric: [%s] %s = %v - error: %v", key, metric, value, err)
		return err
	} else {
		log.Infof("Reported successfully! Metric: [%s] %s = %v - tags: %v", key, metric, value, tags)
	}
	return nil
}

func (s *StatsdClient) Name() string {
	return reporterName
}

func StatsdClientFactory(p string) (metro.Reporter, error) {
	return NewStatsdClientFromYAML(p)
}
