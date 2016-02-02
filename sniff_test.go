package main

import (
	"testing"
	"time"
)

const goodCfg = `
init_config:
    snaplen: 512
    idle_ttl: 300
    exp_ttl: 60
    statsd_ip: 127.0.0.1
    statsd_port: 8125
    log_to_file: true
    log_level: debug

config:
- interface: en0
  tags: [mytag]
  ips: []
`

const goodFileCfg = `
init_config:
    snaplen: 512
    idle_ttl: 300
    exp_ttl: 60
    statsd_ip: 127.0.0.1
    statsd_port: 8125
    log_to_file: true
    log_level: debug

config:
- interface: file
  pcap: fixtures/test_tcp.pcap
  tags: [mytag]
  ips: []
`

const scpFileCfg = `
init_config:
    snaplen: 512
    idle_ttl: 300
    exp_ttl: 60
    statsd_ip: 127.0.0.1
    statsd_port: 8125
    log_to_file: true
    log_level: debug

config:
- interface: file
  pcap: fixtures/test_scp.pcap
  tags: [scp]
  ips: []
`

const badFileCfg = `
init_config:
    snaplen: 512
    idle_ttl: 300
    exp_ttl: 60
    statsd_ip: 127.0.0.1
    statsd_port: 8125
    log_to_file: true
    log_level: debug

config:
- interface: file
  tags: [mytag]
  ips: []
`

const badCfg = `
init_config:
    snaplen: 512
    idle_ttl: 300
    exp_ttl: 60
    statsd_ip: 127.0.0.1
    statsd_port: 8125
    log_to_file: true
    log_level: debug

config:
`

const badInterfaceCfg = `
init_config:
    snaplen: 512
    idle_ttl: 300
    exp_ttl: 60
    statsd_ip: 127.0.0.1
    statsd_port: 8125
    log_to_file: true
    log_level: debug

config:
- interface: noifc0
  tags: [mytag]
  ips: []
`

func TestParseConfig(t *testing.T) {
	var cfg MetroConfig
	err := cfg.Parse([]byte(goodCfg))
	if err != nil {
		t.Fatalf("MetroConfig.parse expected == nil, got %q", err)
	}
}

func TestParseBadConfig(t *testing.T) {
	var cfg MetroConfig
	err := cfg.Parse([]byte(badCfg))
	if err == nil {
		t.Fatalf("MetroConfig.parse expected error, got %q", err)
	}
}

func TestBadInterfaceSniffer(t *testing.T) {
	var cfg MetroConfig
	err := cfg.Parse([]byte(badInterfaceCfg))
	if err != nil {
		t.Fatalf("MetroConfig.parse expected == %q, got %q", nil, err)
	}

	rttsniffer, err := NewMetroSniffer(cfg.InitConf, cfg.Configs[0], "tcp")

	//sniff
	err = rttsniffer.Sniff()
	if err == nil {
		t.Fatalf("MetroConfig.parse expected error, but got %q", err)
	}
}

func TestSnifferFromBadFile(t *testing.T) {
	var cfg MetroConfig
	err := cfg.Parse([]byte(badFileCfg))
	if err == nil {
		t.Fatalf("MetroConfig.parse expected error, got %v", nil)
	}
}

func TestSnifferFromFile(t *testing.T) {
	var cfg MetroConfig
	err := cfg.Parse([]byte(goodFileCfg))
	if err != nil {
		t.Fatalf("MetroConfig.parse expected == %q, got %q", nil, err)
	}

	rttsniffer, err := NewMetroSniffer(cfg.InitConf, cfg.Configs[0], "tcp")

	//set artificial host_ip 192.168.1.116 (from pcap)
	rttsniffer.hostIPs["192.168.1.116"] = true
	//sniff
	err = rttsniffer.Sniff()
	if err != nil {
		t.Fatalf("Problem running sniffer expected %v, got %v - cfg %v", nil, err, cfg.Configs[0])
	}

	n_flows := 0
	for k := range rttsniffer.flows.FlowMapKeyIterator() {
		n_flows++
		flow, e := rttsniffer.flows.Get(k)
		if flow.Src.String() != "192.168.1.116" {
			t.Fatalf("Bad Source IP in flow.")
		}
		if e && flow.Sampled > 0 {
			t.Fatalf("One way HTTP flow can't be sampled for RTT reliably")
		}
	}

	if n_flows == 0 {
		t.Fatalf("Flow was not detected!")
	}
}

func TestSnifferFromScp(t *testing.T) {
	var cfg MetroConfig
	err := cfg.Parse([]byte(scpFileCfg))
	if err != nil {
		t.Fatalf("MetroConfig.parse expected == %q, got %q", nil, err)
	}

	rttsniffer, err := NewMetroSniffer(cfg.InitConf, cfg.Configs[0], "tcp")

	//set artificial host_ip 10.42.31.222 (from pcap)
	rttsniffer.hostIPs["10.42.31.222"] = true
	//sniff
	err = rttsniffer.Sniff()
	if err != nil {
		t.Fatalf("Problem running sniffer expected %v, got %v - cfg %v", nil, err, cfg.Configs[0])
	}

	n_flows := 0
	for k := range rttsniffer.flows.FlowMapKeyIterator() {
		n_flows++
		flow, e := rttsniffer.flows.Get(k)
		if flow.Src.String() != "10.42.31.222" {
			t.Fatalf("Bad Source IP in flow.")
		}
		if e && flow.Sampled == 0 {
			t.Fatalf("outgoing payloaded traffic, we should've sampled!")
		}
		value := float64(flow.SRTT) * float64(time.Nanosecond) / float64(time.Millisecond)
		value_jitter := float64(flow.Jitter) * float64(time.Nanosecond) / float64(time.Millisecond)
		value_last := float64(flow.Last) * float64(time.Nanosecond) / float64(time.Millisecond)

		t.Logf("samples %d", flow.Sampled)
		t.Logf("srtt %v", value)
		t.Logf("jitter %v", value_jitter)
		t.Logf("last %v", value_last)
	}

	if n_flows == 0 {
		t.Fatalf("Flow was not detected!")
	}
}
