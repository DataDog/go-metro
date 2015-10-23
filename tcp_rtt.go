// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// synscan implements a TCP syn scanner on top of pcap.
// It's more complicated than arpscan, since it has to handle sending packets
// outside the local network, requiring some routing and ARP work.
//
// Since this is just an example program, it aims for simplicity over
// performance.  It doesn't handle sending packets very quickly, it scans IPs
// serially instead of in parallel, and uses gopacket.Packet instead of
// gopacket.DecodingLayerParser for packet processing.  We also make use of very
// simple timeout logic with time.Since.
//
// Making it blazingly fast is left as an exercise to the reader.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Datadog/dd-tcp-rtt/ddsniff"
	"github.com/Datadog/dd-tcp-rtt/ddtypes"
	log "github.com/Sirupsen/logrus"
	"github.com/google/gopacket/pcap"
)

var filter = flag.String("f", "tcp", "BPF filter for pcap")
var soften = flag.Bool("st", true, "Soften RTTM")
var cfg = flag.String("cfg", "/etc/dd-agent/checks.d/dd-tcp-rtt.yaml", "YAML configuration file.")

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func initLogging(level string) {

	log.SetOutput(os.Stderr)

	switch {
	case strings.EqualFold(level, "debug"):
		log.SetLevel(log.DebugLevel)
	case strings.EqualFold(level, "info"):
		log.SetLevel(log.InfoLevel)
	case strings.EqualFold(level, "warning"):
		log.SetLevel(log.WarnLevel)
	case strings.EqualFold(level, "error"):
		log.SetLevel(log.ErrorLevel)
	default:
		log.Infof("Configured log level \"%s\" unknown - defaulting to WARNING level.", level)
		log.SetLevel(log.WarnLevel)
	}
}

func main() {
	flag.Parse()

	//Parse config
	filename, _ := filepath.Abs(*cfg)

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}

	var cfg ddtypes.RTTConfig
	err = cfg.Parse(yamlFile)
	if err != nil {
		log.Fatalf("Error parsing configuration file: %s ", err)
	}

	//set logging
	initLogging(cfg.InitConf.Log_level)

	//Install signal handler
	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	exit_chan := make(chan bool)
	go func() {
		for {
			s := <-signal_chan
			switch s {
			// kill -SIGHUP XXXX
			case syscall.SIGHUP:
				log.Warn("hungup")
				exit_chan <- true

				// kill -SIGINT XXXX or Ctrl+c
			case syscall.SIGINT:
				log.Warn("sig int caught, shutting down.")
				exit_chan <- true

				// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				log.Warn("force stop")
				exit_chan <- true

				// kill -SIGQUIT XXXX
			case syscall.SIGQUIT:
				log.Warn("stop and core dump")
				exit_chan <- true

			default:
				fmt.Println("Unknown signal.")
			}
		}
	}()

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error getting interface details: %s", err)
	}

	sniffers := make([]*ddsniff.DatadogSniffer, 0)
	for i := range cfg.Configs {
		for j := range ifaces {
			if ifaces[j].Name == cfg.Configs[i].Interface {
				log.Infof("Will attempt sniffing off interface %q", cfg.Configs[i].Interface)
				rttsniffer := ddsniff.NewDatadogSniffer(cfg.InitConf, cfg.Configs[i], *filter)
				sniffers = append(sniffers, rttsniffer)
			}
		}
	}

	if len(sniffers) == 0 {
		log.Fatalf("No sniffers available, baling out (please check your privileges).")
	}

	quit := false
	for !quit {
		msg := <-exit_chan
		switch msg {
		case true:
			quit = true
		case false:
		default:
			quit = false
		}
	}

	//Stop the show
	for i := range sniffers {
		err := sniffers[i].Stop()
		if err != nil {
			log.Infof("Error shutting down %s sniffer: %v.", sniffers[i].Iface, err)
		}
	}

}
