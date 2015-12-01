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
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Datadog/dd-tcp-rtt/ddsniff"
	"github.com/google/gopacket/pcap"
)

var snaplen = flag.Int("sz", 65536, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var soften = flag.Bool("st", false, "Soften RTTM")
var logAllPackets = flag.Bool("v", false, "Log whenever we see a packet")
var getMinRTT = flag.Bool("m", false, "Return the minimum RTT we have for a given connection.")
var packetCount = flag.Int("c", -1, `Quit after processing this many packets. If negative, ad infinitum.
If specified together with the 't' flag, which happens first will end execution`)
var sniffTime = flag.Int("t", -1, `Quit after processing packets for this many seconds. If negative or zero, ad infinitum.
If specified together with the 'c' flag, which happens first will end execution`)
var expiration_TTL = flag.Int("ttl", 60, `TTL after flow ends - after this time it will be flushed.`)
var idle_TTL = flag.Int("idle", 300, `TTL a flow can remain idle - after this time it will be flushed.`)
var statsd_ip = flag.String("r", "127.0.0.1", "IP address to the stats service")
var statsd_port = flag.Int("p", 8125, "Port to the stats service.")

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var myInterfaces arrayFlags

func main() {
	flag.Var(&myInterfaces, "iface", "Interface we wish to sniff from.")
	flag.Parse()

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
				fmt.Println("hungup")
				exit_chan <- true

				// kill -SIGINT XXXX or Ctrl+c
			case syscall.SIGINT:
				fmt.Println("sig int caught, shutting down.")
				exit_chan <- true

				// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				fmt.Println("force stop")
				exit_chan <- true

				// kill -SIGQUIT XXXX
			case syscall.SIGQUIT:
				fmt.Println("stop and core dump")
				exit_chan <- true

			default:
				fmt.Println("Unknown signal.")
			}
		}
	}()

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error getting interface details: ", err)
	}

	sniffers := make([]*ddsniff.DatadogSniffer, 0)
	for i := range myInterfaces {
		for j := range ifaces {
			if ifaces[j].Name == myInterfaces[i] {
				log.Printf("Will attempt sniffing off interface %q", myInterfaces[i])
				rttsniffer := ddsniff.NewDatadogSniffer(myInterfaces[i], *snaplen, *filter, *expiration_TTL, *idle_TTL, *statsd_ip, int32(*statsd_port))
				sniffers = append(sniffers, rttsniffer)
			}
		}
	}

	if len(sniffers) == 0 {
		log.Fatal("No sniffers available, baling out (please check your privileges).")
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
			log.Printf("Error shutting down %s sniffer: %v.", sniffers[i].Iface, err)
		}
	}

}
