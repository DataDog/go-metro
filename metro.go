// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	log "github.com/cihub/seelog"
	"github.com/google/gopacket/pcap"
)

const (
	defaultConfigFile = "/etc/dd-agent/checks.d/go-metro.yaml"
	defaultLogFile    = "/var/log/datadog/go-metro.log"
	defaultBPFFilter  = "tcp"
	baseFileLogConfig = `<seelog minlevel="ddloglevel">
	<outputs formatid="common">
		<rollingfile type="size" filename="ddlogfile" maxsize="100000" maxrolls="5" />
	</outputs>
	<formats>
		<format id="common" format="%Date %Time TIMEZONE | %LEVEL | (%File:%Line) |  %Msg%n" />
	</formats>
</seelog>`
	baseStdoLogConfig = `<seelog minlevel="ddloglevel">
	<outputs formatid="common">
		<console />
	</outputs>
	<formats>
		<format id="common" format="%Date %Time TIMEZONE | %LEVEL | (%File:%Line) |  %Msg%n"/>
	</formats>
</seelog>`
)

var cfg = flag.String("cfg", defaultConfigFile, "YAML configuration file.")
var logfile = flag.String("log", defaultLogFile, "Destination log file.")
var filter = flag.String("f", defaultBPFFilter, "BPF filter for pcap")
var soften = flag.Bool("st", true, "Soften RTTM")

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func initLogging(to_file bool, level string) {
	loglevel := "warn"

	switch {
	case strings.EqualFold(level, "trace"):
		loglevel = "trace"
	case strings.EqualFold(level, "debug"):
		loglevel = "debug"
	case strings.EqualFold(level, "info"):
		loglevel = "info"
	case strings.EqualFold(level, "error"):
	case strings.EqualFold(level, "err"):
		loglevel = "error"
	case strings.EqualFold(level, "critical"):
	case strings.EqualFold(level, "crit"):
		loglevel = "critical"
	case strings.EqualFold(level, "warning"):
	case strings.EqualFold(level, "warn"):
	default:
		log.Infof("Configured log level \"%s\" unknown - defaulting to WARNING level.", level)
	}

	var logConfig []byte

	timezone, _ := time.Now().Zone()
	if to_file {
		logConfig = bytes.Replace([]byte(baseFileLogConfig), []byte("ddloglevel"), []byte(strings.ToLower(loglevel)), 1)
		logConfig = bytes.Replace([]byte(logConfig), []byte("ddlogfile"), []byte(*logfile), 1)
	} else {
		logConfig = bytes.Replace([]byte(baseStdoLogConfig), []byte("ddloglevel"), []byte(strings.ToLower(loglevel)), 1)
	}
	logConfig = bytes.Replace([]byte(logConfig), []byte("TIMEZONE"), []byte(strings.ToUpper(timezone)), 1)
	logger, err := log.LoggerFromConfigAsBytes(logConfig)
	if err != nil {
		log.Criticalf("Unable to initiate logger: %s", err)
		os.Exit(1)
	}
	log.ReplaceLogger(logger)

}

func main() {
	flag.Parse()

	initLogging(true, "warning")

	//Parse config
	filename, _ := filepath.Abs(*cfg)

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		//hack so that supervisord doesnt consider it "too quick" an exit.
		time.Sleep(time.Second * 5)
		os.Exit(0)
	}

	var cfg MetroConfig
	err = cfg.Parse(yamlFile)
	if err != nil {
		log.Criticalf("Error parsing configuration file: %s ", err)
		os.Exit(1)
	}

	//set logging
	if cfg.InitConf.LogToFile {
		initLogging(true, cfg.InitConf.LogLevel)
	} else {
		initLogging(false, cfg.InitConf.LogLevel)
	}

	//Install signal handler
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	exitChan := make(chan bool)
	go func() {
		for {
			s := <-signalChan
			switch s {
			// kill -SIGHUP XXXX
			case syscall.SIGHUP:
				log.Warn("hungup")
				exitChan <- true

				// kill -SIGINT XXXX or Ctrl+c
			case syscall.SIGINT:
				log.Warn("sig int caught, shutting down.")
				exitChan <- true

				// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				log.Warn("force stop")
				exitChan <- true

				// kill -SIGQUIT XXXX
			case syscall.SIGQUIT:
				log.Warn("stop and core dump")
				exitChan <- true

			default:
				fmt.Println("Unknown signal.")
			}
		}
	}()

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Criticalf("Error getting interface details: %s", err)
		os.Exit(1)
	}

	sniffers := make([]*MetroSniffer, 0)
	for i := range cfg.Configs {
		for j := range ifaces {
			if ifaces[j].Name == cfg.Configs[i].Interface {
				log.Infof("Will attempt sniffing off interface %q", cfg.Configs[i].Interface)
				metrosniffer, err := NewMetroSniffer(cfg.InitConf, cfg.Configs[i], *filter)
				if err == nil {
					sniffers = append(sniffers, metrosniffer)
					metrosniffer.Start()
				} else {
					log.Errorf("Unable to instantiate sniffer for interface %q", cfg.Configs[i].Interface)
				}
			}
		}
	}

	if len(sniffers) == 0 {
		log.Criticalf("No sniffers available, baling out (please check your configuration and privileges).")
		os.Exit(1)
	}

	//Check all sniffers are up and running or quit.
	log.Debug("Waiting for sniffers to start...")
	time.Sleep(time.Second)
	for i := range sniffers {
		running := sniffers[i].Running()
		if !running {
			log.Criticalf("Unable to start sniffer for interface: %q (please check your configuration and privileges).", sniffers[i].Iface)
			os.Exit(1)
		}
	}

	quit := false
	for !quit {
		msg := <-exitChan
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
