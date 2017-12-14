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

	"github.com/DataDog/go-metro"
	"github.com/DataDog/go-metro/processors/tcp"
	"github.com/DataDog/go-metro/reporters"
	log "github.com/cihub/seelog"
)

const (
	defaultConfigFile = "/etc/dd-agent/checks.d/go-metro.yaml"
	defaultLogFile    = "/var/log/datadog/go-metro.log"
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
var soften = flag.Bool("st", true, "Soften RTTM")

func init() {
	metro.RegisterProcessorFactory("tcp", tcp.Factory)
	metro.RegisterReporterFactory("statsd", reporters.StatsdClientFactory)
}

func initLogging(to_file bool, level string) log.LoggerInterface {
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
		panic(err)
	}
	log.ReplaceLogger(logger)
	return logger

}

func main() {
	defer log.Flush()
	flag.Parse()

	logger := initLogging(true, "warning")

	//Parse config
	filename, _ := filepath.Abs(*cfg)

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		//hack so that supervisord doesnt consider it "too quick" an exit.
		time.Sleep(time.Second * 5)
		os.Exit(1)
	}

	var cfg metro.Config
	err = cfg.Parse(yamlFile)
	if err != nil {
		log.Criticalf("Error parsing configuration file: %s ", err)
		os.Exit(1)
	}

	//set logging
	if cfg.LogToFile {
		logger = initLogging(true, cfg.LogLevel)
	} else {
		logger = initLogging(false, cfg.LogLevel)
	}
	defer logger.Close()

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

	// instantiate reporters
	for _, reporterCfg := range cfg.ReportModules {
		factory, ok := metro.ReporterFactories[reporterCfg.Name]
		if !ok {
			log.Warnf("Reporter factory unavailable, continue...")
			continue
		}
		r, err := factory(reporterCfg.ModuleConfig)
		if err != nil {
			log.Warnf("Issue instantiating reporter: %v", err)
			continue
		}
		if _, ok := metro.Reporters[r.Name()]; ok {
			log.Warnf("Reporter already instantiated: %v", r.Name())
			continue
		}
		metro.Reporters[r.Name()] = r
	}

	// instantiate processors
	for _, processorCfg := range cfg.ProcessModules {
		factory, ok := metro.ProcessorFactories[processorCfg.Name]
		if !ok {
			log.Warnf("Processor factory unavailable, continue...")
			continue
		}
		p, err := factory(processorCfg.ModuleConfig)
		if err != nil {
			log.Warnf("Issue instantiating reporter: %v", err)
			continue
		}

		if _, ok := metro.Processors[p.Name()]; ok {
			log.Warnf("Processor already instantiated: %v", p.Name())
			continue
		}
		metro.Processors[p.Name()] = p
	}

	if len(metro.Processors) == 0 {
		log.Criticalf("No network processors could be configured, baling out (please check your configuration and privileges).")
		os.Exit(1)
	}

	// Register Reporters with Processors
	for _, reporter := range metro.Reporters {
		for _, processor := range metro.Processors {
			processor.RegisterReporter(reporter.Name(), reporter)
		}
	}

	// Start all processors
	for _, processor := range metro.Processors {
		processor.Start()
	}

	//Check all sniffers are up and running or quit.
	log.Debug("Waiting for processors to settle...")
	time.Sleep(time.Second)
	for _, processor := range metro.Processors {
		running := processor.Running()
		if !running {
			log.Criticalf("Processor failed to start - quitting...")
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
	for _, processor := range metro.Processors {
		err := processor.Stop()
		if err != nil {
			log.Infof("Error shutting down %s sniffer: %v.", processor, err)
		}
	}
}
