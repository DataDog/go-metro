package main

import (
	"gopkg.in/tomb.v2"
	"net"
	"strconv"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	log "github.com/cihub/seelog"
)

type Client struct {
	client *statsd.Client
	ip     net.IP
	port   int32
	sleep  int32
	flows  *FlowMap
	tags   []string
	lookup map[string]string
	t      tomb.Tomb
}

const (
	statsdBufflen = 5
	statsdSleep   = 30
)

func NewClient(ip net.IP, port int32, sleep int32, flows *FlowMap, lookup map[string]string, tags []string) (*Client, error) {
	cli, err := statsd.NewBuffered(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), statsdBufflen)
	if err != nil {
		cli = nil
		log.Errorf("Error instantiating stats Statter: %v", err)
		return nil, err
	}

	r := &Client{
		client: cli,
		port:   port,
		sleep:  sleep,
		flows:  flows,
		tags:   tags,
		lookup: lookup,
	}
	r.t.Go(r.Report)
	return r, nil
}

func (r *Client) Stop() error {
	r.t.Kill(nil)
	return r.t.Wait()
}

func (r *Client) submit(key, metric string, value float64, tags []string, asHistogram bool) error {
	var err error
	if asHistogram {
		err = r.client.Histogram(metric, value, tags, 1)
	} else {
		err = r.client.Gauge(metric, value, tags, 1)
	}
	if err != nil {
		log.Infof("There was an issue reporting metric: [%s] %s = %v - error: %v", key, metric, value, err)
		return err
	} else {
		log.Infof("Reported successfully! Metric: [%s] %s = %v - tags: %v", key, metric, value, tags)
	}
	return nil
}

func (r *Client) Report() error {
	defer r.client.Close()

	log.Infof("Started reporting.")

	ticker := time.NewTicker(time.Duration(r.sleep) * time.Second)
	done := false
	for !done {
		select {
		case key := <-r.flows.Expire:
			r.flows.Delete(key)
			log.Infof("Flow expired: [%s]", key)
		case <-ticker.C:
			r.flows.Lock()
			for k := range r.flows.Map {
				flow, e := r.flows.GetUnsafe(k)
				flow.Lock()
				if e && flow.Sampled > 0 {
					success := true
					value := float64(flow.SRTT) * float64(time.Nanosecond) / float64(time.Millisecond)
					value_jitter := float64(flow.Jitter) * float64(time.Nanosecond) / float64(time.Millisecond)
					value_last := float64(flow.Last) * float64(time.Nanosecond) / float64(time.Millisecond)

					srcHost, ok := r.lookup[flow.Src.String()]
					if !ok {
						srcHost = flow.Src.String()
					}
					dstHost, ok := r.lookup[flow.Dst.String()]
					if !ok {
						dstHost = flow.Dst.String()
					}

					tags := []string{"link:" + srcHost + "-" + dstHost}
					tags = append(tags, r.tags...)

					metric := "system.net.tcp.rtt.avg"
					err := r.submit(k, metric, value, tags, false)
					if err != nil {
						success = false
					}
					metric = "system.net.tcp.rtt.jitter"
					err = r.submit(k, metric, value_jitter, tags, false)
					if err != nil {
						success = false
					}
					metric = "system.net.tcp.rtt.last"
					err = r.submit(k, metric, value_last, tags, false)
					if err != nil {
						success = false
					}
					if success {
						log.Debugf("Reported successfully on: %v", k)
					}
				}
				flow.Unlock()
			}
			r.flows.Unlock()
		case <-r.t.Dying():
			log.Infof("Done reporting.")
			done = true
		}
	}

	return nil
}
