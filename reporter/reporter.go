package reporter

import (
	"gopkg.in/tomb.v2"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/Datadog/dd-tcp-rtt/ddtypes"
)

type Client struct {
	client *statsd.Client
	ip     net.IP
	port   int32
	sleep  int32
	flows  *ddtypes.FlowMap
	tags   []string
	t      tomb.Tomb
}

const (
	Statsd_bufflen = 4
	Statsd_sleep   = 30
)

func NewClient(ip net.IP, port int32, sleep int32, flows *ddtypes.FlowMap, tags []string) *Client {
	cli, err := statsd.NewBuffered(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), Statsd_bufflen)
	if err != nil {
		cli = nil
		log.Printf("Error instantiating stats Statter: %v", err)
	}

	r := &Client{
		client: cli,
		port:   port,
		sleep:  sleep,
		flows:  flows,
		tags:   tags,
	}
	r.t.Go(r.Report)
	return r
}

func (r *Client) Stop() error {
	r.t.Kill(nil)
	return r.t.Wait()
}

func (r *Client) Report() error {
	done := false
	defer r.client.Close()

	log.Printf("Started reporting.")

	report := int32(0)
	for !done {
		if report == 0 {
			for k := range r.flows.FlowMapKeyIterator() {
				flow, e := r.flows.Get(k)
				flow.RLock()
				if e && flow.Sampled > 0 {

					success := true
					value := float64(flow.SRTT) * float64(time.Nanosecond) / float64(time.Millisecond)
					value_jitter := float64(flow.Jitter) * float64(time.Nanosecond) / float64(time.Millisecond)
					value_last := float64(flow.Last) * float64(time.Nanosecond) / float64(time.Millisecond)
					value_min := float64(flow.Min) * float64(time.Nanosecond) / float64(time.Millisecond)
					value_max := float64(flow.Max) * float64(time.Nanosecond) / float64(time.Millisecond)

					tags := []string{"link:" + flow.Src.String() + "-" + flow.Dst.String()}
					tags = append(tags, r.tags...)

					err := r.client.Gauge("system.net.tcp.rtt.avg", value, tags, 1)
					if err != nil {
						log.Printf("There was an issue reporting the avg RTT metric: %v", err)
						success = false
					} else {
						log.Printf("system.net.tcp.rtt.avg for %v: %v", tags, value)
					}
					err = r.client.Gauge("system.net.tcp.rtt.jitter", value_jitter, tags, 1)
					if err != nil {
						log.Printf("There was an issue reporting the jitter RTT metric: %v", err)
						success = false
					} else {
						log.Printf("system.net.tcp.rtt.jitter for %v: %v", tags, value_jitter)
					}
					err = r.client.Gauge("system.net.tcp.rtt.last", value_last, tags, 1)
					if err != nil {
						log.Printf("There was an issue reporting the last RTT metric: %v", err)
						success = false
					} else {
						log.Printf("system.net.tcp.rtt.last for %v: %v", tags, value_last)
					}
					err = r.client.Gauge("system.net.tcp.rtt.min", value_min, tags, 1)
					if err != nil {
						log.Printf("There was an issue reporting the min RTT metric: %v", err)
						success = false
					} else {
						log.Printf("system.net.tcp.rtt.min for %v: %v", tags, value_min)
					}

					err = r.client.Gauge("system.net.tcp.rtt.max", value_max, tags, 1)
					if err != nil {
						log.Printf("There was an issue reporting the max RTT metric: %v", err)
						success = false
					} else {
						log.Printf("system.net.tcp.rtt.max for %v: %v", tags, value_max)
					}

					if success {
						log.Printf("Reported on: %v", k)
					}
				}
				flow.RUnlock()
			}
		}

		//expire old flows...
		expire := true
		for expire {
			select {
			case key := <-r.flows.Expire:
				r.flows.Delete(key)
				log.Printf("Flow with key %v expired.", key)
			default:
				expire = false
			}
		}

		select {
		case <-r.t.Dying():
			log.Printf("Done reporting.")
			return nil
		case _ = <-time.After(1 * time.Second):
		}
		report++
		report = report % r.sleep
	}

	return nil
}
