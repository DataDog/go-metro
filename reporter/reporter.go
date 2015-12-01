package reporter

import (
	"gopkg.in/tomb.v2"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/Datadog/dd-tcp-rtt/ddtypes"
	"github.com/ooyala/go-dogstatsd"
)

type Client struct {
	client  *dogstatsd.Client
	ip      net.IP
	port    int32
	sleep   int32
	flows   *ddtypes.FlowMap
	tracker map[string]uint32
	t       tomb.Tomb
}

func NewClient(ip net.IP, port int32, sleep int32, id string, flows *ddtypes.FlowMap) *Client {
	cli, err := dogstatsd.New(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	if err != nil {
		cli = nil
		log.Printf("Error instantiating stats Statter: %v", err)
	}

	r := &Client{
		client:  cli,
		port:    port,
		sleep:   sleep,
		flows:   flows,
		tracker: make(map[string]uint32),
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

	for !done {
		for k := range r.flows.FlowMapKeyIterator() {
			flow, e := r.flows.Get(k)
			last, ok := r.tracker[k]
			if e && flow.Sampled > 0 &&
				((ok && last != flow.Sampled) || !ok) {

				success := true
				value := float64(flow.SRTT) / float64(flow.Sampled) * float64(time.Nanosecond) / float64(time.Millisecond)
				value_min := float64(flow.Min) * float64(time.Nanosecond) / float64(time.Millisecond)
				value_max := float64(flow.Max) * float64(time.Nanosecond) / float64(time.Millisecond)
				tags := []string{"link:" + flow.Src.String() + "-" + flow.Dst.String()}
				err := r.client.Gauge("system.net.tcp.rtt.avg", value, tags, 1.0)
				if err != nil {
					log.Printf("There was an issue reporting the avg RTT metric: %v", err)
					success = false
				} else {
					log.Printf("system.net.tcp.rtt.avg for %v: %v", tags, value)
				}
				err = r.client.Gauge("system.net.tcp.rtt.min", value_min, tags, 1.0)
				if err != nil {
					log.Printf("There was an issue reporting the min RTT metric: %v", err)
					success = false
				} else {
					log.Printf("system.net.tcp.rtt.min for %v: %v", tags, value_min)
				}

				err = r.client.Gauge("system.net.tcp.rtt.max", value_max, tags, 1.0)
				if err != nil {
					log.Printf("There was an issue reporting the max RTT metric: %v", err)
					success = false
				} else {
					log.Printf("system.net.tcp.rtt.max for %v: %v", tags, value_max)
				}

				if success {
					r.tracker[k] = flow.Sampled
					log.Printf("Reported on: %v", k)
				}
			}
		}
		select {
		case <-r.t.Dying():
			log.Printf("Done reporting.")
			return nil
		case _ = <-time.After(1 * time.Second):
		}
		//-1 because we're sleeping for a second above
		time.Sleep(time.Duration(r.sleep-1) * time.Second)
	}

	return nil
}
