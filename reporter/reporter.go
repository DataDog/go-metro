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
	client *dogstatsd.Client
	ip     net.IP
	port   int32
	sleep  int32
	flows  *ddtypes.FlowMap
	t      tomb.Tomb
}

func NewClient(ip net.IP, port int32, sleep int32, id string, flows *ddtypes.FlowMap) *Client {
	cli, err := dogstatsd.New(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	if err != nil {
		cli = nil
		log.Printf("Error instantiating stats Statter: %v", err)
	}

	r := &Client{
		client: cli,
		port:   port,
		sleep:  sleep,
		flows:  flows,
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
			if e && flow.Sampled > 0 {
				value := float64(flow.SRTT) / float64(flow.Sampled) * float64(time.Nanosecond) / float64(time.Millisecond)
				tags := []string{"link:" + flow.Src.String() + "-" + flow.Dst.String()}
				err := r.client.Gauge("system.net.tcp.rtt", value, tags, 1.0)
				if err != nil {
					log.Printf("There was an issue reporting the metric: %v", err)
				}
				log.Printf("Reported on: %v", k)
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
