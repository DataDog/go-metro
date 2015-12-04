package reporter

import (
	"errors"
	"gopkg.in/tomb.v2"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/Datadog/dd-tcp-rtt/ddtypes"
)

type Client struct {
	client  *statsd.Client
	ip      net.IP
	port    int32
	sleep   int32
	flows   *ddtypes.FlowMap
	metrics chan ddtypes.Metric
	t       tomb.Tomb
}

const (
	Statsd_bufflen = 4
	Statsd_sleep   = 30
)

func NewClient(ip net.IP, port int32, sleep int32, flows *ddtypes.FlowMap) *Client {
	cli, err := statsd.NewBuffered(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), Statsd_bufflen)
	if err != nil {
		cli = nil
		log.Printf("Error instantiating stats Statter: %v", err)
	}

	r := &Client{
		client:  cli,
		port:    port,
		sleep:   sleep,
		flows:   flows,
		metrics: make(chan ddtypes.Metric, ddtypes.BufSz),
	}
	r.t.Go(r.Report)
	return r
}

func (r *Client) Stop() error {
	r.t.Kill(nil)
	return r.t.Wait()
}

func (r *Client) ReportMetric(metric *ddtypes.Metric) error {
	select {
	case r.metrics <- *metric:
		return nil
	default:
		return errors.New("Channel unavailable. Skipping metric.")
	}
}

func (r *Client) Report() error {
	defer r.client.Close()

	log.Printf("Started reporting.")

	for {

		select {
		case <-r.t.Dying():
			log.Printf("Done reporting.")
			return nil
		case metric := <-r.metrics:
			if metric.Mtype == ddtypes.Gauge {
				err := r.client.Gauge(metric.Name, metric.Value, metric.Tags, 1)
				if err != nil {
					log.Printf("There was an issue reporting the gauge metric: %v with err %v", metric.Name, err)
				}
			} else if metric.Mtype == ddtypes.Rate {
				err := r.client.Gauge(metric.Name, metric.Value, metric.Tags, 1)
				if err != nil {
					log.Printf("There was an issue reporting the rate metric: %v with err %v", metric.Name, err)
				}
			}
		case key := <-r.flows.Expire:
			r.flows.Delete(key)
			log.Printf("Flow with key %v expired.", key)
		case _ = <-time.After(1 * time.Second):
		}
	}

	return nil
}
