package tcp

import (
	"bufio"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/cihub/seelog"
)

func memorySize() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}

	s := bufio.NewScanner(f)
	if !s.Scan() {
		return 0, errors.New("/proc/meminfo parse error")
	}

	l := s.Text()
	fs := strings.Fields(l)
	if len(fs) != 3 || fs[2] != "kB" {
		return 0, errors.New("/proc/meminfo parse error")
	}

	kb, err := strconv.ParseUint(fs[1], 10, 64)
	if err != nil {
		return 0, err
	}

	//return bytes
	return kb * 1024, nil
}

func (d *MetroSniffer) Report() error {
	log.Infof("Started reporting.")

	memsize, err := memorySize()
	if err != nil {
		log.Warnf("Error getting memory size. Relying on OOM to keep process in check. Err: %v", err)
	}

	ticker := time.NewTicker(d.reportIval)
	done := false
	var memstats runtime.MemStats
	var pct float64
	for !done {
		select {
		case key := <-d.flows.Expire:
			d.flows.Delete(key)
			log.Infof("Flow expired: [%s]", key)
		case <-ticker.C:
			flush := false
			now := time.Now().Unix()

			runtime.ReadMemStats(&memstats)
			if memsize > 0 {
				pct = float64(memstats.Alloc) / float64(memsize)
			} else {
				pct = 0
			}

			if pct >= FORCE_FLUSH_PCT { //memory out of control
				flush = true
				log.Warnf("Forcing flush - memory consumption above maximum allowed system usage: %v %%", pct*100)
			}

			d.flows.Lock()
			for k := range d.flows.Map {
				flow, e := d.flows.GetUnsafe(k)
				flow.Lock()
				if e && flow.Sampled > 0 {
					success := true
					value := float64(flow.SRTT) * float64(time.Nanosecond) / float64(time.Millisecond)
					value_jitter := float64(flow.Jitter) * float64(time.Nanosecond) / float64(time.Millisecond)
					value_last := float64(flow.Last) * float64(time.Nanosecond) / float64(time.Millisecond)

					srcHost, ok := d.nameLookup[flow.Src.String()]
					if !ok {
						srcHost = flow.Src.String()
					}
					dstHost, ok := d.nameLookup[flow.Dst.String()]
					if !ok {
						dstHost = flow.Dst.String()
					}

					tags := []string{"src:" + srcHost, "dst:" + dstHost}
					tags = append(tags, d.config.Tags...)

					for n, r := range d.reporters {
						metric := "system.net.tcp.rtt.avg"
						err := r.Submit(k, metric, value, tags, false)
						if err != nil {
							success = false
						}
						metric = "system.net.tcp.rtt.jitter"
						err = r.Submit(k, metric, value_jitter, tags, false)
						if err != nil {
							success = false
						}
						metric = "system.net.tcp.rtt"
						err = r.Submit(k, metric, value_last, tags, false)
						if err != nil {
							success = false
						}
						if success {
							log.Debugf("Reported successfully via %v: %v", n, k)
						}
					}
				}
				if flush || (now-flow.LastFlush) > FLUSH_IVAL {
					log.Debugf("Flushing book-keeping for long-lived flow: %v", k)
					flow.Flush()
				}
				flow.Unlock()
			}
			d.flows.Unlock()
		case <-d.t.Dying():
			log.Infof("Done reporting.")
			done = true
		}
	}

	return nil
}
