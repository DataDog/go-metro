package dns

import (
	"fmt"
	"time"

	log "github.com/cihub/seelog"
)

func (d *MetroDNSProcessor) Report() error {
	log.Infof("Started reporting.")

	ticker := time.NewTicker(d.reportIval)
	reqMetric := "system.net.dns.reqs"
	respMetric := "system.net.dns.resps"

	done := false
	for !done {
		select {
		case <-ticker.C:
			success := true

			d.responses.Lock()
			for k, v := range d.responses.countMap {
				for _, r := range d.reporters {
					tags := []string{fmt.Sprintf("client:%s", k)}
					tags = append(tags, d.config.Tags...)

					err := r.Submit("", reqMetric, float64(v), tags, false)
					if err != nil {
						success = false
					}
				}
			}
			d.responses.Flush()
			d.responses.Unlock()

			d.requests.Lock()
			for k, v := range d.requests.countMap {
				for _, r := range d.reporters {
					tags := []string{fmt.Sprintf("server:%s", k)}
					tags = append(tags, d.config.Tags...)

					err := r.Submit("", respMetric, float64(v), tags, false)
					if err != nil {
						success = false
					}
				}
			}
			d.requests.Flush()
			d.requests.Unlock()

			if success {
				log.Debugf("Reported successfully")
			}
		case <-d.t.Dying():
			log.Infof("Done reporting.")
			done = true
		}
	}

	return nil
}
