package dns

import (
	"sync"
)

type DNSStats struct {
	sync.RWMutex
	countMap map[string]int
}

func NewDNSStats() *DNSStats {
	t := &DNSStats{
		countMap: make(map[string]int),
	}
	return t
}

//Call holding lock!
func (d *DNSStats) Flush() {
	//Current maps will be GC'd
	d.countMap = make(map[string]int)
}

func (d *DNSStats) Increment(key string) {
	d.Lock()
	defer d.Unlock()

	d.countMap[key] += 1
}
