package main

import (
	"math"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

type TCPKey struct {
	Seq uint32
	TS  uint32
}

const (
	CHAN_DEPTH = 10
)

// scanner handles scanning a single IP address.
type TCPAccounting struct {
	// destination, gateway (if applicable), and source IP addresses to use.
	Dst, Src     net.IP
	Dport, Sport layers.TCPPort

	sync.RWMutex
	SRTT      uint64
	Jitter    uint64
	Max       uint64
	Min       uint64
	Last      uint64
	TS, TSecr uint32
	Seen      map[uint32]bool
	Timed     map[TCPKey]int64
	Done      bool
	Sampled   uint64
	Seq       uint32
	NextSeq   uint32
	LastSz    uint32
	Expire    *chan string
	Alive     *time.Timer
}

// New creates a new stream.  It's called whenever the assembler sees a stream
// it isn't currently following.
func NewTCPAccounting(src net.IP, dst net.IP, sport layers.TCPPort, dport layers.TCPPort, d time.Duration, expire *chan string) *TCPAccounting {
	t := &TCPAccounting{
		Dst:     dst,
		Src:     src,
		Dport:   dport,
		Sport:   sport,
		SRTT:    0,
		Jitter:  0,
		Max:     0,
		Min:     math.MaxUint64,
		Last:    0,
		Sampled: 0,
		TS:      0,
		TSecr:   0,
		Seq:     0,
		Done:    false,
		Seen:    make(map[uint32]bool),
		Timed:   make(map[TCPKey]int64),
		Expire:  expire,
		Alive:   nil,
	}
	return t
}

func (t *TCPAccounting) SetExpiration(ttl time.Duration, expkey string) {
	if t.Alive != nil {
		t.Alive.Stop()
	}
	t.Alive = time.AfterFunc(ttl, func() {
		t.Lock()
		t.Done = true
		t.Unlock()
		*t.Expire <- expkey
	})
}

type TimedMap struct {
	sync.RWMutex
	Map map[string]*time.Timer
}

func NewTimedMap() *TimedMap {
	t := &TimedMap{
		Map: make(map[string]*time.Timer),
	}
	return t
}

func (tb *TimedMap) Add(key string, t *time.Timer) {
	tb.Lock()
	tb.Map[key] = t
	tb.Unlock()
}

func (tb *TimedMap) Get(key string) (*time.Timer, bool) {
	tb.RLock()
	v, e := tb.Map[key]
	tb.RUnlock()
	return v, e
}

func (tb *TimedMap) Exists(key string) bool {
	tb.RLock()
	_, e := tb.Map[key]
	tb.RUnlock()
	return e
}

func (tb *TimedMap) Delete(key string) {
	tb.Lock()
	delete(tb.Map, key)
	tb.Unlock()
}

type FlowMap struct {
	sync.RWMutex
	Map    map[string]*TCPAccounting
	Expire chan string
}

func NewFlowMap() *FlowMap {
	m := &FlowMap{
		Map:    make(map[string]*TCPAccounting),
		Expire: make(chan string, CHAN_DEPTH),
	}
	return m
}

func (f *FlowMap) Add(key string, t *TCPAccounting) {
	f.Lock()
	f.Map[key] = t
	f.Unlock()
}

func (f *FlowMap) Get(key string) (*TCPAccounting, bool) {
	f.RLock()
	v, e := f.Map[key]
	f.RUnlock()
	return v, e
}

func (f *FlowMap) GetUnsafe(key string) (*TCPAccounting, bool) {
	v, e := f.Map[key]
	return v, e
}

func (f *FlowMap) Exists(key string) bool {
	f.RLock()
	_, e := f.Map[key]
	f.RUnlock()
	return e
}

func (f *FlowMap) Delete(key string) {
	f.Lock()
	delete(f.Map, key)
	f.Unlock()
}

// NOTE: Never call break on a loop that uses this FlowMapKeyIterator, or else you
//       end up with uncollectable garabage becase the go routine this will be
//       running in will continue to do so because we'll never read from the other
//       end of the channel pipe. Sooooo... ONLY USE THIS IF YOU WISH TO ITERATE
//       OVER THE ENTIRE KEYSET.
func (f *FlowMap) FlowMapKeyIterator() <-chan string {
	ch := make(chan string)
	go func() {
		f.RLock()
		for k, _ := range f.Map {
			ch <- k
		}
		f.RUnlock()
		close(ch) // Remember to close or the loop never ends!
	}()
	return ch
}

func (t *TCPAccounting) CalcSRTT(rtt uint64, soften bool) {

	if rtt < 1000 {
		rtt = 1001
	}

	if t.SRTT == 0 {
		t.SRTT = rtt
	} else if soften {
		t.SRTT -= t.SRTT >> 3
		t.SRTT += rtt >> 3
	} else {
		t.SRTT = uint64(float64(t.Sampled*t.SRTT)/float64(t.Sampled+1) + float64(rtt)/float64(t.Sampled+1))
	}

}

func (t *TCPAccounting) CalcJitter(rtt uint64, soften bool) {

	if t.Sampled > 0 {
		diff := int64(rtt - t.Last)
		if diff < 0 {
			diff = -1 * diff
		}
		if soften {
			t.Jitter -= t.Jitter >> 3
			t.Jitter += uint64(diff) >> 3
		} else {
			t.Jitter = uint64(float64(t.Sampled*t.Jitter)/float64(t.Sampled+1) + float64(diff)/float64(t.Sampled+1))
		}
	}
}

func (t *TCPAccounting) MaxRTT(sample uint64) {

	if sample > t.Max {
		t.Max = sample
	}
}

func (t *TCPAccounting) MinRTT(sample uint64) {

	if sample < 1000 {
		sample = 1000
	}

	if sample < t.Min {
		t.Min = sample
	}
}
