package ddtypes

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

// scanner handles scanning a single IP address.
type TCPAccounting struct {
	// destination, gateway (if applicable), and soruce IP addresses to use.
	Dst, Src     net.IP
	Dport, Sport layers.TCPPort

	SRTT      uint64
	Max       uint64
	Min       uint64
	Last      uint64
	TS, TSecr uint32
	Seen      map[uint32]bool
	Timed     map[TCPKey]int64
	Done      bool
	Sampled   uint32
	Seq       uint32
	NextSeq   uint32
	LastSz    uint32
	Alive     *time.Timer
}

type FlowMap struct {
	sync.RWMutex
	Map map[string]*TCPAccounting
}

// New creates a new stream.  It's called whenever the assembler sees a stream
// it isn't currently following.
func NewTCPAccounting(src net.IP, dst net.IP, sport layers.TCPPort, dport layers.TCPPort, d time.Duration, cb func()) *TCPAccounting {
	//log.Printf("new stream %v:%v started", net, transport)
	t := &TCPAccounting{
		Dst:     dst,
		Src:     src,
		Dport:   dport,
		Sport:   sport,
		SRTT:    0,
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
		Alive:   time.AfterFunc(d, cb),
	}

	return t
}

func NewFlowMap() *FlowMap {
	m := &FlowMap{
		Map: make(map[string]*TCPAccounting),
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
		rtt = 1000
	}

	if t.SRTT == 0 {
		t.SRTT = rtt
	} else if soften {
		t.SRTT -= (t.SRTT >> 3)
		t.SRTT += rtt >> 3
	} else {
		t.SRTT += rtt
	}
	t.Last = rtt
}

func (t *TCPAccounting) MaxRTT(sample uint64) {

	if sample > t.Max {
		t.Max = sample
	}
}

func (t *TCPAccounting) MinRTT(sample uint64) {

	if sample < t.Min {
		t.Min = sample
	}
}
