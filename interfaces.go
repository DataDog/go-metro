package metro

type Processor interface {
	Start() error
	Stop() error
	Running() bool
	EnqueuePacket([]byte, interface{}) error
	RegisterReporter(string, Reporter) error
	Name() string
}

type Reporter interface {
	Submit(key, metric string, value float64, tags []string, asHistogram bool) error
	Name() string
}

type Ingestor interface {
	Name() string
	Start() error
	Stop() error
	Running() bool
	RegisterProcessor(string, Processor) error
}
