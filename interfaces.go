package metro

type Processor interface {
	Start() error
	Stop() error
	Running() bool
	RegisterReporter(id string, r Reporter) error
	Name() string
}

type Reporter interface {
	Submit(key, metric string, value float64, tags []string, asHistogram bool) error
	Name() string
}
