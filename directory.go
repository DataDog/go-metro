package metro

import (
	"errors"
)

var Processors = map[string]Processor{}
var Reporters = map[string]Reporter{}

type ProcessorFactory func(string) (Processor, error)
type ReporterFactory func(string) (Reporter, error)

var ProcessorFactories = map[string]ProcessorFactory{}
var ReporterFactories = map[string]ReporterFactory{}

func RegisterProcessorFactory(id string, factory ProcessorFactory) error {
	if _, ok := ProcessorFactories[id]; ok {
		return errors.New("Processor already registered")
	}

	ProcessorFactories[id] = factory
	return nil
}

func RegisterReporterFactory(id string, factory ReporterFactory) error {
	if _, ok := ReporterFactories[id]; ok {
		return errors.New("Reporter already registered")
	}

	ReporterFactories[id] = factory
	return nil
}
