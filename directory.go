package metro

import (
	"errors"
)

var Processors = map[string]Processor{}
var Reporters = map[string]Reporter{}
var Ingestors = map[string]Ingestor{}

type ProcessorFactory func(string) (Processor, error)
type ReporterFactory func(string) (Reporter, error)
type IngestorFactory func(string) (Ingestor, error)

var ProcessorFactories = map[string]ProcessorFactory{}
var ReporterFactories = map[string]ReporterFactory{}
var IngestorFactories = map[string]IngestorFactory{}

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

func RegisterIngestorFactory(id string, factory IngestorFactory) error {
	if _, ok := IngestorFactories[id]; ok {
		return errors.New("Ingestor already registered")
	}

	IngestorFactories[id] = factory
	return nil
}
