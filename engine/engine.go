package engine

import (
	"fmt"
	"sync"

	"dpi-engine/rules"
	"dpi-engine/types"
)

// Config holds the configuration for the DPI engine.
type Config struct {
	InputFile   string
	OutputFile  string
	NumWorkers  int
	Verbose     bool
	RuleManager *rules.RuleManager
}

// DPIEngine orchestrates the full packet processing pipeline.
type DPIEngine struct {
	config        Config
	stats         *Stats
	appCounter    *AppCounter
	domainCounter *DomainCounter
}

// NewDPIEngine creates a new DPI engine with the given configuration.
func NewDPIEngine(config Config) *DPIEngine {
	return &DPIEngine{
		config:        config,
		stats:         NewStats(config.NumWorkers),
		appCounter:    NewAppCounter(),
		domainCounter: NewDomainCounter(),
	}
}

// Run executes the full DPI pipeline:
// 1. Reader goroutine reads pcap and distributes to workers
// 2. Worker goroutines inspect and classify packets
// 3. Writer goroutine writes forwarded packets to output
func (e *DPIEngine) Run() error {
	numWorkers := e.config.NumWorkers

	// Create worker input channels (one per worker)
	workerChans := make([]chan types.PacketJob, numWorkers)
	for i := 0; i < numWorkers; i++ {
		workerChans[i] = make(chan types.PacketJob, types.ChannelBufferSize)
	}

	// Create shared output channel
	outputChan := make(chan types.PacketJob, types.ChannelBufferSize)

	// Create reader
	reader := NewReader(e.config.InputFile, numWorkers, workerChans, e.stats, e.config.Verbose)

	// Create workers
	workers := make([]*Worker, numWorkers)
	for i := 0; i < numWorkers; i++ {
		workers[i] = NewWorker(
			i,
			workerChans[i],
			outputChan,
			e.config.RuleManager,
			e.stats,
			e.appCounter,
			e.domainCounter,
			e.config.Verbose,
		)
	}

	// Create writer — use Ethernet link type by default; the reader will
	// detect the actual link type but we need the writer started before
	// the reader begins pushing packets.
	writer := NewWriter(e.config.OutputFile, outputChan, 1, e.config.Verbose)

	// Start writer goroutine
	var writerWg sync.WaitGroup
	var writerErr error
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		writerErr = writer.Run()
	}()

	// Start worker goroutines
	var workerWg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		workerWg.Add(1)
		go func(w *Worker) {
			defer workerWg.Done()
			w.Run()
		}(workers[i])
	}

	// Start reader goroutine
	var readerErr error
	readerDone := make(chan struct{})
	go func() {
		readerErr = reader.Run()
		close(readerDone)
	}()

	// Wait for reader to finish
	<-readerDone
	if readerErr != nil {
		return fmt.Errorf("reader error: %w", readerErr)
	}

	// Reader closed all worker channels.
	// Wait for all workers to finish processing.
	workerWg.Wait()

	// Close output channel — all workers are done.
	close(outputChan)

	// Wait for writer to drain and finish.
	writerWg.Wait()
	if writerErr != nil {
		return fmt.Errorf("writer error: %w", writerErr)
	}

	// Print final report
	e.stats.PrintReport(e.appCounter, e.domainCounter)

	return nil
}
