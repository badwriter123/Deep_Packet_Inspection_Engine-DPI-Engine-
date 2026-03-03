package engine

import (
	"time"

	"dpi-engine/dpi"
	"dpi-engine/rules"
	"dpi-engine/tracker"
	"dpi-engine/types"
)

// Worker is a Fast Path (FP) processor goroutine.
type Worker struct {
	id            int
	inputChan     <-chan types.PacketJob
	outputChan    chan<- types.PacketJob
	ruleManager   *rules.RuleManager
	stats         *Stats
	workerStats   *WorkerStats
	appCounter    *AppCounter
	domainCounter *DomainCounter
	ipTracker     *IPTracker
	verbose       bool
}

// NewWorker creates a new FP worker.
func NewWorker(
	id int,
	inputChan <-chan types.PacketJob,
	outputChan chan<- types.PacketJob,
	ruleManager *rules.RuleManager,
	stats *Stats,
	appCounter *AppCounter,
	domainCounter *DomainCounter,
	ipTracker *IPTracker,
	verbose bool,
) *Worker {
	return &Worker{
		id:            id,
		inputChan:     inputChan,
		outputChan:    outputChan,
		ruleManager:   ruleManager,
		stats:         stats,
		workerStats:   stats.Workers[id],
		appCounter:    appCounter,
		domainCounter: domainCounter,
		ipTracker:     ipTracker,
		verbose:       verbose,
	}
}

// Run processes packets from the input channel until it's closed.
func (w *Worker) Run() {
	ct := tracker.NewConnectionTracker()
	lastCleanup := time.Now()

	for job := range w.inputChan {
		w.workerStats.PacketsProcessed.Add(1)
		now := time.Now()

		// Periodic cleanup (every ~100ms worth of idle or every 1000 packets)
		if now.Sub(lastCleanup) > 100*time.Millisecond {
			ct.CleanupExpired(now)
			w.workerStats.ActiveConnections.Store(int64(ct.ActiveCount()))
			lastCleanup = now
		}

		action := w.processPacket(&job, ct, now)

		if action == types.ActionForward {
			w.outputChan <- job
			w.workerStats.PacketsForwarded.Add(1)
			w.stats.ForwardedPkts.Add(1)
		} else {
			w.workerStats.PacketsDropped.Add(1)
			w.stats.DroppedPkts.Add(1)
		}
	}

	// Final active connections count
	w.workerStats.ActiveConnections.Store(0)
}

// processPacket handles a single packet through the DPI pipeline.
func (w *Worker) processPacket(job *types.PacketJob, ct *tracker.ConnectionTracker, now time.Time) types.Action {
	// Step 1 — Get or create connection
	conn, isReverse := ct.GetOrCreate(job.Tuple, now)

	// Update byte/packet counters
	if isReverse {
		conn.PacketsOut++
		conn.BytesOut += uint64(len(job.RawData))
	} else {
		conn.PacketsIn++
		conn.BytesIn += uint64(len(job.RawData))
	}

	// Step 2 — Update TCP state machine (only for TCP)
	if job.Tuple.Protocol == 6 {
		tracker.UpdateTCPState(conn, job.TCPFlags)
	}

	// Step 3 — If blocked, drop
	if conn.State == types.StateBlocked {
		return types.ActionDrop
	}

	// Step 4 — Payload inspection
	if conn.State != types.StateClassified && job.PayloadLength > 0 {
		payload := job.Payload()
		if payload != nil {
			w.inspectPayload(conn, job, payload)
		}
	}

	// Step 5 — Check rules
	blocked, _ := w.ruleManager.ShouldBlock(
		job.Tuple.SrcIP,
		job.Tuple.DstPort,
		conn.AppType,
		conn.SNI,
	)
	if blocked {
		conn.State = types.StateBlocked
		return types.ActionDrop
	}

	// Step 6 — Track source and destination IP for every forwarded packet
	w.ipTracker.Track(job.Tuple.SrcIP, job.Tuple.DstIP, job.Tuple.DstPort, uint64(len(job.RawData)), conn.SNI)

	// Step 7 — Forward
	return types.ActionForward
}

// inspectPayload tries each DPI extractor in order.
func (w *Worker) inspectPayload(conn *types.Connection, job *types.PacketJob, payload []byte) {
	// Try TLS SNI extraction
	if job.Tuple.DstPort == 443 || len(payload) > 50 {
		if sni, ok := dpi.ExtractSNI(payload); ok {
			w.workerStats.SNIExtractions.Add(1)
			appType := types.SNIToAppType(sni)
			if appType == types.AppUnknown {
				appType = types.AppTLS
			}
			w.classify(conn, appType, sni)
			return
		}
	}

	// Try HTTP Host extraction
	if job.Tuple.DstPort == 80 {
		if host, ok := dpi.ExtractHTTPHost(payload); ok {
			appType := types.SNIToAppType(host)
			if appType == types.AppUnknown {
				appType = types.AppHTTP
			}
			w.classify(conn, appType, host)
			return
		}
	}

	// Try DNS query extraction
	if job.Tuple.DstPort == 53 || job.Tuple.SrcPort == 53 {
		if domain, ok := dpi.ExtractDNSQuery(payload); ok {
			appType := types.SNIToAppType(domain)
			if appType == types.AppUnknown {
				appType = types.AppDNS
			}
			w.classify(conn, appType, domain)
			return
		}
	}

	// Port fallback
	switch job.Tuple.DstPort {
	case 80:
		w.classify(conn, types.AppHTTP, "")
	case 443:
		w.classify(conn, types.AppHTTPS, "")
	}
}

// classify sets the classification on a connection and updates counters.
func (w *Worker) classify(conn *types.Connection, appType types.AppType, sni string) {
	tracker.ClassifyConnection(conn, appType, sni)
	w.workerStats.ClassificationHits.Add(1)
	w.appCounter.Increment(appType)
	if sni != "" {
		w.domainCounter.Increment(sni)
	}
}
