package engine

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"dpi-engine/types"
)

// Stats tracks global and per-worker statistics using atomic counters.
type Stats struct {
	TotalPackets    atomic.Uint64
	TotalBytes      atomic.Uint64
	TCPPackets      atomic.Uint64
	UDPPackets      atomic.Uint64
	ForwardedPkts   atomic.Uint64
	DroppedPkts     atomic.Uint64
	ParseErrors     atomic.Uint64

	Workers []*WorkerStats
}

// WorkerStats tracks per-worker statistics.
type WorkerStats struct {
	PacketsProcessed   atomic.Uint64
	PacketsForwarded   atomic.Uint64
	PacketsDropped     atomic.Uint64
	ActiveConnections  atomic.Int64
	SNIExtractions     atomic.Uint64
	ClassificationHits atomic.Uint64
}

// AppCounter tracks per-app classification counts.
type AppCounter struct {
	mu     sync.Mutex
	counts map[types.AppType]uint64
}

// NewAppCounter creates a new AppCounter.
func NewAppCounter() *AppCounter {
	return &AppCounter{
		counts: make(map[types.AppType]uint64),
	}
}

// Increment adds 1 to the count for the given app type.
func (ac *AppCounter) Increment(app types.AppType) {
	ac.mu.Lock()
	ac.counts[app]++
	ac.mu.Unlock()
}

// GetCounts returns a copy of the counts map.
func (ac *AppCounter) GetCounts() map[types.AppType]uint64 {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	result := make(map[types.AppType]uint64, len(ac.counts))
	for k, v := range ac.counts {
		result[k] = v
	}
	return result
}

// DomainCounter tracks per-domain connection counts.
type DomainCounter struct {
	mu     sync.Mutex
	counts map[string]uint64
}

// NewDomainCounter creates a new DomainCounter.
func NewDomainCounter() *DomainCounter {
	return &DomainCounter{
		counts: make(map[string]uint64),
	}
}

// Increment adds 1 to the count for the given domain.
func (dc *DomainCounter) Increment(domain string) {
	if domain == "" {
		return
	}
	dc.mu.Lock()
	dc.counts[domain]++
	dc.mu.Unlock()
}

// NewStats creates a Stats instance with the given number of workers.
func NewStats(numWorkers int) *Stats {
	s := &Stats{
		Workers: make([]*WorkerStats, numWorkers),
	}
	for i := 0; i < numWorkers; i++ {
		s.Workers[i] = &WorkerStats{}
	}
	return s
}

// PrintReport prints a final summary report to stdout.
func (s *Stats) PrintReport(appCounter *AppCounter, domainCounter *DomainCounter) {
	totalPkts := s.TotalPackets.Load()
	totalBytes := s.TotalBytes.Load()
	fwd := s.ForwardedPkts.Load()
	dropped := s.DroppedPkts.Load()

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    DPI ENGINE REPORT                        ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Overall Packet Statistics                                  ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Total packets:      %-39d ║\n", totalPkts)
	fmt.Printf("║  Total bytes:        %-39d ║\n", totalBytes)
	fmt.Printf("║  TCP packets:        %-39d ║\n", s.TCPPackets.Load())
	fmt.Printf("║  UDP packets:        %-39d ║\n", s.UDPPackets.Load())
	fmt.Printf("║  Parse errors:       %-39d ║\n", s.ParseErrors.Load())

	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Filtering Statistics                                       ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Forwarded:          %-39d ║\n", fwd)
	fmt.Printf("║  Dropped:            %-39d ║\n", dropped)
	if totalPkts > 0 {
		dropRate := float64(dropped) / float64(totalPkts) * 100
		fmt.Printf("║  Drop rate:          %-39s ║\n", fmt.Sprintf("%.2f%%", dropRate))
	}

	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Per-Worker Statistics                                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	for i, w := range s.Workers {
		fmt.Printf("║  Worker %-2d: processed=%-8d fwd=%-8d drop=%-8d  ║\n",
			i,
			w.PacketsProcessed.Load(),
			w.PacketsForwarded.Load(),
			w.PacketsDropped.Load(),
		)
		fmt.Printf("║            active_conns=%-6d sni=%-8d classified=%-5d ║\n",
			w.ActiveConnections.Load(),
			w.SNIExtractions.Load(),
			w.ClassificationHits.Load(),
		)
	}

	// App classification breakdown
	appCounts := appCounter.GetCounts()
	if len(appCounts) > 0 {
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")
		fmt.Println("║  Application Classification Breakdown                       ║")
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")

		// Sort by count descending
		type appEntry struct {
			app   types.AppType
			count uint64
		}
		var entries []appEntry
		var totalClassified uint64
		for app, count := range appCounts {
			entries = append(entries, appEntry{app, count})
			totalClassified += count
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].count > entries[j].count
		})

		for _, e := range entries {
			pct := float64(0)
			if totalClassified > 0 {
				pct = float64(e.count) / float64(totalClassified) * 100
			}
			barLen := int(pct / 2) // max ~50 chars
			if barLen > 30 {
				barLen = 30
			}
			bar := strings.Repeat("█", barLen)
			fmt.Printf("║  %-14s %6d (%5.1f%%) %s\n",
				e.app.String(), e.count, pct, bar)
		}
	}

	// Top domains
	if domainCounter != nil {
		domainCounter.mu.Lock()
		domainCounts := make(map[string]uint64, len(domainCounter.counts))
		for k, v := range domainCounter.counts {
			domainCounts[k] = v
		}
		domainCounter.mu.Unlock()

		if len(domainCounts) > 0 {
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Println("║  Top 20 Domains                                             ║")
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")

			type domainEntry struct {
				domain string
				count  uint64
			}
			var dEntries []domainEntry
			for d, c := range domainCounts {
				dEntries = append(dEntries, domainEntry{d, c})
			}
			sort.Slice(dEntries, func(i, j int) bool {
				return dEntries[i].count > dEntries[j].count
			})

			limit := 20
			if len(dEntries) < limit {
				limit = len(dEntries)
			}
			for i := 0; i < limit; i++ {
				name := dEntries[i].domain
				if len(name) > 40 {
					name = name[:37] + "..."
				}
				fmt.Printf("║  %-3d %-42s %6d     ║\n",
					i+1, name, dEntries[i].count)
			}
		}
	}

	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}
