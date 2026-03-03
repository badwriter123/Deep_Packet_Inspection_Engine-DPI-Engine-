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

// IPRecord tracks activity for a single IP address.
type IPRecord struct {
	IP          uint32
	Connections uint64
	Bytes       uint64
	Ports       map[uint16]bool
	Domains     map[string]bool
	ConnectedTo map[uint32]bool // destination IPs this source talked to
	Suspicious  bool
	Reasons     []string
}

// IPTracker tracks per-IP activity for both source and destination. Thread-safe.
type IPTracker struct {
	mu      sync.Mutex
	records map[uint32]*IPRecord
}

// NewIPTracker creates a new IPTracker.
func NewIPTracker() *IPTracker {
	return &IPTracker{
		records: make(map[uint32]*IPRecord),
	}
}

// Track records a packet from srcIP to dstIP.
// Both source and destination IPs are tracked. The domain/port are associated
// with the destination IP, and the source IP records which destinations it talked to.
func (it *IPTracker) Track(srcIP, dstIP uint32, dstPort uint16, bytes uint64, domain string) {
	it.mu.Lock()
	defer it.mu.Unlock()

	// Track destination IP
	dstRec := it.getOrCreate(dstIP)
	dstRec.Connections++
	dstRec.Bytes += bytes
	dstRec.Ports[dstPort] = true
	if domain != "" {
		dstRec.Domains[domain] = true
	}

	// Track source IP — link it to what it connected to
	srcRec := it.getOrCreate(srcIP)
	srcRec.ConnectedTo[dstIP] = true
	if domain != "" {
		srcRec.Domains[domain] = true
	}
}

// getOrCreate returns an existing record or creates a new one. Must be called with lock held.
func (it *IPTracker) getOrCreate(ip uint32) *IPRecord {
	rec, ok := it.records[ip]
	if !ok {
		rec = &IPRecord{
			IP:          ip,
			Ports:       make(map[uint16]bool),
			Domains:     make(map[string]bool),
			ConnectedTo: make(map[uint32]bool),
		}
		it.records[ip] = rec
	}
	return rec
}

// standardPorts are common ports that are not suspicious on their own.
var standardPorts = map[uint16]bool{
	0: true, // ICMP and other portless protocols
	22: true, 25: true, 53: true, 80: true, 443: true,
	587: true, 993: true, 995: true, 8080: true, 8443: true,
}

// Analyze runs suspicious activity detection on all tracked IPs.
func (it *IPTracker) Analyze() {
	it.mu.Lock()
	defer it.mu.Unlock()

	for _, rec := range it.records {
		rec.Suspicious = false
		rec.Reasons = nil

		// 1. High connection volume (> 100 connections)
		if rec.Connections > 100 {
			rec.Suspicious = true
			rec.Reasons = append(rec.Reasons,
				fmt.Sprintf("HIGH VOLUME: %d connections", rec.Connections))
		}

		// 2. Reserved/Bogon range detection
		if isReservedIP(rec.IP) {
			rec.Suspicious = true
			rec.Reasons = append(rec.Reasons, "RESERVED RANGE: private/reserved IP as destination")
		}

		// 3. Unusual port patterns
		if len(rec.Ports) > 10 {
			rec.Suspicious = true
			rec.Reasons = append(rec.Reasons,
				fmt.Sprintf("PORT SCAN: %d unique ports contacted", len(rec.Ports)))
		}

		// Check for non-standard low ports
		for port := range rec.Ports {
			if !standardPorts[port] && port < 1024 {
				rec.Suspicious = true
				rec.Reasons = append(rec.Reasons,
					fmt.Sprintf("UNUSUAL PORT: non-standard low port %d", port))
				break
			}
		}
	}

	// Propagation: if a source IP is suspicious, flag all destinations it connected to.
	// Collect initially suspicious IPs first to avoid cascade effects.
	var initiallySuspicious []*IPRecord
	for _, rec := range it.records {
		if rec.Suspicious && len(rec.ConnectedTo) > 0 {
			initiallySuspicious = append(initiallySuspicious, rec)
		}
	}
	for _, rec := range initiallySuspicious {
		srcIPStr := types.Uint32ToIP(rec.IP).String()
		for destIP := range rec.ConnectedTo {
			destRec, ok := it.records[destIP]
			if !ok {
				continue
			}
			destRec.Suspicious = true
			destRec.Reasons = append(destRec.Reasons,
				fmt.Sprintf("ASSOCIATED: traffic from flagged IP %s", srcIPStr))
		}
	}
}

// isReservedIP checks if an IP (as uint32, big-endian) falls in a private/reserved range.
func isReservedIP(ip uint32) bool {
	firstOctet := ip >> 24

	// 10.0.0.0/8
	if firstOctet == 10 {
		return true
	}
	// 127.0.0.0/8
	if firstOctet == 127 {
		return true
	}
	// 0.0.0.0/8
	if firstOctet == 0 {
		return true
	}
	// 172.16.0.0/12
	if firstOctet == 172 {
		secondOctet := (ip >> 16) & 0xFF
		if secondOctet >= 16 && secondOctet <= 31 {
			return true
		}
	}
	// 192.168.0.0/16
	if firstOctet == 192 {
		secondOctet := (ip >> 16) & 0xFF
		if secondOctet == 168 {
			return true
		}
	}
	// 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved)
	if firstOctet >= 224 {
		return true
	}

	return false
}

// lookupRecord returns the record for an IP, or nil if not found.
func (it *IPTracker) lookupRecord(ip uint32) *IPRecord {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.records[ip]
}

// GetRecords returns a copy of all IP records.
func (it *IPTracker) GetRecords() []*IPRecord {
	it.mu.Lock()
	defer it.mu.Unlock()

	result := make([]*IPRecord, 0, len(it.records))
	for _, rec := range it.records {
		result = append(result, rec)
	}
	return result
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
func (s *Stats) PrintReport(appCounter *AppCounter, domainCounter *DomainCounter, ipTracker *IPTracker) {
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

	// IP Address Activity
	if ipTracker != nil {
		records := ipTracker.GetRecords()
		if len(records) > 0 {
			// Sort by connection count descending
			sort.Slice(records, func(i, j int) bool {
				return records[i].Connections > records[j].Connections
			})

			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Println("║  Destination IP Activity (Top 20)                           ║")
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")

			limit := 20
			if len(records) < limit {
				limit = len(records)
			}
			for i := 0; i < limit; i++ {
				rec := records[i]
				ipStr := types.Uint32ToIP(rec.IP).String()

				// Get first associated domain (if any)
				domainStr := ""
				for d := range rec.Domains {
					domainStr = d
					break
				}
				if len(rec.Domains) > 1 {
					domainStr += fmt.Sprintf(" +%d", len(rec.Domains)-1)
				}

				bytesStr := formatBytes(rec.Bytes)
				flag := "  "
				if rec.Suspicious {
					flag = "!!"
				}

				if domainStr != "" {
					if len(domainStr) > 22 {
						domainStr = domainStr[:19] + "..."
					}
					fmt.Printf("║ %s %-3d %-16s (%-22s) %5d %7s ║\n",
						flag, i+1, ipStr, domainStr, rec.Connections, bytesStr)
				} else {
					fmt.Printf("║ %s %-3d %-16s %-25s %5d %7s ║\n",
						flag, i+1, ipStr, "", rec.Connections, bytesStr)
				}
			}

			// Suspicious IPs section
			var suspicious []*IPRecord
			for _, rec := range records {
				if rec.Suspicious {
					suspicious = append(suspicious, rec)
				}
			}
			if len(suspicious) > 0 {
				fmt.Println("╠══════════════════════════════════════════════════════════════╣")
				fmt.Println("║  !! Suspicious IP Activity                                  ║")
				fmt.Println("╠══════════════════════════════════════════════════════════════╣")

				for _, rec := range suspicious {
					ipStr := types.Uint32ToIP(rec.IP).String()
					for _, reason := range rec.Reasons {
						if len(reason) > 42 {
							reason = reason[:39] + "..."
						}
						fmt.Printf("║  !! %-16s [%-42s] ║\n", ipStr, reason)
					}
					// Show associated domains this IP visited
					if len(rec.Domains) > 0 {
						domList := make([]string, 0, len(rec.Domains))
						for d := range rec.Domains {
							domList = append(domList, d)
						}
						sort.Strings(domList)
						fmt.Printf("║     Visited domains:\n")
						for _, d := range domList {
							if len(d) > 54 {
								d = d[:51] + "..."
							}
							fmt.Printf("║       -> %-54s ║\n", d)
						}
					}
					// Show destination IPs this flagged IP connected to
					if len(rec.ConnectedTo) > 0 {
						fmt.Printf("║     Connected to IPs:\n")
						destIPs := make([]string, 0, len(rec.ConnectedTo))
						for destIP := range rec.ConnectedTo {
							destStr := types.Uint32ToIP(destIP).String()
							// Look up domain for this dest IP
							destRec := ipTracker.lookupRecord(destIP)
							if destRec != nil && len(destRec.Domains) > 0 {
								for d := range destRec.Domains {
									destStr += " (" + d + ")"
									break
								}
							}
							destIPs = append(destIPs, destStr)
						}
						sort.Strings(destIPs)
						for _, d := range destIPs {
							if len(d) > 54 {
								d = d[:51] + "..."
							}
							fmt.Printf("║       -> %-54s ║\n", d)
						}
					}
				}
			}
		}
	}

	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}

// formatBytes returns a human-readable byte count string.
func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
