package engine

import (
	"testing"

	"dpi-engine/types"
)

// testSrcIP is a dummy source IP for tests (192.168.1.100).
var testSrcIP = types.IPToUint32([]byte{192, 168, 1, 100})

func TestIPTrackerBasic(t *testing.T) {
	tracker := NewIPTracker()

	googleIP := types.IPToUint32([]byte{142, 250, 80, 46})
	tracker.Track(testSrcIP, googleIP, 443, 1500, "www.google.com")
	tracker.Track(testSrcIP, googleIP, 443, 800, "www.google.com")

	records := tracker.GetRecords()
	// 2 records: googleIP (destination) + testSrcIP (source)
	var dstRec *IPRecord
	for _, r := range records {
		if r.IP == googleIP {
			dstRec = r
		}
	}
	if dstRec == nil {
		t.Fatal("Expected a record for Google IP")
	}
	if dstRec.Connections != 2 {
		t.Errorf("Expected 2 connections, got %d", dstRec.Connections)
	}
	if dstRec.Bytes != 2300 {
		t.Errorf("Expected 2300 bytes, got %d", dstRec.Bytes)
	}
	if !dstRec.Domains["www.google.com"] {
		t.Error("Expected domain www.google.com to be tracked")
	}
}

func TestIPTrackerSourceTracksDestinations(t *testing.T) {
	tracker := NewIPTracker()

	laptopIP := types.IPToUint32([]byte{192, 168, 1, 100})
	googleIP := types.IPToUint32([]byte{142, 250, 80, 46})
	netflixIP := types.IPToUint32([]byte{52, 94, 218, 53})

	tracker.Track(laptopIP, googleIP, 443, 1000, "www.google.com")
	tracker.Track(laptopIP, netflixIP, 443, 2000, "www.netflix.com")

	// Source IP should track which destinations it connected to
	records := tracker.GetRecords()
	var srcRec *IPRecord
	for _, r := range records {
		if r.IP == laptopIP {
			srcRec = r
		}
	}
	if srcRec == nil {
		t.Fatal("Expected a record for laptop IP")
	}
	if !srcRec.ConnectedTo[googleIP] {
		t.Error("Source IP should track connection to Google")
	}
	if !srcRec.ConnectedTo[netflixIP] {
		t.Error("Source IP should track connection to Netflix")
	}
	if !srcRec.Domains["www.google.com"] || !srcRec.Domains["www.netflix.com"] {
		t.Error("Source IP should track visited domains")
	}
}

func TestIPTrackerMultipleDomains(t *testing.T) {
	tracker := NewIPTracker()

	cdnIP := types.IPToUint32([]byte{104, 18, 22, 35})
	tracker.Track(testSrcIP, cdnIP, 443, 100, "example.com")
	tracker.Track(testSrcIP, cdnIP, 443, 200, "other.com")

	records := tracker.GetRecords()
	var dstRec *IPRecord
	for _, r := range records {
		if r.IP == cdnIP {
			dstRec = r
		}
	}
	if dstRec == nil {
		t.Fatal("Expected a record for CDN IP")
	}
	if len(dstRec.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(dstRec.Domains))
	}
}

func TestSuspiciousHighVolume(t *testing.T) {
	tracker := NewIPTracker()

	ip := types.IPToUint32([]byte{45, 33, 32, 156})
	for i := 0; i < 150; i++ {
		tracker.Track(testSrcIP, ip, 443, 100, "example.com")
	}

	tracker.Analyze()

	records := tracker.GetRecords()
	var rec *IPRecord
	for _, r := range records {
		if r.IP == ip {
			rec = r
		}
	}
	if rec == nil {
		t.Fatal("Expected a record for target IP")
	}
	if !rec.Suspicious {
		t.Error("Expected IP to be flagged as suspicious (high volume)")
	}
	found := false
	for _, r := range rec.Reasons {
		if len(r) > 10 && r[:11] == "HIGH VOLUME" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected HIGH VOLUME reason, got: %v", rec.Reasons)
	}
}

func TestSuspiciousReservedRange(t *testing.T) {
	tracker := NewIPTracker()

	publicSrc := types.IPToUint32([]byte{8, 8, 8, 8})

	// 192.168.1.1 — private IP as destination
	privateIP := types.IPToUint32([]byte{192, 168, 1, 1})
	tracker.Track(publicSrc, privateIP, 80, 500, "")

	// 10.0.0.1 — another private range
	privateIP2 := types.IPToUint32([]byte{10, 0, 0, 1})
	tracker.Track(publicSrc, privateIP2, 443, 300, "")

	tracker.Analyze()

	records := tracker.GetRecords()
	for _, rec := range records {
		if rec.IP == privateIP || rec.IP == privateIP2 {
			if !rec.Suspicious {
				t.Errorf("Expected IP %s to be flagged as suspicious (reserved range)",
					types.Uint32ToIP(rec.IP))
			}
		}
	}
}

func TestSuspiciousPortScan(t *testing.T) {
	tracker := NewIPTracker()

	ip := types.IPToUint32([]byte{45, 33, 32, 156})
	for port := uint16(1); port <= 15; port++ {
		tracker.Track(testSrcIP, ip, port, 100, "")
	}

	tracker.Analyze()

	records := tracker.GetRecords()
	var rec *IPRecord
	for _, r := range records {
		if r.IP == ip {
			rec = r
		}
	}
	if rec == nil {
		t.Fatal("Expected a record for target IP")
	}
	if !rec.Suspicious {
		t.Error("Expected IP to be flagged as suspicious (port scan)")
	}
	foundPortScan := false
	for _, r := range rec.Reasons {
		if len(r) > 8 && r[:9] == "PORT SCAN" {
			foundPortScan = true
		}
	}
	if !foundPortScan {
		t.Errorf("Expected PORT SCAN reason, got: %v", rec.Reasons)
	}
}

func TestNotSuspiciousNormalTraffic(t *testing.T) {
	tracker := NewIPTracker()

	ip := types.IPToUint32([]byte{142, 250, 80, 46})
	tracker.Track(testSrcIP, ip, 443, 1500, "www.google.com")
	tracker.Track(testSrcIP, ip, 443, 800, "www.google.com")

	tracker.Analyze()

	records := tracker.GetRecords()
	var rec *IPRecord
	for _, r := range records {
		if r.IP == ip {
			rec = r
		}
	}
	if rec == nil {
		t.Fatal("Expected a record for Google IP")
	}
	if rec.Suspicious {
		t.Errorf("Normal traffic should not be flagged, reasons: %v", rec.Reasons)
	}
}

func TestIsReservedIP(t *testing.T) {
	tests := []struct {
		ip       [4]byte
		reserved bool
	}{
		{[4]byte{10, 0, 0, 1}, true},
		{[4]byte{10, 255, 255, 255}, true},
		{[4]byte{172, 16, 0, 1}, true},
		{[4]byte{172, 31, 255, 255}, true},
		{[4]byte{172, 15, 0, 1}, false},
		{[4]byte{172, 32, 0, 1}, false},
		{[4]byte{192, 168, 0, 1}, true},
		{[4]byte{192, 168, 255, 255}, true},
		{[4]byte{192, 169, 0, 1}, false},
		{[4]byte{127, 0, 0, 1}, true},
		{[4]byte{0, 0, 0, 0}, true},
		{[4]byte{224, 0, 0, 1}, true},      // multicast
		{[4]byte{255, 255, 255, 255}, true}, // broadcast
		{[4]byte{8, 8, 8, 8}, false},        // Google DNS
		{[4]byte{1, 1, 1, 1}, false},        // Cloudflare
		{[4]byte{142, 250, 80, 46}, false},  // Google
	}

	for _, tt := range tests {
		ip := types.IPToUint32(tt.ip[:])
		got := isReservedIP(ip)
		if got != tt.reserved {
			t.Errorf("isReservedIP(%v) = %v, want %v", tt.ip, got, tt.reserved)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{0, "0B"},
		{500, "500B"},
		{1024, "1.0KB"},
		{1536, "1.5KB"},
		{1048576, "1.0MB"},
		{1073741824, "1.0GB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
