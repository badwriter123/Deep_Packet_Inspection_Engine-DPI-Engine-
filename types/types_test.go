package types

import (
	"testing"
)

func TestFiveTupleHashDeterministic(t *testing.T) {
	tuple := FiveTuple{
		SrcIP:    0xC0A80001, // 192.168.0.1
		DstIP:    0x08080808, // 8.8.8.8
		SrcPort:  12345,
		DstPort:  443,
		Protocol: 6,
	}

	h1 := tuple.Hash()
	h2 := tuple.Hash()

	if h1 != h2 {
		t.Errorf("Hash is not deterministic: %d != %d", h1, h2)
	}
}

func TestFiveTupleHashDifferentForReverse(t *testing.T) {
	tuple := FiveTuple{
		SrcIP:    0xC0A80001,
		DstIP:    0x08080808,
		SrcPort:  12345,
		DstPort:  443,
		Protocol: 6,
	}

	rev := tuple.Reverse()
	h1 := tuple.Hash()
	h2 := rev.Hash()

	if h1 == h2 {
		t.Errorf("Forward and reverse tuples should produce different hashes, both got: %d", h1)
	}
}

func TestFiveTupleReverse(t *testing.T) {
	tuple := FiveTuple{
		SrcIP:    0xC0A80001,
		DstIP:    0x08080808,
		SrcPort:  12345,
		DstPort:  443,
		Protocol: 6,
	}

	rev := tuple.Reverse()
	if rev.SrcIP != tuple.DstIP || rev.DstIP != tuple.SrcIP {
		t.Error("Reverse should swap IPs")
	}
	if rev.SrcPort != tuple.DstPort || rev.DstPort != tuple.SrcPort {
		t.Error("Reverse should swap ports")
	}
	if rev.Protocol != tuple.Protocol {
		t.Error("Reverse should preserve protocol")
	}
}

func TestFiveTupleRoutingInvariant(t *testing.T) {
	tuple := FiveTuple{
		SrcIP:    0xC0A80001,
		DstIP:    0x08080808,
		SrcPort:  12345,
		DstPort:  443,
		Protocol: 6,
	}

	numWorkers := uint64(4)
	workerIdx := tuple.Hash() % numWorkers

	// Same tuple should always route to the same worker
	for i := 0; i < 1000; i++ {
		if tuple.Hash()%numWorkers != workerIdx {
			t.Fatalf("Routing invariant violated at iteration %d", i)
		}
	}
}

func TestFiveTupleHashDistribution(t *testing.T) {
	numWorkers := 4
	counts := make([]int, numWorkers)

	// Generate a range of tuples and check distribution
	for i := uint32(0); i < 1000; i++ {
		tuple := FiveTuple{
			SrcIP:    0xC0A80000 + i,
			DstIP:    0x08080808,
			SrcPort:  uint16(1024 + i),
			DstPort:  443,
			Protocol: 6,
		}
		idx := int(tuple.Hash() % uint64(numWorkers))
		counts[idx]++
	}

	// Each worker should get at least some packets (not all to one)
	for i, c := range counts {
		if c == 0 {
			t.Errorf("Worker %d got 0 packets — poor distribution", i)
		}
	}
}

func TestSNIToAppType(t *testing.T) {
	tests := []struct {
		domain   string
		expected AppType
	}{
		{"www.youtube.com", AppYouTube},
		{"youtube.com", AppYouTube},
		{"r1.googlevideo.com", AppYouTube},
		{"www.netflix.com", AppNetflix},
		{"assets.nflxvideo.net", AppNetflix},
		{"www.tiktok.com", AppTikTok},
		{"facebook.com", AppFacebook},
		{"static.fbcdn.net", AppFacebook},
		{"www.instagram.com", AppInstagram},
		{"twitter.com", AppTwitter},
		{"web.whatsapp.com", AppWhatsApp},
		{"discord.com", AppDiscord},
		{"github.com", AppGitHub},
		{"www.google.com", AppGoogle},
		{"login.microsoftonline.com", AppMicrosoft},
		{"unknown-domain.xyz", AppUnknown},
	}

	for _, tt := range tests {
		got := SNIToAppType(tt.domain)
		if got != tt.expected {
			t.Errorf("SNIToAppType(%q) = %v, want %v", tt.domain, got, tt.expected)
		}
	}
}

func TestAppTypeFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected AppType
		ok       bool
	}{
		{"YouTube", AppYouTube, true},
		{"youtube", AppYouTube, true},
		{"YOUTUBE", AppYouTube, true},
		{"HTTP", AppHTTP, true},
		{"nonexistent", AppUnknown, false},
	}

	for _, tt := range tests {
		got, ok := AppTypeFromString(tt.input)
		if ok != tt.ok {
			t.Errorf("AppTypeFromString(%q) ok = %v, want %v", tt.input, ok, tt.ok)
		}
		if ok && got != tt.expected {
			t.Errorf("AppTypeFromString(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestPacketJobPayload(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}

	job := PacketJob{
		RawData:       raw,
		PayloadOffset: 4,
		PayloadLength: 6,
	}

	payload := job.Payload()
	if len(payload) != 6 {
		t.Fatalf("Expected payload length 6, got %d", len(payload))
	}
	if payload[0] != 0x04 || payload[5] != 0x09 {
		t.Error("Payload bytes don't match expected")
	}

	// Test invalid offsets
	job2 := PacketJob{RawData: raw, PayloadOffset: -1, PayloadLength: 5}
	if job2.Payload() != nil {
		t.Error("Expected nil payload for negative offset")
	}

	job3 := PacketJob{RawData: raw, PayloadOffset: 8, PayloadLength: 5}
	if job3.Payload() != nil {
		t.Error("Expected nil payload for out-of-bounds")
	}
}
