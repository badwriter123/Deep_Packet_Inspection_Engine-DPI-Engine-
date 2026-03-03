package engine

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"dpi-engine/rules"
)

// writeSamplePcap creates a minimal valid pcap file with one TCP SYN packet.
// This simulates a real-world pcap that the engine should be able to process.
func writeSamplePcap(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create sample pcap: %v", err)
	}
	defer f.Close()

	// Global header
	globalHeader := pcapGlobalHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      65535,
		Network:      1, // Ethernet
	}
	if err := binary.Write(f, binary.LittleEndian, &globalHeader); err != nil {
		t.Fatalf("failed to write global header: %v", err)
	}

	// Build a valid Ethernet + IPv4 + TCP SYN packet
	packet := buildTCPSynPacket()

	// Packet header
	pktHeader := pcapPacketHeader{
		TsSec:   1700000000,
		TsUsec:  0,
		InclLen: uint32(len(packet)),
		OrigLen: uint32(len(packet)),
	}
	if err := binary.Write(f, binary.LittleEndian, &pktHeader); err != nil {
		t.Fatalf("failed to write packet header: %v", err)
	}
	if _, err := f.Write(packet); err != nil {
		t.Fatalf("failed to write packet data: %v", err)
	}

	// Add a second packet: TCP with HTTP GET payload
	httpPacket := buildHTTPGetPacket()
	pktHeader2 := pcapPacketHeader{
		TsSec:   1700000001,
		TsUsec:  0,
		InclLen: uint32(len(httpPacket)),
		OrigLen: uint32(len(httpPacket)),
	}
	if err := binary.Write(f, binary.LittleEndian, &pktHeader2); err != nil {
		t.Fatalf("failed to write packet header: %v", err)
	}
	if _, err := f.Write(httpPacket); err != nil {
		t.Fatalf("failed to write packet data: %v", err)
	}
}

// buildTCPSynPacket constructs a minimal Ethernet/IPv4/TCP SYN packet.
func buildTCPSynPacket() []byte {
	// Ethernet header (14 bytes)
	eth := make([]byte, 14)
	eth[12] = 0x08 // EtherType IPv4
	eth[13] = 0x00

	// IPv4 header (20 bytes, no options)
	ip := make([]byte, 20)
	ip[0] = 0x45       // Version=4, IHL=5
	ip[2] = 0x00       // Total length high byte
	ip[3] = 40         // Total length = 20 (IP) + 20 (TCP) = 40
	ip[8] = 64         // TTL
	ip[9] = 6          // Protocol = TCP
	ip[12] = 192       // SrcIP: 192.168.1.100
	ip[13] = 168
	ip[14] = 1
	ip[15] = 100
	ip[16] = 93        // DstIP: 93.184.216.34 (example.com)
	ip[17] = 184
	ip[18] = 216
	ip[19] = 34

	// TCP header (20 bytes, no options)
	tcp := make([]byte, 20)
	tcp[0] = 0xC0      // SrcPort high: 49152
	tcp[1] = 0x00
	tcp[2] = 0x00      // DstPort: 80
	tcp[3] = 0x50
	tcp[12] = 0x50     // Data offset = 5 (20 bytes), no flags except...
	tcp[13] = 0x02     // SYN flag

	result := make([]byte, 0, 54)
	result = append(result, eth...)
	result = append(result, ip...)
	result = append(result, tcp...)
	return result
}

// buildHTTPGetPacket constructs a packet with an HTTP GET request payload.
func buildHTTPGetPacket() []byte {
	payload := []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n")

	// Ethernet header (14 bytes)
	eth := make([]byte, 14)
	eth[12] = 0x08
	eth[13] = 0x00

	totalIPLen := 20 + 20 + len(payload)

	// IPv4 header (20 bytes)
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[2] = byte(totalIPLen >> 8)
	ip[3] = byte(totalIPLen)
	ip[8] = 64
	ip[9] = 6 // TCP
	ip[12] = 192
	ip[13] = 168
	ip[14] = 1
	ip[15] = 100
	ip[16] = 93
	ip[17] = 184
	ip[18] = 216
	ip[19] = 34

	// TCP header (20 bytes)
	tcp := make([]byte, 20)
	tcp[0] = 0xC0 // SrcPort: 49152
	tcp[1] = 0x00
	tcp[2] = 0x00 // DstPort: 80
	tcp[3] = 0x50
	tcp[12] = 0x50 // Data offset = 5
	tcp[13] = 0x18 // ACK+PSH

	result := make([]byte, 0, 14+20+20+len(payload))
	result = append(result, eth...)
	result = append(result, ip...)
	result = append(result, tcp...)
	result = append(result, payload...)
	return result
}

func TestEngineEndToEnd(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.pcap")
	outputPath := filepath.Join(dir, "output.pcap")

	writeSamplePcap(t, inputPath)

	rm := rules.NewRuleManager()
	config := Config{
		InputFile:   inputPath,
		OutputFile:  outputPath,
		NumWorkers:  2,
		Verbose:     false,
		RuleManager: rm,
	}

	engine := NewDPIEngine(config)
	if err := engine.Run(); err != nil {
		t.Fatalf("Engine.Run() failed: %v", err)
	}

	// Verify output file exists and is valid pcap
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Output file not found: %v", err)
	}
	// Should have at least the global header (24 bytes) + 2 packets
	if info.Size() < 24 {
		t.Fatalf("Output file too small: %d bytes", info.Size())
	}

	// Read and verify the global header
	f, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open output: %v", err)
	}
	defer f.Close()

	var header pcapGlobalHeader
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		t.Fatalf("Failed to read global header: %v", err)
	}
	if header.MagicNumber != 0xa1b2c3d4 {
		t.Errorf("Wrong magic number: 0x%x", header.MagicNumber)
	}
	if header.VersionMajor != 2 || header.VersionMinor != 4 {
		t.Errorf("Wrong version: %d.%d", header.VersionMajor, header.VersionMinor)
	}
}

func TestEngineWithBlockingRules(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.pcap")
	outputPath := filepath.Join(dir, "output.pcap")

	writeSamplePcap(t, inputPath)

	// Block port 80 — should drop the HTTP packets
	rm := rules.NewRuleManager()
	rm.AddBlockedPort(80)

	config := Config{
		InputFile:   inputPath,
		OutputFile:  outputPath,
		NumWorkers:  2,
		Verbose:     false,
		RuleManager: rm,
	}

	engine := NewDPIEngine(config)
	if err := engine.Run(); err != nil {
		t.Fatalf("Engine.Run() failed: %v", err)
	}

	// Output should only have the global header (all packets blocked)
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Output file not found: %v", err)
	}
	// With port 80 blocked, both packets (dst port 80) should be dropped.
	// Output should be just the 24-byte global header.
	if info.Size() != 24 {
		t.Errorf("Expected output with only global header (24 bytes), got %d bytes", info.Size())
	}
}

func TestEngineInvalidInput(t *testing.T) {
	config := Config{
		InputFile:   "/nonexistent/path/input.pcap",
		OutputFile:  "/tmp/output.pcap",
		NumWorkers:  1,
		Verbose:     false,
		RuleManager: rules.NewRuleManager(),
	}

	engine := NewDPIEngine(config)
	err := engine.Run()
	if err == nil {
		t.Error("Expected error for nonexistent input file")
	}
}
