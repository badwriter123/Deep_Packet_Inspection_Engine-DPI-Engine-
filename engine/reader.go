package engine

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"dpi-engine/types"
)

// Reader reads packets from a pcap file and distributes them to worker channels.
type Reader struct {
	inputFile   string
	numWorkers  int
	workerChans []chan types.PacketJob
	stats       *Stats
	verbose     bool
	linkType    uint32 // captured link layer type for output writer
}

// NewReader creates a new pcap Reader.
func NewReader(inputFile string, numWorkers int, workerChans []chan types.PacketJob, stats *Stats, verbose bool) *Reader {
	return &Reader{
		inputFile:   inputFile,
		numWorkers:  numWorkers,
		workerChans: workerChans,
		stats:       stats,
		verbose:     verbose,
		linkType:    1, // default: Ethernet
	}
}

// LinkType returns the link layer type detected from the pcap file.
func (r *Reader) LinkType() uint32 {
	return r.linkType
}

// Run reads all packets from the pcap file and distributes them to workers.
// It closes all worker channels when done.
func (r *Reader) Run() error {
	defer func() {
		for _, ch := range r.workerChans {
			close(ch)
		}
	}()

	handle, err := pcap.OpenOffline(r.inputFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer handle.Close()

	// Capture the link layer type from the input file for the output writer
	r.linkType = uint32(handle.LinkType())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// Use Lazy decoding for performance but NoCopy=false to ensure
	// packet data is stable across iterations.
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = false

	var packetID uint32

	for packet := range packetSource.Packets() {
		packetID++

		// Get raw bytes — make a defensive copy since gopacket may reuse buffers
		origData := packet.Data()
		if origData == nil || len(origData) == 0 {
			r.stats.ParseErrors.Add(1)
			continue
		}

		r.stats.TotalPackets.Add(1)
		r.stats.TotalBytes.Add(uint64(len(origData)))

		// Decode network layer — must be IPv4
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			// Non-IP packet (ARP, IPv6, etc.) — skip silently
			continue
		}

		ipv4Layer, ok := networkLayer.(*layers.IPv4)
		if !ok {
			// Not IPv4 (could be IPv6) — skip
			continue
		}

		// Guard against malformed IP addresses
		srcIP4 := ipv4Layer.SrcIP.To4()
		dstIP4 := ipv4Layer.DstIP.To4()
		if srcIP4 == nil || dstIP4 == nil {
			r.stats.ParseErrors.Add(1)
			continue
		}

		var tuple types.FiveTuple
		tuple.SrcIP = binary.BigEndian.Uint32(srcIP4)
		tuple.DstIP = binary.BigEndian.Uint32(dstIP4)

		// Decode transport layer — must be TCP or UDP
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			// ICMP or other non-TCP/UDP protocol — skip silently
			continue
		}

		var tcpFlags uint8
		var payloadData []byte

		switch t := transportLayer.(type) {
		case *layers.TCP:
			tuple.SrcPort = uint16(t.SrcPort)
			tuple.DstPort = uint16(t.DstPort)
			tuple.Protocol = 6
			r.stats.TCPPackets.Add(1)

			// Build TCP flags byte
			if t.FIN {
				tcpFlags |= types.TCPFlagFIN
			}
			if t.SYN {
				tcpFlags |= types.TCPFlagSYN
			}
			if t.RST {
				tcpFlags |= types.TCPFlagRST
			}
			if t.ACK {
				tcpFlags |= types.TCPFlagACK
			}

			payloadData = t.Payload
		case *layers.UDP:
			tuple.SrcPort = uint16(t.SrcPort)
			tuple.DstPort = uint16(t.DstPort)
			tuple.Protocol = 17
			r.stats.UDPPackets.Add(1)
			payloadData = t.Payload
		default:
			// Not TCP or UDP — skip
			continue
		}

		// Copy raw data to decouple from gopacket internal buffers
		rawData := make([]byte, len(origData))
		copy(rawData, origData)

		// Compute payload offset: the payload starts at (total - payloadLen) in the raw bytes
		payloadLen := len(payloadData)
		payloadOffset := len(rawData) - payloadLen
		if payloadOffset < 0 {
			payloadOffset = 0
			payloadLen = 0
		}

		// Extract timestamps
		metadata := packet.Metadata()
		var tsSec, tsUsec uint32
		if metadata != nil && !metadata.CaptureInfo.Timestamp.IsZero() {
			tsSec = uint32(metadata.CaptureInfo.Timestamp.Unix())
			tsUsec = uint32(metadata.CaptureInfo.Timestamp.Nanosecond() / 1000)
		}

		job := types.PacketJob{
			PacketID:      packetID,
			Tuple:         tuple,
			RawData:       rawData,
			PayloadOffset: payloadOffset,
			PayloadLength: payloadLen,
			TCPFlags:      tcpFlags,
			TsSec:         tsSec,
			TsUsec:        tsUsec,
		}

		// Route to worker based on 5-tuple hash
		workerIdx := int(tuple.Hash() % uint64(r.numWorkers))
		r.workerChans[workerIdx] <- job
	}

	if r.verbose {
		fmt.Printf("[reader] Finished reading %d packets\n", packetID)
	}

	return nil
}
