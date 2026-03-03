package engine

import (
	"encoding/binary"
	"fmt"
	"os"

	"dpi-engine/types"
)

// pcapGlobalHeader is the 24-byte PCAP file global header.
type pcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// pcapPacketHeader is the 16-byte per-packet record header.
type pcapPacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// Writer writes forwarded packets to a PCAP output file.
type Writer struct {
	outputFile string
	outputChan <-chan types.PacketJob
	linkType   uint32
	verbose    bool
}

// NewWriter creates a new output Writer.
func NewWriter(outputFile string, outputChan <-chan types.PacketJob, linkType uint32, verbose bool) *Writer {
	if linkType == 0 {
		linkType = 1 // default Ethernet
	}
	return &Writer{
		outputFile: outputFile,
		outputChan: outputChan,
		linkType:   linkType,
		verbose:    verbose,
	}
}

// Run writes all packets from the output channel to the pcap file.
// It returns when the output channel is closed and drained.
func (w *Writer) Run() error {
	f, err := os.Create(w.outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	// Write global PCAP header
	header := pcapGlobalHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      65535,
		Network:      w.linkType,
	}
	if err := binary.Write(f, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to write pcap header: %w", err)
	}

	var count uint64

	for job := range w.outputChan {
		pktHeader := pcapPacketHeader{
			TsSec:   job.TsSec,
			TsUsec:  job.TsUsec,
			InclLen: uint32(len(job.RawData)),
			OrigLen: uint32(len(job.RawData)),
		}

		if err := binary.Write(f, binary.LittleEndian, &pktHeader); err != nil {
			return fmt.Errorf("failed to write packet header: %w", err)
		}

		if _, err := f.Write(job.RawData); err != nil {
			return fmt.Errorf("failed to write packet data: %w", err)
		}

		count++
	}

	if w.verbose {
		fmt.Printf("[writer] Wrote %d packets to %s\n", count, w.outputFile)
	}

	return nil
}
