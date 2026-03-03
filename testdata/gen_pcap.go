// +build ignore

// gen_pcap generates a test pcap file with DNS, HTTP, and TLS traffic.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	f, err := os.Create("testdata/test_traffic.pcap")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// PCAP global header
	writeLE(f, uint32(0xa1b2c3d4)) // magic
	writeLE(f, uint16(2))           // version major
	writeLE(f, uint16(4))           // version minor
	writeLE(f, int32(0))            // thiszone
	writeLE(f, uint32(0))           // sigfigs
	writeLE(f, uint32(65535))       // snaplen
	writeLE(f, uint32(1))           // Ethernet

	ts := uint32(1700000000)

	// Packet 1: DNS query for youtube.com
	dnsQuery := buildDNSQueryPacket(
		[4]byte{192, 168, 1, 100}, [4]byte{8, 8, 8, 8},
		12345, 53,
		"youtube.com",
	)
	writePacket(f, ts, 0, dnsQuery)
	ts++

	// Packet 2: HTTP GET to www.facebook.com
	httpGet := buildHTTPPacket(
		[4]byte{192, 168, 1, 100}, [4]byte{157, 240, 1, 35},
		54321, 80,
		"GET / HTTP/1.1\r\nHost: www.facebook.com\r\nAccept: */*\r\n\r\n",
	)
	writePacket(f, ts, 0, httpGet)
	ts++

	// Packet 3: TLS ClientHello to www.netflix.com
	tlsHello := buildTLSClientHelloPacket(
		[4]byte{192, 168, 1, 100}, [4]byte{52, 94, 218, 53},
		55555, 443,
		"www.netflix.com",
	)
	writePacket(f, ts, 0, tlsHello)
	ts++

	// Packet 4: TCP SYN (no payload)
	syn := buildTCPSynPacket(
		[4]byte{192, 168, 1, 100}, [4]byte{1, 1, 1, 1},
		60000, 443,
	)
	writePacket(f, ts, 0, syn)
	ts++

	// Packet 5: HTTP POST to api.github.com
	httpPost := buildHTTPPacket(
		[4]byte{192, 168, 1, 100}, [4]byte{140, 82, 121, 4},
		56789, 80,
		"POST /api/data HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 2\r\n\r\n{}",
	)
	writePacket(f, ts, 0, httpPost)
	ts++

	// Packet 6: TLS ClientHello to www.google.com
	tlsHello2 := buildTLSClientHelloPacket(
		[4]byte{192, 168, 1, 100}, [4]byte{142, 250, 80, 46},
		57000, 443,
		"www.google.com",
	)
	writePacket(f, ts, 0, tlsHello2)
	ts++

	// Packet 7: DNS query for tiktok.com
	dnsQuery2 := buildDNSQueryPacket(
		[4]byte{192, 168, 1, 100}, [4]byte{8, 8, 4, 4},
		12346, 53,
		"tiktok.com",
	)
	writePacket(f, ts, 0, dnsQuery2)
	ts++

	// Packet 8: TLS ClientHello to discord.com
	tlsHello3 := buildTLSClientHelloPacket(
		[4]byte{10, 0, 0, 5}, [4]byte{162, 159, 128, 233},
		58000, 443,
		"discord.com",
	)
	writePacket(f, ts, 0, tlsHello3)

	fmt.Println("Generated testdata/test_traffic.pcap with 8 packets")
}

func writePacket(f *os.File, tsSec, tsUsec uint32, data []byte) {
	writeLE(f, tsSec)
	writeLE(f, tsUsec)
	writeLE(f, uint32(len(data)))
	writeLE(f, uint32(len(data)))
	f.Write(data)
}

func writeLE(f *os.File, v interface{}) {
	binary.Write(f, binary.LittleEndian, v)
}

func buildEthIPHeader(srcIP, dstIP [4]byte, proto byte, payloadLen int) []byte {
	totalIPLen := 20 + payloadLen

	buf := make([]byte, 14+20)
	// Ethernet
	buf[12] = 0x08
	buf[13] = 0x00

	// IPv4
	buf[14] = 0x45
	buf[16] = byte(totalIPLen >> 8)
	buf[17] = byte(totalIPLen)
	buf[22] = 64 // TTL
	buf[23] = proto
	copy(buf[26:30], srcIP[:])
	copy(buf[30:34], dstIP[:])

	return buf
}

func buildTCPHeader(srcPort, dstPort uint16, flags byte, payloadLen int) []byte {
	tcp := make([]byte, 20)
	tcp[0] = byte(srcPort >> 8)
	tcp[1] = byte(srcPort)
	tcp[2] = byte(dstPort >> 8)
	tcp[3] = byte(dstPort)
	tcp[12] = 0x50 // data offset = 5
	tcp[13] = flags
	tcp[14] = 0xFF // window size
	tcp[15] = 0xFF
	return tcp
}

func buildUDPHeader(srcPort, dstPort uint16, payloadLen int) []byte {
	udpLen := 8 + payloadLen
	udp := make([]byte, 8)
	udp[0] = byte(srcPort >> 8)
	udp[1] = byte(srcPort)
	udp[2] = byte(dstPort >> 8)
	udp[3] = byte(dstPort)
	udp[4] = byte(udpLen >> 8)
	udp[5] = byte(udpLen)
	return udp
}

func buildDNSQueryPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, domain string) []byte {
	// DNS payload
	dns := []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	// Encode domain
	qname := encodeDNSName(domain)
	dns = append(dns, qname...)
	dns = append(dns, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN

	udp := buildUDPHeader(srcPort, dstPort, len(dns))
	ethip := buildEthIPHeader(srcIP, dstIP, 17, len(udp)+len(dns))

	result := make([]byte, 0, len(ethip)+len(udp)+len(dns))
	result = append(result, ethip...)
	result = append(result, udp...)
	result = append(result, dns...)
	return result
}

func buildHTTPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, httpData string) []byte {
	payload := []byte(httpData)
	tcp := buildTCPHeader(srcPort, dstPort, 0x18, len(payload)) // ACK+PSH
	ethip := buildEthIPHeader(srcIP, dstIP, 6, len(tcp)+len(payload))

	result := make([]byte, 0, len(ethip)+len(tcp)+len(payload))
	result = append(result, ethip...)
	result = append(result, tcp...)
	result = append(result, payload...)
	return result
}

func buildTCPSynPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	tcp := buildTCPHeader(srcPort, dstPort, 0x02, 0) // SYN
	ethip := buildEthIPHeader(srcIP, dstIP, 6, len(tcp))

	result := make([]byte, 0, len(ethip)+len(tcp))
	result = append(result, ethip...)
	result = append(result, tcp...)
	return result
}

func buildTLSClientHelloPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, hostname string) []byte {
	// Build TLS ClientHello with SNI
	tlsPayload := buildMinimalClientHello(hostname)
	tcp := buildTCPHeader(srcPort, dstPort, 0x18, len(tlsPayload)) // ACK+PSH
	ethip := buildEthIPHeader(srcIP, dstIP, 6, len(tcp)+len(tlsPayload))

	result := make([]byte, 0, len(ethip)+len(tcp)+len(tlsPayload))
	result = append(result, ethip...)
	result = append(result, tcp...)
	result = append(result, tlsPayload...)
	return result
}

func buildMinimalClientHello(hostname string) []byte {
	sniNameLen := len(hostname)
	sniExtDataLen := 2 + 1 + 2 + sniNameLen
	sniExtLen := 2 + 2 + sniExtDataLen
	extsTotalLen := sniExtLen
	chBodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extsTotalLen
	hsLen := 1 + 3 + chBodyLen
	totalLen := 5 + hsLen

	buf := make([]byte, totalLen)
	off := 0

	buf[off] = 0x16; off++
	buf[off] = 0x03; off++
	buf[off] = 0x01; off++
	buf[off] = byte(hsLen >> 8); off++
	buf[off] = byte(hsLen); off++

	buf[off] = 0x01; off++
	buf[off] = byte(chBodyLen >> 16); off++
	buf[off] = byte(chBodyLen >> 8); off++
	buf[off] = byte(chBodyLen); off++

	buf[off] = 0x03; off++
	buf[off] = 0x03; off++

	off += 32 // random

	buf[off] = 0x00; off++ // session ID len

	buf[off] = 0x00; off++
	buf[off] = 0x02; off++ // cipher suites len
	buf[off] = 0x00; off++
	buf[off] = 0xff; off++ // cipher suite

	buf[off] = 0x01; off++ // compression methods len
	buf[off] = 0x00; off++ // null compression

	buf[off] = byte(extsTotalLen >> 8); off++
	buf[off] = byte(extsTotalLen); off++

	// SNI extension
	buf[off] = 0x00; off++
	buf[off] = 0x00; off++
	buf[off] = byte(sniExtDataLen >> 8); off++
	buf[off] = byte(sniExtDataLen); off++
	buf[off] = byte((sniExtDataLen - 2) >> 8); off++
	buf[off] = byte(sniExtDataLen - 2); off++
	buf[off] = 0x00; off++ // hostname type
	buf[off] = byte(sniNameLen >> 8); off++
	buf[off] = byte(sniNameLen); off++
	copy(buf[off:], hostname)

	return buf
}

func encodeDNSName(domain string) []byte {
	var result []byte
	label := ""
	for _, c := range domain {
		if c == '.' {
			result = append(result, byte(len(label)))
			result = append(result, []byte(label)...)
			label = ""
		} else {
			label += string(c)
		}
	}
	if label != "" {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0x00) // terminator
	return result
}
