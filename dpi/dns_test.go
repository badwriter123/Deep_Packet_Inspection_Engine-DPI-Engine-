package dpi

import (
	"testing"
)

// buildDNSQuery constructs a raw DNS query for the given domain.
func buildDNSQuery(domain string) []byte {
	// DNS header (12 bytes)
	header := []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags: standard query (QR=0)
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}

	// Encode domain name
	var qname []byte
	labels := splitDomain(domain)
	for _, label := range labels {
		qname = append(qname, byte(len(label)))
		qname = append(qname, []byte(label)...)
	}
	qname = append(qname, 0x00) // null terminator

	// QTYPE (A = 1) and QCLASS (IN = 1)
	suffix := []byte{0x00, 0x01, 0x00, 0x01}

	result := append(header, qname...)
	result = append(result, suffix...)
	return result
}

func splitDomain(domain string) []string {
	var labels []string
	current := ""
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				labels = append(labels, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		labels = append(labels, current)
	}
	return labels
}

func TestExtractDNSQuery(t *testing.T) {
	payload := buildDNSQuery("www.example.com")
	domain, ok := ExtractDNSQuery(payload)
	if !ok {
		t.Fatal("ExtractDNSQuery returned false for valid DNS query")
	}
	if domain != "www.example.com" {
		t.Errorf("Expected 'www.example.com', got %q", domain)
	}
}

func TestExtractDNSQuerySingleLabel(t *testing.T) {
	payload := buildDNSQuery("localhost")
	domain, ok := ExtractDNSQuery(payload)
	if !ok {
		t.Fatal("ExtractDNSQuery returned false")
	}
	if domain != "localhost" {
		t.Errorf("Expected 'localhost', got %q", domain)
	}
}

func TestExtractDNSQueryMultipleLabels(t *testing.T) {
	payload := buildDNSQuery("sub.domain.example.co.uk")
	domain, ok := ExtractDNSQuery(payload)
	if !ok {
		t.Fatal("ExtractDNSQuery returned false")
	}
	if domain != "sub.domain.example.co.uk" {
		t.Errorf("Expected 'sub.domain.example.co.uk', got %q", domain)
	}
}

func TestExtractDNSQueryResponse(t *testing.T) {
	// DNS response (QR bit set)
	payload := []byte{
		0x00, 0x01, // Transaction ID
		0x81, 0x80, // Flags: response (QR=1)
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x01, // ANCOUNT: 1
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	}
	_, ok := ExtractDNSQuery(payload)
	if ok {
		t.Error("ExtractDNSQuery should return false for DNS response")
	}
}

func TestExtractDNSQueryTooShort(t *testing.T) {
	_, ok := ExtractDNSQuery([]byte{0x00, 0x01})
	if ok {
		t.Error("ExtractDNSQuery should return false for too-short data")
	}
}

func TestExtractDNSQueryZeroQDCOUNT(t *testing.T) {
	payload := []byte{
		0x00, 0x01,
		0x01, 0x00,
		0x00, 0x00, // QDCOUNT: 0
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	_, ok := ExtractDNSQuery(payload)
	if ok {
		t.Error("ExtractDNSQuery should return false for QDCOUNT=0")
	}
}
