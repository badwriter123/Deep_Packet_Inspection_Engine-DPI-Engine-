package dpi

import (
	"testing"
)

func TestExtractHTTPHost(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n")
	host, ok := ExtractHTTPHost(payload)
	if !ok {
		t.Fatal("ExtractHTTPHost returned false for valid HTTP request")
	}
	if host != "www.example.com" {
		t.Errorf("Expected 'www.example.com', got %q", host)
	}
}

func TestExtractHTTPHostWithPort(t *testing.T) {
	payload := []byte("GET /path HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n")
	host, ok := ExtractHTTPHost(payload)
	if !ok {
		t.Fatal("ExtractHTTPHost returned false")
	}
	if host != "example.com" {
		t.Errorf("Expected 'example.com' (port stripped), got %q", host)
	}
}

func TestExtractHTTPHostPOST(t *testing.T) {
	payload := []byte("POST /api/data HTTP/1.1\r\nHost: api.github.com\r\nContent-Type: application/json\r\n\r\n{}")
	host, ok := ExtractHTTPHost(payload)
	if !ok {
		t.Fatal("ExtractHTTPHost returned false for POST request")
	}
	if host != "api.github.com" {
		t.Errorf("Expected 'api.github.com', got %q", host)
	}
}

func TestExtractHTTPHostHEAD(t *testing.T) {
	payload := []byte("HEAD / HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n")
	host, ok := ExtractHTTPHost(payload)
	if !ok {
		t.Fatal("ExtractHTTPHost returned false for HEAD request")
	}
	if host != "cdn.example.com" {
		t.Errorf("Expected 'cdn.example.com', got %q", host)
	}
}

func TestExtractHTTPHostNotHTTP(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x10} // TLS data
	_, ok := ExtractHTTPHost(payload)
	if ok {
		t.Error("ExtractHTTPHost should return false for non-HTTP data")
	}
}

func TestExtractHTTPHostNoHostHeader(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n")
	_, ok := ExtractHTTPHost(payload)
	if ok {
		t.Error("ExtractHTTPHost should return false when no Host header")
	}
}

func TestExtractHTTPHostTooShort(t *testing.T) {
	_, ok := ExtractHTTPHost([]byte("GET"))
	if ok {
		t.Error("ExtractHTTPHost should return false for too-short data")
	}
}

func TestExtractHTTPHostCaseInsensitive(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nhOsT: CaseTest.com\r\n\r\n")
	host, ok := ExtractHTTPHost(payload)
	if !ok {
		t.Fatal("ExtractHTTPHost should handle case-insensitive Host header")
	}
	if host != "CaseTest.com" {
		t.Errorf("Expected 'CaseTest.com', got %q", host)
	}
}
