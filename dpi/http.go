package dpi

import (
	"bytes"
	"strings"
)

// httpMethods are the recognized HTTP method prefixes.
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST"),
	[]byte("PUT "),
	[]byte("HEAD"),
	[]byte("DELE"),
	[]byte("PATC"),
	[]byte("OPTI"),
}

// ExtractHTTPHost extracts the Host header value from an HTTP request payload.
//
// Returns the hostname and true if extraction succeeded, or ("", false) if the
// payload does not look like an HTTP request or does not contain a Host header.
func ExtractHTTPHost(payload []byte) (string, bool) {
	if len(payload) < 16 {
		return "", false
	}

	// Check that the payload starts with a known HTTP method
	isHTTP := false
	for _, method := range httpMethods {
		if len(payload) >= len(method) && bytes.Equal(payload[:len(method)], method) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return "", false
	}

	// Scan for Host: header (case-insensitive)
	// We look for "\r\nHost:" or "\nHost:" patterns
	hostIdx := -1
	lower := bytes.ToLower(payload)

	patterns := [][]byte{
		[]byte("\r\nhost:"),
		[]byte("\nhost:"),
	}

	for _, pat := range patterns {
		idx := bytes.Index(lower, pat)
		if idx >= 0 {
			// Move past the pattern to the value
			hostIdx = idx + len(pat)
			break
		}
	}

	if hostIdx < 0 {
		return "", false
	}

	// Extract value: trim leading whitespace, read until \r or \n
	end := len(payload)
	start := hostIdx

	// Skip leading whitespace
	for start < end && (payload[start] == ' ' || payload[start] == '\t') {
		start++
	}

	// Find end of line
	lineEnd := start
	for lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n' {
		lineEnd++
	}

	if lineEnd <= start {
		return "", false
	}

	host := strings.TrimSpace(string(payload[start:lineEnd]))

	// Strip port if present
	if colonIdx := strings.LastIndex(host, ":"); colonIdx >= 0 {
		host = host[:colonIdx]
	}

	if len(host) == 0 {
		return "", false
	}

	return host, true
}
