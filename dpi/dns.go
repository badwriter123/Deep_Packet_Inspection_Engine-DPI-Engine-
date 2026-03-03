package dpi

// ExtractDNSQuery extracts the domain name from a DNS query payload.
//
// Returns the assembled domain string and true if extraction succeeded, or
// ("", false) if the payload is not a valid DNS query.
func ExtractDNSQuery(payload []byte) (string, bool) {
	// DNS header is 12 bytes minimum
	if len(payload) < 12 {
		return "", false
	}

	// Check QR bit (byte[2] bit 7) == 0 (it's a query, not a response)
	if payload[2]&0x80 != 0 {
		return "", false
	}

	// Check QDCOUNT (bytes[4-5]) > 0
	qdcount := uint16(payload[4])<<8 | uint16(payload[5])
	if qdcount == 0 {
		return "", false
	}

	// Parse domain name starting at byte 12
	offset := 12
	var domain []byte

	for offset < len(payload) {
		labelLen := int(payload[offset])
		offset++

		// End of name
		if labelLen == 0 {
			break
		}

		// Compression pointer (label length byte has top 2 bits set)
		if labelLen > 63 {
			// Compression pointer — stop parsing
			break
		}

		// Bounds check
		if offset+labelLen > len(payload) {
			return "", false
		}

		// Append dot separator if we already have labels
		if len(domain) > 0 {
			domain = append(domain, '.')
		}

		domain = append(domain, payload[offset:offset+labelLen]...)
		offset += labelLen
	}

	if len(domain) == 0 {
		return "", false
	}

	return string(domain), true
}
