package dpi

// ExtractSNI extracts the Server Name Indication (SNI) hostname from a TLS
// ClientHello message in the raw payload bytes. All parsing is done manually
// without relying on gopacket.
//
// Returns the hostname and true if extraction succeeded, or ("", false) if the
// payload is not a valid TLS ClientHello or does not contain an SNI extension.
func ExtractSNI(payload []byte) (string, bool) {
	// Need at least TLS record header (5) + handshake header (4) + client hello min fields
	if len(payload) < 44 {
		return "", false
	}

	// TLS Record Header
	// byte[0] = content type, must be 0x16 (Handshake)
	if payload[0] != 0x16 {
		return "", false
	}

	// byte[1-2] = TLS version: must be 0x0300–0x0304
	version := uint16(payload[1])<<8 | uint16(payload[2])
	if version < 0x0300 || version > 0x0304 {
		return "", false
	}

	// byte[3-4] = record length
	recordLen := int(uint16(payload[3])<<8 | uint16(payload[4]))
	if 5+recordLen > len(payload) {
		// Allow processing with available data, but cap
		recordLen = len(payload) - 5
	}

	// Handshake starts at byte 5
	offset := 5

	// byte[5] = handshake type, must be 0x01 (ClientHello)
	if offset >= len(payload) || payload[offset] != 0x01 {
		return "", false
	}
	offset++

	// byte[6-8] = handshake length (uint24 big-endian)
	if offset+3 > len(payload) {
		return "", false
	}
	_ = int(payload[offset])<<16 | int(payload[offset+1])<<8 | int(payload[offset+2])
	offset += 3

	// ClientHello body starts at byte 9
	// byte[9-10] = client version
	if offset+2 > len(payload) {
		return "", false
	}
	offset += 2

	// byte[11-42] = 32 bytes of random
	if offset+32 > len(payload) {
		return "", false
	}
	offset += 32

	// Session ID
	if offset >= len(payload) {
		return "", false
	}
	sessionIDLen := int(payload[offset])
	offset++
	if offset+sessionIDLen > len(payload) {
		return "", false
	}
	offset += sessionIDLen

	// Cipher suites
	if offset+2 > len(payload) {
		return "", false
	}
	cipherSuitesLen := int(uint16(payload[offset])<<8 | uint16(payload[offset+1]))
	offset += 2
	if offset+cipherSuitesLen > len(payload) {
		return "", false
	}
	offset += cipherSuitesLen

	// Compression methods
	if offset >= len(payload) {
		return "", false
	}
	compMethodsLen := int(payload[offset])
	offset++
	if offset+compMethodsLen > len(payload) {
		return "", false
	}
	offset += compMethodsLen

	// Extensions total length
	if offset+2 > len(payload) {
		return "", false
	}
	extensionsLen := int(uint16(payload[offset])<<8 | uint16(payload[offset+1]))
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(payload) {
		extensionsEnd = len(payload)
	}

	// Parse extensions
	for offset+4 <= extensionsEnd {
		extType := uint16(payload[offset])<<8 | uint16(payload[offset+1])
		offset += 2
		extDataLen := int(uint16(payload[offset])<<8 | uint16(payload[offset+1]))
		offset += 2

		if offset+extDataLen > extensionsEnd {
			return "", false
		}

		// SNI extension type == 0x0000
		if extType == 0x0000 {
			return parseSNIExtension(payload[offset : offset+extDataLen])
		}

		offset += extDataLen
	}

	return "", false
}

// parseSNIExtension parses the SNI extension data to extract the hostname.
func parseSNIExtension(data []byte) (string, bool) {
	if len(data) < 5 {
		return "", false
	}

	// 2 bytes = SNI list length
	sniListLen := int(uint16(data[0])<<8 | uint16(data[1]))
	if 2+sniListLen > len(data) {
		return "", false
	}

	offset := 2

	// 1 byte = name type (must be 0x00 for hostname)
	if data[offset] != 0x00 {
		return "", false
	}
	offset++

	// 2 bytes = name length
	if offset+2 > len(data) {
		return "", false
	}
	nameLen := int(uint16(data[offset])<<8 | uint16(data[offset+1]))
	offset += 2

	if offset+nameLen > len(data) {
		return "", false
	}

	hostname := string(data[offset : offset+nameLen])
	if len(hostname) == 0 {
		return "", false
	}

	return hostname, true
}
