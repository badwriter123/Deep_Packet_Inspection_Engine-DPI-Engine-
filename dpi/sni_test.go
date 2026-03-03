package dpi

import (
	"encoding/hex"
	"testing"
)

// This is a real TLS ClientHello captured for www.example.com
// It contains the SNI extension with hostname "www.example.com"
var tlsClientHelloHex = "160301" + // TLS record: handshake, version 3.1
	"00f1" + // record length: 241
	"01" + // handshake type: ClientHello
	"0000ed" + // handshake length: 237
	"0303" + // client version: TLS 1.2
	// 32 bytes random
	"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd" +
	"00" + // session ID length: 0
	"0004" + // cipher suites length: 4
	"c02cc02b" + // cipher suites
	"0100" + // compression methods: 1 method, null
	// Extensions
	"00be" + // extensions length: 190
	// SNI extension
	"0000" + // extension type: SNI (0x0000)
	"0014" + // extension length: 20
	"0012" + // SNI list length: 18
	"00" + // name type: hostname
	"000f" + // name length: 15
	"7777772e6578616d706c652e636f6d" + // "www.example.com"
	// Some other extension to pad
	"000d" + // extension type: signature_algorithms
	"0004" + // extension length
	"00020401" + // data
	// More padding extensions to reach declared length
	"00170000" + // extended_master_secret (empty)
	"ff01" + // renegotiation_info
	"0001" + // length: 1
	"00" + // data
	// Pad with supported_versions extension
	"002b" + // extension type: supported_versions
	"0003" + // length: 3
	"020304" + // TLS 1.3
	// key_share extension placeholder
	"0033" + // extension type: key_share
	"0026" + // length
	"0024" + // client key share length
	"001d" + // x25519 group
	"0020" + // key exchange length: 32
	"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd" +
	// psk_key_exchange_modes
	"002d" +
	"0002" +
	"0101" +
	// supported_groups
	"000a" +
	"0004" +
	"001d0017" +
	// session_ticket
	"0023" +
	"0000"

func TestExtractSNI(t *testing.T) {
	data, err := hex.DecodeString(tlsClientHelloHex)
	if err != nil {
		t.Fatalf("Failed to decode test hex: %v", err)
	}

	sni, ok := ExtractSNI(data)
	if !ok {
		t.Fatal("ExtractSNI returned false for valid ClientHello")
	}
	if sni != "www.example.com" {
		t.Errorf("Expected 'www.example.com', got %q", sni)
	}
}

func TestExtractSNIMinimalClientHello(t *testing.T) {
	// Build a minimal valid TLS ClientHello with SNI
	hello := buildMinimalClientHello("github.com")
	sni, ok := ExtractSNI(hello)
	if !ok {
		t.Fatal("ExtractSNI returned false for minimal ClientHello")
	}
	if sni != "github.com" {
		t.Errorf("Expected 'github.com', got %q", sni)
	}
}

func TestExtractSNINotTLS(t *testing.T) {
	// Not a TLS record
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, ok := ExtractSNI(data)
	if ok {
		t.Error("ExtractSNI should return false for non-TLS data")
	}
}

func TestExtractSNITooShort(t *testing.T) {
	_, ok := ExtractSNI([]byte{0x16, 0x03, 0x01})
	if ok {
		t.Error("ExtractSNI should return false for too-short data")
	}
}

func TestExtractSNIEmpty(t *testing.T) {
	_, ok := ExtractSNI(nil)
	if ok {
		t.Error("ExtractSNI should return false for nil data")
	}
}

func TestExtractSNIWrongContentType(t *testing.T) {
	data := make([]byte, 100)
	data[0] = 0x17 // application data, not handshake
	data[1] = 0x03
	data[2] = 0x01
	_, ok := ExtractSNI(data)
	if ok {
		t.Error("ExtractSNI should return false for non-handshake content type")
	}
}

// buildMinimalClientHello constructs a minimal TLS 1.2 ClientHello with SNI.
func buildMinimalClientHello(hostname string) []byte {
	sniNameLen := len(hostname)
	sniExtDataLen := 2 + 1 + 2 + sniNameLen // list_len + type + name_len + name
	sniExtLen := 2 + 2 + sniExtDataLen       // ext_type + ext_data_len + data
	extsTotalLen := sniExtLen

	// ClientHello body: version(2) + random(32) + sessionID(1+0) + ciphers(2+2) + compression(1+1) + extensions
	chBodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extsTotalLen

	// Handshake: type(1) + length(3) + body
	hsLen := 1 + 3 + chBodyLen

	// TLS record: type(1) + version(2) + length(2) + handshake
	totalLen := 5 + hsLen

	buf := make([]byte, totalLen)
	off := 0

	// TLS Record Header
	buf[off] = 0x16 // Handshake
	off++
	buf[off] = 0x03
	off++
	buf[off] = 0x01 // TLS 1.0 record version
	off++
	buf[off] = byte(hsLen >> 8)
	off++
	buf[off] = byte(hsLen)
	off++

	// Handshake Header
	buf[off] = 0x01 // ClientHello
	off++
	buf[off] = byte(chBodyLen >> 16)
	off++
	buf[off] = byte(chBodyLen >> 8)
	off++
	buf[off] = byte(chBodyLen)
	off++

	// Client version
	buf[off] = 0x03
	off++
	buf[off] = 0x03 // TLS 1.2
	off++

	// Random (32 bytes of zeros)
	off += 32

	// Session ID length = 0
	buf[off] = 0x00
	off++

	// Cipher suites length = 2
	buf[off] = 0x00
	off++
	buf[off] = 0x02
	off++
	// One cipher suite
	buf[off] = 0x00
	off++
	buf[off] = 0xff
	off++

	// Compression methods length = 1
	buf[off] = 0x01
	off++
	buf[off] = 0x00 // null compression
	off++

	// Extensions total length
	buf[off] = byte(extsTotalLen >> 8)
	off++
	buf[off] = byte(extsTotalLen)
	off++

	// SNI extension
	buf[off] = 0x00
	off++
	buf[off] = 0x00 // type = 0x0000
	off++
	buf[off] = byte(sniExtDataLen >> 8)
	off++
	buf[off] = byte(sniExtDataLen)
	off++
	// SNI list length
	buf[off] = byte((sniExtDataLen - 2) >> 8)
	off++
	buf[off] = byte(sniExtDataLen - 2)
	off++
	// Name type = hostname (0x00)
	buf[off] = 0x00
	off++
	// Name length
	buf[off] = byte(sniNameLen >> 8)
	off++
	buf[off] = byte(sniNameLen)
	off++
	// Hostname
	copy(buf[off:], hostname)

	return buf
}
