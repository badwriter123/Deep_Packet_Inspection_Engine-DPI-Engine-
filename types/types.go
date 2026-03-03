package types

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ConnectionState represents the state of a tracked connection.
type ConnectionState int

const (
	StateNew ConnectionState = iota
	StateEstablished
	StateClassified
	StateBlocked
	StateClosed
)

func (s ConnectionState) String() string {
	switch s {
	case StateNew:
		return "New"
	case StateEstablished:
		return "Established"
	case StateClassified:
		return "Classified"
	case StateBlocked:
		return "Blocked"
	case StateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// AppType represents a classified application type.
type AppType int

const (
	AppUnknown AppType = iota
	AppHTTP
	AppHTTPS
	AppDNS
	AppTLS
	AppQUIC
	AppGoogle
	AppFacebook
	AppYouTube
	AppTwitter
	AppInstagram
	AppNetflix
	AppAmazon
	AppMicrosoft
	AppApple
	AppWhatsApp
	AppTelegram
	AppTikTok
	AppSpotify
	AppZoom
	AppDiscord
	AppGitHub
	AppCloudflare
	AppTypeCount // sentinel for iteration
)

func (a AppType) String() string {
	switch a {
	case AppUnknown:
		return "Unknown"
	case AppHTTP:
		return "HTTP"
	case AppHTTPS:
		return "HTTPS"
	case AppDNS:
		return "DNS"
	case AppTLS:
		return "TLS"
	case AppQUIC:
		return "QUIC"
	case AppGoogle:
		return "Google"
	case AppFacebook:
		return "Facebook"
	case AppYouTube:
		return "YouTube"
	case AppTwitter:
		return "Twitter"
	case AppInstagram:
		return "Instagram"
	case AppNetflix:
		return "Netflix"
	case AppAmazon:
		return "Amazon"
	case AppMicrosoft:
		return "Microsoft"
	case AppApple:
		return "Apple"
	case AppWhatsApp:
		return "WhatsApp"
	case AppTelegram:
		return "Telegram"
	case AppTikTok:
		return "TikTok"
	case AppSpotify:
		return "Spotify"
	case AppZoom:
		return "Zoom"
	case AppDiscord:
		return "Discord"
	case AppGitHub:
		return "GitHub"
	case AppCloudflare:
		return "Cloudflare"
	default:
		return "Unknown"
	}
}

// AppTypeFromString parses an AppType from its string name.
func AppTypeFromString(s string) (AppType, bool) {
	lower := strings.ToLower(s)
	for i := AppType(0); i < AppTypeCount; i++ {
		if strings.ToLower(i.String()) == lower {
			return i, true
		}
	}
	return AppUnknown, false
}

// SNIToAppType maps a domain (SNI) to an application type using suffix matching.
func SNIToAppType(sni string) AppType {
	domain := strings.ToLower(sni)

	// Domain suffix to AppType mapping
	mappings := []struct {
		suffixes []string
		appType  AppType
	}{
		{[]string{"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be"}, AppYouTube},
		{[]string{"netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com"}, AppNetflix},
		{[]string{"tiktok.com", "tiktokv.com", "tiktokcdn.com", "musical.ly"}, AppTikTok},
		{[]string{"facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "facebook.net"}, AppFacebook},
		{[]string{"instagram.com", "cdninstagram.com"}, AppInstagram},
		{[]string{"twitter.com", "twimg.com", "t.co", "x.com"}, AppTwitter},
		{[]string{"whatsapp.com", "whatsapp.net"}, AppWhatsApp},
		{[]string{"telegram.org", "t.me", "telegram.me"}, AppTelegram},
		{[]string{"spotify.com", "scdn.co", "spotifycdn.com"}, AppSpotify},
		{[]string{"zoom.us", "zoom.com", "zoomgov.com"}, AppZoom},
		{[]string{"discord.com", "discord.gg", "discordapp.com", "discord.media"}, AppDiscord},
		{[]string{"github.com", "github.io", "githubusercontent.com", "githubassets.com"}, AppGitHub},
		{[]string{"cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com"}, AppCloudflare},
		{[]string{"google.com", "googleapis.com", "gstatic.com", "google.co", "goog"}, AppGoogle},
		{[]string{"microsoft.com", "microsoftonline.com", "msn.com", "live.com", "office.com", "office365.com", "azure.com", "windows.net", "bing.com", "skype.com"}, AppMicrosoft},
		{[]string{"apple.com", "icloud.com", "apple-dns.net", "mzstatic.com"}, AppApple},
		{[]string{"amazon.com", "amazonaws.com", "amazonvideo.com", "amazon.co", "cloudfront.net", "aws.amazon.com"}, AppAmazon},
	}

	for _, m := range mappings {
		for _, suffix := range m.suffixes {
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return m.appType
			}
		}
	}

	return AppUnknown
}

// FiveTuple represents a network 5-tuple for connection identification.
type FiveTuple struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8 // 6=TCP, 17=UDP
}

// Hash computes a deterministic hash using Boost-style hash combining.
func (ft FiveTuple) Hash() uint64 {
	var seed uint64

	// Boost-style hash combine for each field
	seed ^= uint64(ft.SrcIP) + 0x9e3779b9 + (seed << 6) + (seed >> 2)
	seed ^= uint64(ft.DstIP) + 0x9e3779b9 + (seed << 6) + (seed >> 2)
	seed ^= uint64(ft.SrcPort) + 0x9e3779b9 + (seed << 6) + (seed >> 2)
	seed ^= uint64(ft.DstPort) + 0x9e3779b9 + (seed << 6) + (seed >> 2)
	seed ^= uint64(ft.Protocol) + 0x9e3779b9 + (seed << 6) + (seed >> 2)

	return seed
}

// Reverse returns a new FiveTuple with src and dst swapped.
func (ft FiveTuple) Reverse() FiveTuple {
	return FiveTuple{
		SrcIP:    ft.DstIP,
		DstIP:    ft.SrcIP,
		SrcPort:  ft.DstPort,
		DstPort:  ft.SrcPort,
		Protocol: ft.Protocol,
	}
}

// String returns a human-readable representation.
func (ft FiveTuple) String() string {
	srcIP := make(net.IP, 4)
	dstIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(srcIP, ft.SrcIP)
	binary.BigEndian.PutUint32(dstIP, ft.DstIP)
	return fmt.Sprintf("%s:%d -> %s:%d (proto=%d)", srcIP, ft.SrcPort, dstIP, ft.DstPort, ft.Protocol)
}

// IPToUint32 converts a net.IP to uint32.
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Uint32ToIP converts a uint32 to net.IP.
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// PacketJob is the unit of work passed between goroutines via channels.
type PacketJob struct {
	PacketID      uint32
	Tuple         FiveTuple
	RawData       []byte // full raw packet bytes
	PayloadOffset int    // byte offset where application payload starts
	PayloadLength int    // bytes of application payload
	TCPFlags      uint8
	TsSec         uint32
	TsUsec        uint32
}

// Payload returns the application-layer payload slice.
func (p *PacketJob) Payload() []byte {
	if p.PayloadOffset < 0 || p.PayloadOffset > len(p.RawData) || p.PayloadLength <= 0 {
		return nil
	}
	end := p.PayloadOffset + p.PayloadLength
	if end > len(p.RawData) {
		return nil
	}
	return p.RawData[p.PayloadOffset:end]
}

// Connection represents per-flow state tracked inside each worker.
type Connection struct {
	Tuple      FiveTuple
	State      ConnectionState
	AppType    AppType
	SNI        string
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64
	FirstSeen  time.Time
	LastSeen   time.Time
	SynSeen    bool
	SynAckSeen bool
	FinSeen    bool
}

// TCP flag constants.
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagACK = 0x10
)

// Action represents the result of packet processing.
type Action int

const (
	ActionForward Action = iota
	ActionDrop
)

// ChannelBufferSize is the default buffered channel size.
const ChannelBufferSize = 10000

// MaxConnectionsPerWorker is the max connections before eviction.
const MaxConnectionsPerWorker = 65536

// ConnectionTimeout is the idle timeout for connections.
const ConnectionTimeout = 300 * time.Second
