package rules

import (
	"os"
	"testing"

	"dpi-engine/types"
)

func TestShouldBlockIP(t *testing.T) {
	rm := NewRuleManager()
	rm.AddBlockedIP("192.168.1.1")

	ip := types.IPToUint32([]byte{192, 168, 1, 1})
	blocked, reason := rm.ShouldBlock(ip, 80, types.AppUnknown, "")
	if !blocked {
		t.Error("Expected IP to be blocked")
	}
	if reason == "" {
		t.Error("Expected a reason string")
	}

	// Non-blocked IP
	ip2 := types.IPToUint32([]byte{10, 0, 0, 1})
	blocked2, _ := rm.ShouldBlock(ip2, 80, types.AppUnknown, "")
	if blocked2 {
		t.Error("IP 10.0.0.1 should not be blocked")
	}
}

func TestShouldBlockPort(t *testing.T) {
	rm := NewRuleManager()
	rm.AddBlockedPort(6881)

	blocked, _ := rm.ShouldBlock(0, 6881, types.AppUnknown, "")
	if !blocked {
		t.Error("Expected port 6881 to be blocked")
	}

	blocked2, _ := rm.ShouldBlock(0, 80, types.AppUnknown, "")
	if blocked2 {
		t.Error("Port 80 should not be blocked")
	}
}

func TestShouldBlockApp(t *testing.T) {
	rm := NewRuleManager()
	rm.AddBlockedApp(types.AppYouTube)

	blocked, _ := rm.ShouldBlock(0, 443, types.AppYouTube, "youtube.com")
	if !blocked {
		t.Error("Expected YouTube to be blocked")
	}

	blocked2, _ := rm.ShouldBlock(0, 443, types.AppNetflix, "netflix.com")
	if blocked2 {
		t.Error("Netflix should not be blocked")
	}
}

func TestShouldBlockExactDomain(t *testing.T) {
	rm := NewRuleManager()
	rm.AddBlockedDomain("bad.example.com")

	blocked, _ := rm.ShouldBlock(0, 443, types.AppUnknown, "bad.example.com")
	if !blocked {
		t.Error("Expected exact domain to be blocked")
	}

	blocked2, _ := rm.ShouldBlock(0, 443, types.AppUnknown, "good.example.com")
	if blocked2 {
		t.Error("Different domain should not be blocked")
	}
}

func TestShouldBlockWildcardDomain(t *testing.T) {
	rm := NewRuleManager()
	rm.AddBlockedDomain("*.tiktok.com")

	blocked, _ := rm.ShouldBlock(0, 443, types.AppUnknown, "www.tiktok.com")
	if !blocked {
		t.Error("Expected www.tiktok.com to match *.tiktok.com")
	}

	blocked2, _ := rm.ShouldBlock(0, 443, types.AppUnknown, "tiktok.com")
	if !blocked2 {
		t.Error("Expected tiktok.com to match *.tiktok.com")
	}

	blocked3, _ := rm.ShouldBlock(0, 443, types.AppUnknown, "sub.www.tiktok.com")
	if !blocked3 {
		t.Error("Expected sub.www.tiktok.com to match *.tiktok.com")
	}

	blocked4, _ := rm.ShouldBlock(0, 443, types.AppUnknown, "nottiktok.com")
	if blocked4 {
		t.Error("nottiktok.com should NOT match *.tiktok.com")
	}
}

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "notexample.com", false},
		{"*.example.com", "other.com", false},
		{"*.EXAMPLE.COM", "sub.example.com", true},   // case insensitive
		{"*.example.com", "SUB.EXAMPLE.COM", true},    // case insensitive
		{"example.com", "sub.example.com", false},     // not a wildcard pattern
	}

	for _, tt := range tests {
		got := WildcardMatch(tt.pattern, tt.domain)
		if got != tt.want {
			t.Errorf("WildcardMatch(%q, %q) = %v, want %v", tt.pattern, tt.domain, got, tt.want)
		}
	}
}

func TestShouldBlockPriority(t *testing.T) {
	// IP match should take priority
	rm := NewRuleManager()
	rm.AddBlockedIP("1.2.3.4")
	rm.AddBlockedPort(443)

	ip := types.IPToUint32([]byte{1, 2, 3, 4})
	blocked, reason := rm.ShouldBlock(ip, 443, types.AppUnknown, "")
	if !blocked {
		t.Error("Expected blocked")
	}
	if reason == "" {
		t.Error("Expected reason")
	}
	// Should match on IP first
	if reason != "blocked IP: 1.2.3.4" {
		t.Errorf("Expected IP block reason, got: %s", reason)
	}
}

func TestLoadSaveRules(t *testing.T) {
	tmpFile := t.TempDir() + "/test_rules.txt"

	// Create rules
	rm := NewRuleManager()
	rm.AddBlockedIP("10.0.0.1")
	rm.AddBlockedApp(types.AppYouTube)
	rm.AddBlockedDomain("*.tiktok.com")
	rm.AddBlockedPort(6881)

	// Save
	if err := rm.SaveRules(tmpFile); err != nil {
		t.Fatalf("SaveRules failed: %v", err)
	}

	// Load into fresh manager
	rm2 := NewRuleManager()
	if err := rm2.LoadRules(tmpFile); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	// Verify IP
	ip := types.IPToUint32([]byte{10, 0, 0, 1})
	blocked, _ := rm2.ShouldBlock(ip, 0, types.AppUnknown, "")
	if !blocked {
		t.Error("Loaded rules should block IP 10.0.0.1")
	}

	// Verify App
	blocked2, _ := rm2.ShouldBlock(0, 0, types.AppYouTube, "")
	if !blocked2 {
		t.Error("Loaded rules should block YouTube")
	}

	// Verify Domain
	blocked3, _ := rm2.ShouldBlock(0, 0, types.AppUnknown, "www.tiktok.com")
	if !blocked3 {
		t.Error("Loaded rules should block www.tiktok.com")
	}

	// Verify Port
	blocked4, _ := rm2.ShouldBlock(0, 6881, types.AppUnknown, "")
	if !blocked4 {
		t.Error("Loaded rules should block port 6881")
	}

	// Cleanup
	os.Remove(tmpFile)
}

func TestHasRules(t *testing.T) {
	rm := NewRuleManager()
	if rm.HasRules() {
		t.Error("Empty manager should have no rules")
	}

	rm.AddBlockedPort(80)
	if !rm.HasRules() {
		t.Error("Manager with port rule should have rules")
	}
}
