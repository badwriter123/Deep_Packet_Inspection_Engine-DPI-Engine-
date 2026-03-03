package rules

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"dpi-engine/types"
)

// RuleManager manages blocking rules. It is thread-safe for concurrent reads.
type RuleManager struct {
	ipMu           sync.RWMutex
	blockedIPs     map[uint32]bool

	portMu         sync.RWMutex
	blockedPorts   map[uint16]bool

	appMu          sync.RWMutex
	blockedApps    map[types.AppType]bool

	domainMu       sync.RWMutex
	blockedDomains map[string]bool
	domainPatterns []string
}

// NewRuleManager creates a new RuleManager with empty rule sets.
func NewRuleManager() *RuleManager {
	return &RuleManager{
		blockedIPs:     make(map[uint32]bool),
		blockedPorts:   make(map[uint16]bool),
		blockedApps:    make(map[types.AppType]bool),
		blockedDomains: make(map[string]bool),
	}
}

// AddBlockedIP adds a source IP to the block list.
func (rm *RuleManager) AddBlockedIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}
	ipUint := types.IPToUint32(ip)
	rm.ipMu.Lock()
	rm.blockedIPs[ipUint] = true
	rm.ipMu.Unlock()
	return nil
}

// AddBlockedPort adds a destination port to the block list.
func (rm *RuleManager) AddBlockedPort(port uint16) {
	rm.portMu.Lock()
	rm.blockedPorts[port] = true
	rm.portMu.Unlock()
}

// AddBlockedApp adds an application type to the block list.
func (rm *RuleManager) AddBlockedApp(app types.AppType) {
	rm.appMu.Lock()
	rm.blockedApps[app] = true
	rm.appMu.Unlock()
}

// AddBlockedDomain adds a domain or wildcard pattern to the block list.
func (rm *RuleManager) AddBlockedDomain(domain string) {
	rm.domainMu.Lock()
	defer rm.domainMu.Unlock()

	domain = strings.ToLower(domain)
	if strings.HasPrefix(domain, "*.") {
		rm.domainPatterns = append(rm.domainPatterns, domain)
	} else {
		rm.blockedDomains[domain] = true
	}
}

// ShouldBlock checks if a packet should be blocked based on loaded rules.
// Returns whether blocked and the reason.
func (rm *RuleManager) ShouldBlock(srcIP uint32, dstPort uint16, app types.AppType, domain string) (bool, string) {
	// Check IP
	rm.ipMu.RLock()
	if rm.blockedIPs[srcIP] {
		rm.ipMu.RUnlock()
		return true, fmt.Sprintf("blocked IP: %s", types.Uint32ToIP(srcIP))
	}
	rm.ipMu.RUnlock()

	// Check port
	rm.portMu.RLock()
	if rm.blockedPorts[dstPort] {
		rm.portMu.RUnlock()
		return true, fmt.Sprintf("blocked port: %d", dstPort)
	}
	rm.portMu.RUnlock()

	// Check app
	rm.appMu.RLock()
	if app != types.AppUnknown && rm.blockedApps[app] {
		rm.appMu.RUnlock()
		return true, fmt.Sprintf("blocked app: %s", app)
	}
	rm.appMu.RUnlock()

	// Check domain
	if domain != "" {
		rm.domainMu.RLock()
		defer rm.domainMu.RUnlock()

		lowerDomain := strings.ToLower(domain)

		// Exact match
		if rm.blockedDomains[lowerDomain] {
			return true, fmt.Sprintf("blocked domain: %s", domain)
		}

		// Wildcard match
		for _, pattern := range rm.domainPatterns {
			if WildcardMatch(pattern, lowerDomain) {
				return true, fmt.Sprintf("blocked domain pattern: %s", pattern)
			}
		}
	}

	return false, ""
}

// WildcardMatch checks if a domain matches a wildcard pattern.
// Pattern must start with "*." — e.g., "*.example.com" matches
// "sub.example.com" and "example.com" but NOT "notexample.com".
func WildcardMatch(pattern, domain string) bool {
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	// Strip "*." to get the base domain
	suffix := pattern[2:] // e.g., "example.com"

	// Match if domain equals the bare domain
	if domain == suffix {
		return true
	}

	// Match if domain ends with ".suffix"
	if strings.HasSuffix(domain, "."+suffix) {
		return true
	}

	return false
}

// HasRules returns true if any rules are configured.
func (rm *RuleManager) HasRules() bool {
	rm.ipMu.RLock()
	ipCount := len(rm.blockedIPs)
	rm.ipMu.RUnlock()

	rm.portMu.RLock()
	portCount := len(rm.blockedPorts)
	rm.portMu.RUnlock()

	rm.appMu.RLock()
	appCount := len(rm.blockedApps)
	rm.appMu.RUnlock()

	rm.domainMu.RLock()
	domainCount := len(rm.blockedDomains) + len(rm.domainPatterns)
	rm.domainMu.RUnlock()

	return ipCount+portCount+appCount+domainCount > 0
}

// LoadRules loads rules from a file in the specified format.
func (rm *RuleManager) LoadRules(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open rules file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var section string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}

		switch section {
		case "[BLOCKED_IPS]":
			if err := rm.AddBlockedIP(line); err != nil {
				return fmt.Errorf("invalid IP in rules file: %s", line)
			}
		case "[BLOCKED_APPS]":
			app, ok := types.AppTypeFromString(line)
			if !ok {
				return fmt.Errorf("unknown app type in rules file: %s", line)
			}
			rm.AddBlockedApp(app)
		case "[BLOCKED_DOMAINS]":
			rm.AddBlockedDomain(line)
		case "[BLOCKED_PORTS]":
			port, err := strconv.ParseUint(line, 10, 16)
			if err != nil {
				return fmt.Errorf("invalid port in rules file: %s", line)
			}
			rm.AddBlockedPort(uint16(port))
		}
	}

	return scanner.Err()
}

// SaveRules saves the current rules to a file.
func (rm *RuleManager) SaveRules(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create rules file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	// Blocked IPs
	rm.ipMu.RLock()
	if len(rm.blockedIPs) > 0 {
		fmt.Fprintln(w, "[BLOCKED_IPS]")
		for ip := range rm.blockedIPs {
			fmt.Fprintln(w, types.Uint32ToIP(ip))
		}
		fmt.Fprintln(w)
	}
	rm.ipMu.RUnlock()

	// Blocked Apps
	rm.appMu.RLock()
	if len(rm.blockedApps) > 0 {
		fmt.Fprintln(w, "[BLOCKED_APPS]")
		for app := range rm.blockedApps {
			fmt.Fprintln(w, app.String())
		}
		fmt.Fprintln(w)
	}
	rm.appMu.RUnlock()

	// Blocked Domains
	rm.domainMu.RLock()
	if len(rm.blockedDomains) > 0 || len(rm.domainPatterns) > 0 {
		fmt.Fprintln(w, "[BLOCKED_DOMAINS]")
		for domain := range rm.blockedDomains {
			fmt.Fprintln(w, domain)
		}
		for _, pattern := range rm.domainPatterns {
			fmt.Fprintln(w, pattern)
		}
		fmt.Fprintln(w)
	}
	rm.domainMu.RUnlock()

	// Blocked Ports
	rm.portMu.RLock()
	if len(rm.blockedPorts) > 0 {
		fmt.Fprintln(w, "[BLOCKED_PORTS]")
		for port := range rm.blockedPorts {
			fmt.Fprintf(w, "%d\n", port)
		}
		fmt.Fprintln(w)
	}
	rm.portMu.RUnlock()

	return w.Flush()
}
