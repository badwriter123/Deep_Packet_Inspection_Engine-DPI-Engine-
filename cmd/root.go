package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"dpi-engine/engine"
	"dpi-engine/rules"
	"dpi-engine/types"
)

// CLIOptions holds parsed command-line arguments.
type CLIOptions struct {
	InputFile    string
	OutputFile   string
	BlockIPs     []string
	BlockApps    []string
	BlockDomains []string
	BlockPorts   []uint16
	RulesFile    string
	NumWorkers   int
	Verbose      bool
}

// ParseArgs parses command-line arguments into CLIOptions.
func ParseArgs(args []string) (*CLIOptions, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: dpi_engine <input.pcap> <output.pcap> [options]")
	}

	opts := &CLIOptions{
		InputFile:  args[0],
		OutputFile: args[1],
		NumWorkers: 4, // default
	}

	i := 2
	for i < len(args) {
		switch args[i] {
		case "--block-ip":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--block-ip requires an argument")
			}
			i++
			opts.BlockIPs = append(opts.BlockIPs, args[i])
		case "--block-app":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--block-app requires an argument")
			}
			i++
			opts.BlockApps = append(opts.BlockApps, args[i])
		case "--block-domain":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--block-domain requires an argument")
			}
			i++
			opts.BlockDomains = append(opts.BlockDomains, args[i])
		case "--block-port":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--block-port requires an argument")
			}
			i++
			port, err := strconv.ParseUint(args[i], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", args[i])
			}
			opts.BlockPorts = append(opts.BlockPorts, uint16(port))
		case "--rules":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--rules requires an argument")
			}
			i++
			opts.RulesFile = args[i]
		case "--workers":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--workers requires an argument")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				return nil, fmt.Errorf("invalid worker count: %s", args[i])
			}
			opts.NumWorkers = n
		case "--verbose":
			opts.Verbose = true
		default:
			return nil, fmt.Errorf("unknown option: %s", args[i])
		}
		i++
	}

	return opts, nil
}

// Execute is the main entry point for the CLI.
func Execute() {
	opts, err := ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nUsage: dpi_engine <input.pcap> <output.pcap> [options]\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  --block-ip <ip>         Block all packets from this source IP\n")
		fmt.Fprintf(os.Stderr, "  --block-app <app>       Block by app name (e.g. YouTube, Netflix)\n")
		fmt.Fprintf(os.Stderr, "  --block-domain <domain> Block domain, supports wildcards (*.tiktok.com)\n")
		fmt.Fprintf(os.Stderr, "  --block-port <port>     Block destination port\n")
		fmt.Fprintf(os.Stderr, "  --rules <file>          Load rules from a file\n")
		fmt.Fprintf(os.Stderr, "  --workers <n>           Number of FP worker goroutines (default: 4)\n")
		fmt.Fprintf(os.Stderr, "  --verbose               Verbose output\n")
		os.Exit(1)
	}

	// Build rule manager
	rm := rules.NewRuleManager()

	// Load rules file first (if specified)
	if opts.RulesFile != "" {
		if err := rm.LoadRules(opts.RulesFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading rules: %v\n", err)
			os.Exit(1)
		}
		if opts.Verbose {
			fmt.Printf("[config] Loaded rules from %s\n", opts.RulesFile)
		}
	}

	// Apply CLI rules
	for _, ip := range opts.BlockIPs {
		if err := rm.AddBlockedIP(ip); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if opts.Verbose {
			fmt.Printf("[config] Blocking IP: %s\n", ip)
		}
	}

	for _, appName := range opts.BlockApps {
		app, ok := types.AppTypeFromString(appName)
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: unknown app type: %s\n", appName)
			fmt.Fprintf(os.Stderr, "Valid app types: HTTP, HTTPS, DNS, TLS, QUIC, Google, Facebook, YouTube, Twitter, Instagram, Netflix, Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare\n")
			os.Exit(1)
		}
		rm.AddBlockedApp(app)
		if opts.Verbose {
			fmt.Printf("[config] Blocking app: %s\n", appName)
		}
	}

	for _, domain := range opts.BlockDomains {
		rm.AddBlockedDomain(domain)
		if opts.Verbose {
			fmt.Printf("[config] Blocking domain: %s\n", domain)
		}
	}

	for _, port := range opts.BlockPorts {
		rm.AddBlockedPort(port)
		if opts.Verbose {
			fmt.Printf("[config] Blocking port: %d\n", port)
		}
	}

	// Print startup info
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  DPI Engine (Go)                            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Input:   %s\n", opts.InputFile)
	fmt.Printf("  Output:  %s\n", opts.OutputFile)
	fmt.Printf("  Workers: %d\n", opts.NumWorkers)
	if rm.HasRules() {
		fmt.Println("  Rules:   active")
	} else {
		fmt.Println("  Rules:   none (pass-through mode)")
	}
	fmt.Println(strings.Repeat("─", 62))

	// Create and run engine
	config := engine.Config{
		InputFile:   opts.InputFile,
		OutputFile:  opts.OutputFile,
		NumWorkers:  opts.NumWorkers,
		Verbose:     opts.Verbose,
		RuleManager: rm,
	}

	dpiEngine := engine.NewDPIEngine(config)
	if err := dpiEngine.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
