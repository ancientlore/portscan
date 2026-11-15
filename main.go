/*
portscan is a simple port scanner that tries to open a range of TCP or UDP connections to the given host.
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	host      = flag.String("host", "localhost", "Host or IP to scan")
	ipv4Only  = flag.Bool("4", false, "Force IPv4 resolution and scanning")
	ipv6Only  = flag.Bool("6", false, "Force IPv6 resolution and scanning")
	timeout   = flag.Duration("timeout", 1*time.Second, "Timeout per port")
	ports     = flag.String("range", "80,443", "Port ranges e.g. 80,443,200-1000,8000-9000")
	topN      = flag.Int("top", 0, "Scan the top N most common ports (1-100)")
	allPorts  = flag.Bool("all", false, "Scan all ports (1-65535)")
	udpMode   = flag.Bool("udp", false, "Scan UDP ports instead of TCP")
	banner    = flag.Bool("banner", false, "Grab service banners on open ports")
	rateLimit = flag.Int("rate", 0, "Max port probes per second (0 for unlimited)")
	shuffle   = flag.Bool("shuffle", false, "Randomize port scan order")
	threads   = flag.Int("threads", 100, "Threads to use")
	showErrs  = flag.Bool("verbose", false, "Show errors for failed ports")
	jsonOut   = flag.Bool("json", false, "Output results as JSON")
	csvOut    = flag.Bool("csv", false, "Output results as CSV")
	noTUI     = flag.Bool("no-tui", false, "Disable live interactive TUI")
)

const (
	minPort = 1
	maxPort = 65535
)

// PortStatus represents the outcome of scanning a single port.
type PortStatus string

const (
	StatusOpen              PortStatus = "open"
	StatusOpenFiltered      PortStatus = "open|filtered"
	StatusClosed            PortStatus = "closed"
	StatusFiltered          PortStatus = "filtered"
	StatusResourceExhausted PortStatus = "resource_exhausted"
	StatusCanceled          PortStatus = "canceled"
	StatusError             PortStatus = "error"
)

// ScanConfig configures how ports are scanned.
type ScanConfig struct {
	TargetAddr string
	HostHeader string
	Protocol   string
	IPVersion  int // 0 (any), 4 (IPv4 only), or 6 (IPv6 only)
	Workers    int
	Timeout    time.Duration
	GrabBanner bool
}

func dialNetwork(proto string, ipVersion int) string {
	switch ipVersion {
	case 4:
		return proto + "4"
	case 6:
		return proto + "6"
	default:
		return proto
	}
}

// ScanResult holds the structured result of a single port scan.
type ScanResult struct {
	Port     int
	Protocol string
	Service  string
	Banner   string
	Status   PortStatus
	Latency  time.Duration
	Err      error
}

// Open reports whether the scanned port is confirmed open.
func (r ScanResult) Open() bool {
	return r.Status == StatusOpen
}

func (r ScanResult) String() string {
	proto := r.Protocol
	if proto == "" {
		proto = "tcp"
	}
	svc := ""
	if r.Service != "" {
		svc = " " + r.Service
	}
	if r.Open() {
		if r.Banner != "" {
			return fmt.Sprintf("%d/%s%s: OK (%s) [%s]", r.Port, proto, svc, r.Latency.Round(time.Microsecond), r.Banner)
		}
		return fmt.Sprintf("%d/%s%s: OK (%s)", r.Port, proto, svc, r.Latency.Round(time.Microsecond))
	}
	if r.Status == StatusOpenFiltered {
		return fmt.Sprintf("%d/%s%s: [%s] no UDP response within %s", r.Port, proto, svc, r.Status, r.Latency.Round(time.Millisecond))
	}
	if r.Status == StatusResourceExhausted {
		return fmt.Sprintf("%d/%s%s: [%s] %v (hint: lower -threads or increase ulimit -n)", r.Port, proto, svc, r.Status, r.Err)
	}
	if r.Err != nil {
		return fmt.Sprintf("%d/%s%s: [%s] %v", r.Port, proto, svc, r.Status, r.Err)
	}
	return fmt.Sprintf("%d/%s%s: [%s]", r.Port, proto, svc, r.Status)
}

// classifyError inspects a dial/read error and categorizes it into a PortStatus.
func classifyError(err error) PortStatus {
	if err == nil {
		return StatusOpen
	}
	if errors.Is(err, context.Canceled) {
		return StatusCanceled
	}
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return StatusResourceExhausted
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StatusClosed
	}
	var netErr net.Error
	if (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
		return StatusFiltered
	}
	return StatusError
}

// resolvePortSelection determines the final port list from presets (-all, -top) or -range,
// and optionally shuffles the resulting slice.
func resolvePortSelection(rangeSpec string, top int, all bool, randomize bool) ([]int, error) {
	var portList []int
	var err error

	switch {
	case all && top > 0:
		return nil, errors.New("cannot specify both -all and -top")
	case all:
		portList = make([]int, maxPort)
		for i := range portList {
			portList[i] = i + 1
		}
	case top > 0:
		if top > len(topPorts) {
			return nil, fmt.Errorf("-top must be between 1 and %d (got %d)", len(topPorts), top)
		}
		portList = append([]int(nil), topPorts[:top]...)
	default:
		portList, err = parsePorts(rangeSpec)
		if err != nil {
			return nil, err
		}
	}

	if randomize {
		rand.Shuffle(len(portList), func(i, j int) {
			portList[i], portList[j] = portList[j], portList[i]
		})
	}
	return portList, nil
}

// parsePorts parses, validates, and deduplicates a comma-separated list of ports and port ranges.
func parsePorts(r string) ([]int, error) {
	if strings.TrimSpace(r) == "" {
		return nil, errors.New("port range cannot be empty")
	}

	var result []int
	seen := make(map[int]struct{})

	blocks := strings.Split(r, ",")
	for _, rawBlock := range blocks {
		block := strings.TrimSpace(rawBlock)
		if block == "" {
			continue
		}

		rg := strings.Split(block, "-")
		if len(rg) != 1 && len(rg) != 2 {
			return nil, fmt.Errorf("cannot interpret range %q", block)
		}

		r1, err := strconv.Atoi(strings.TrimSpace(rg[0]))
		if err != nil {
			return nil, fmt.Errorf("cannot interpret range %q: %w", block, err)
		}

		r2 := r1
		if len(rg) == 2 {
			r2, err = strconv.Atoi(strings.TrimSpace(rg[1]))
			if err != nil {
				return nil, fmt.Errorf("cannot interpret range %q: %w", block, err)
			}
		}

		if r1 < minPort || r1 > maxPort || r2 < minPort || r2 > maxPort {
			return nil, fmt.Errorf("port out of valid range (%d-%d) in %q", minPort, maxPort, block)
		}
		if r1 > r2 {
			return nil, fmt.Errorf("inverted port range %d-%d in %q", r1, r2, block)
		}

		for port := r1; port <= r2; port++ {
			if _, exists := seen[port]; !exists {
				seen[port] = struct{}{}
				result = append(result, port)
			}
		}
	}

	if len(result) == 0 {
		return nil, errors.New("no valid ports specified")
	}

	return result, nil
}

// resolveHost resolves a hostname once to avoid redundant DNS lookups per port.
// ipVersion may be 0 (default: prefer IPv4, fallback to IPv6), 4 (IPv4 only), or 6 (IPv6 only).
// If the input is already an IP literal, it is validated against ipVersion and returned without brackets.
func resolveHost(ctx context.Context, target string, timeout time.Duration, ipVersion int) (string, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", errors.New("host cannot be empty")
	}
	if ipVersion != 0 && ipVersion != 4 && ipVersion != 6 {
		return "", fmt.Errorf("invalid IP version %d", ipVersion)
	}

	// Strip surrounding brackets if an IPv6 literal like "[::1]" was passed.
	unbracketed := strings.TrimPrefix(strings.TrimSuffix(trimmed, "]"), "[")
	if ip := net.ParseIP(unbracketed); ip != nil {
		isV4 := ip.To4() != nil
		if ipVersion == 4 && !isV4 {
			return "", fmt.Errorf("host %q is an IPv6 address, but -4 was specified", trimmed)
		}
		if ipVersion == 6 && isV4 {
			return "", fmt.Errorf("host %q is an IPv4 address, but -6 was specified", trimmed)
		}
		return ip.String(), nil
	}

	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch ipVersion {
	case 4:
		ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip4", trimmed)
		if err != nil {
			return "", fmt.Errorf("failed to resolve IPv4 address for host %q: %w", trimmed, err)
		}
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				return ipv4.String(), nil
			}
		}
		return "", fmt.Errorf("no IPv4 addresses found for host %q", trimmed)

	case 6:
		ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip6", trimmed)
		if err != nil {
			if strings.EqualFold(trimmed, "localhost") {
				return "::1", nil
			}
			return "", fmt.Errorf("failed to resolve IPv6 address for host %q: %w", trimmed, err)
		}
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() != nil {
				return ip.String(), nil
			}
		}
		if strings.EqualFold(trimmed, "localhost") {
			return "::1", nil
		}
		return "", fmt.Errorf("no IPv6 addresses found for host %q", trimmed)

	default:
		addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, trimmed)
		if err != nil {
			return "", fmt.Errorf("failed to resolve host %q: %w", trimmed, err)
		}
		if len(addrs) == 0 {
			return "", fmt.Errorf("no IP addresses found for host %q", trimmed)
		}

		// Prefer IPv4 if available, otherwise take the first resolved address.
		for _, addr := range addrs {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				return ipv4.String(), nil
			}
		}
		return addrs[0].IP.String(), nil
	}
}

// emitPorts feeds ports to workers, applying an optional rate limit (ports per second).
func emitPorts(ctx context.Context, portList []int, maxPerSec int) <-chan int {
	c := make(chan int)
	go func() {
		defer close(c)

		var ticker *time.Ticker
		if maxPerSec > 0 {
			interval := time.Second / time.Duration(maxPerSec)
			if interval <= 0 {
				interval = time.Nanosecond
			}
			ticker = time.NewTicker(interval)
			defer ticker.Stop()
		}

		for i, port := range portList {
			if ticker != nil && i > 0 {
				select {
				case <-ticker.C:
				case <-ctx.Done():
					return
				}
			}
			select {
			case c <- port:
			case <-ctx.Done():
				return
			}
		}
	}()
	return c
}

func scanPorts(ctx context.Context, cfg ScanConfig, portChan <-chan int) <-chan ScanResult {
	out := make(chan ScanResult)
	numWorkers := cfg.Workers
	if numWorkers <= 0 {
		numWorkers = 1
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "tcp"
	}

	dialer := &net.Dialer{Timeout: cfg.Timeout}
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case port, ok := <-portChan:
					if !ok {
						return
					}
					var res ScanResult
					if cfg.Protocol == "udp" {
						res = scanUDPPort(ctx, dialer, cfg, port)
					} else {
						res = scanTCPPort(ctx, dialer, cfg, port)
					}
					select {
					case out <- res:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func scanTCPPort(ctx context.Context, dialer *net.Dialer, cfg ScanConfig, port int) ScanResult {
	addr := net.JoinHostPort(cfg.TargetAddr, strconv.Itoa(port))
	svc := lookupService("tcp", port)
	network := dialNetwork("tcp", cfg.IPVersion)
	start := time.Now()
	conn, err := dialer.DialContext(ctx, network, addr)
	latency := time.Since(start)
	if err != nil {
		return ScanResult{
			Port:     port,
			Protocol: "tcp",
			Service:  svc,
			Status:   classifyError(err),
			Latency:  latency,
			Err:      err,
		}
	}
	defer conn.Close()

	var bannerText string
	if cfg.GrabBanner {
		hostHdr := cfg.HostHeader
		if hostHdr == "" {
			hostHdr = cfg.TargetAddr
		}
		bannerText = grabTCPBanner(ctx, conn, hostHdr, port, cfg.Timeout)
	}

	return ScanResult{
		Port:     port,
		Protocol: "tcp",
		Service:  svc,
		Banner:   bannerText,
		Status:   StatusOpen,
		Latency:  latency,
	}
}

func validateFlags() error {
	if strings.TrimSpace(*host) == "" {
		return errors.New("-host cannot be empty")
	}
	if *ipv4Only && *ipv6Only {
		return errors.New("cannot specify both -4 and -6")
	}
	if *threads <= 0 {
		return fmt.Errorf("-threads must be greater than 0 (got %d)", *threads)
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout must be greater than 0 (got %s)", *timeout)
	}
	if *topN < 0 || *topN > len(topPorts) {
		return fmt.Errorf("-top must be between 1 and %d (got %d)", len(topPorts), *topN)
	}
	if *rateLimit < 0 {
		return fmt.Errorf("-rate cannot be negative (got %d)", *rateLimit)
	}
	if *jsonOut && *csvOut {
		return errors.New("cannot specify both -json and -csv")
	}
	return nil
}

func selectedIPVersion(v4, v6 bool) int {
	if v4 {
		return 4
	}
	if v6 {
		return 6
	}
	return 0
}

func main() {
	flag.Parse()

	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	portList, err := resolvePortSelection(*ports, *topN, *allPorts, *shuffle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error selecting ports: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()

	ipVer := selectedIPVersion(*ipv4Only, *ipv6Only)
	resolvedIP, err := resolveHost(scanCtx, *host, *timeout, ipVer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	workers := *threads
	if workers > len(portList) {
		workers = len(portList)
	}

	proto := "tcp"
	if *udpMode {
		proto = "udp"
	}

	cfg := ScanConfig{
		TargetAddr: resolvedIP,
		HostHeader: *host,
		Protocol:   proto,
		IPVersion:  ipVer,
		Workers:    workers,
		Timeout:    *timeout,
		GrabBanner: *banner,
	}

	portChan := emitPorts(scanCtx, portList, *rateLimit)
	results := scanPorts(scanCtx, cfg, portChan)

	if isStdoutTTY() && !*noTUI && !*jsonOut && !*csvOut {
		if err := runInteractiveTUI(scanCtx, cancelScan, cfg, len(portList), *showErrs, results); err != nil {
			fmt.Fprintf(os.Stderr, "Error running UI: %v\n", err)
			os.Exit(1)
		}
		return
	}

	summary, displayed := collectScanHeadless(cfg, len(portList), *showErrs, results)
	if scanCtx.Err() != nil {
		summary.Canceled = true
	}

	switch {
	case *jsonOut:
		if err := writeJSONReport(os.Stdout, summary, displayed); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}
	case *csvOut:
		if err := writeCSVReport(os.Stdout, displayed); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
			os.Exit(1)
		}
	default:
		printFinalScrollbackReport(os.Stdout, summary, cfg, displayed, *showErrs)
	}
}
