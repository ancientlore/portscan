/*
portscan is a simple port scanner that tries to open a range of TCP connections to the given host.
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	host     = flag.String("host", "localhost", "Host or IP to scan")
	timeout  = flag.Duration("timeout", 1*time.Second, "Timeout per port")
	ports    = flag.String("range", "80,443", "Port ranges e.g. 80,443,200-1000,8000-9000")
	threads  = flag.Int("threads", 100, "Threads to use")
	showErrs = flag.Bool("verbose", false, "Show errors for failed ports")
)

const (
	minPort = 1
	maxPort = 65535
)

// PortStatus represents the outcome of scanning a single port.
type PortStatus string

const (
	StatusOpen              PortStatus = "open"
	StatusClosed            PortStatus = "closed"
	StatusFiltered          PortStatus = "filtered"
	StatusResourceExhausted PortStatus = "resource_exhausted"
	StatusCanceled          PortStatus = "canceled"
	StatusError             PortStatus = "error"
)

// ScanResult holds the structured result of a single port scan.
type ScanResult struct {
	Port    int
	Status  PortStatus
	Latency time.Duration
	Err     error
}

// Open reports whether the scanned port accepted a TCP connection.
func (r ScanResult) Open() bool {
	return r.Status == StatusOpen
}

func (r ScanResult) String() string {
	if r.Open() {
		return fmt.Sprintf("%d: OK (%s)", r.Port, r.Latency.Round(time.Microsecond))
	}
	if r.Status == StatusResourceExhausted {
		return fmt.Sprintf("%d: [%s] %v (hint: lower -threads or increase ulimit -n)", r.Port, r.Status, r.Err)
	}
	if r.Err != nil {
		return fmt.Sprintf("%d: [%s] %v", r.Port, r.Status, r.Err)
	}
	return fmt.Sprintf("%d: [%s]", r.Port, r.Status)
}

// classifyError inspects a dial error and categorizes it into a PortStatus.
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
// If the input is already an IP literal, it is returned directly without brackets.
func resolveHost(ctx context.Context, target string, timeout time.Duration) (string, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", errors.New("host cannot be empty")
	}

	// Strip surrounding brackets if an IPv6 literal like "[::1]" was passed.
	unbracketed := strings.TrimPrefix(strings.TrimSuffix(trimmed, "]"), "[")
	if ip := net.ParseIP(unbracketed); ip != nil {
		return ip.String(), nil
	}

	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

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

func emitPorts(ctx context.Context, portList []int) <-chan int {
	c := make(chan int)
	go func() {
		defer close(c)
		for _, port := range portList {
			select {
			case c <- port:
			case <-ctx.Done():
				return
			}
		}
	}()
	return c
}

func scanPorts(ctx context.Context, targetAddr string, portChan <-chan int, numWorkers int, dialTimeout time.Duration) <-chan ScanResult {
	out := make(chan ScanResult)
	if numWorkers <= 0 {
		numWorkers = 1
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
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
					res := scanPort(ctx, dialer, targetAddr, port)
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

func scanPort(ctx context.Context, dialer *net.Dialer, targetHost string, port int) ScanResult {
	addr := net.JoinHostPort(targetHost, strconv.Itoa(port))
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	latency := time.Since(start)
	if err != nil {
		return ScanResult{
			Port:    port,
			Status:  classifyError(err),
			Latency: latency,
			Err:     err,
		}
	}
	_ = conn.Close()
	return ScanResult{
		Port:    port,
		Status:  StatusOpen,
		Latency: latency,
	}
}

func validateFlags() error {
	if strings.TrimSpace(*host) == "" {
		return errors.New("-host cannot be empty")
	}
	if *threads <= 0 {
		return fmt.Errorf("-threads must be greater than 0 (got %d)", *threads)
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout must be greater than 0 (got %s)", *timeout)
	}
	return nil
}

func main() {
	flag.Parse()

	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing -range: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	resolvedIP, err := resolveHost(ctx, *host, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	workers := *threads
	if workers > len(portList) {
		workers = len(portList)
	}

	hostDisplay := *host
	if resolvedIP != *host {
		hostDisplay = fmt.Sprintf("%s (%s)", *host, resolvedIP)
	}
	fmt.Printf("Scanning %s (%d ports) timeout %s threads %d\n", hostDisplay, len(portList), (*timeout).String(), workers)

	portChan := emitPorts(ctx, portList)
	results := scanPorts(ctx, resolvedIP, portChan, workers, *timeout)

	warnedFDLimit := false
	for res := range results {
		if res.Status == StatusResourceExhausted && !warnedFDLimit {
			fmt.Fprintf(os.Stderr, "Warning: file descriptor limit reached (%v); try lowering -threads or raising ulimit -n\n", res.Err)
			warnedFDLimit = true
		}
		if *showErrs || res.Open() {
			fmt.Println(res)
		}
	}
}

