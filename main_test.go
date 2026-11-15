package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{
			name:  "single port",
			input: "80",
			want:  []int{80},
		},
		{
			name:  "multiple ports and ranges with spaces and duplicates",
			input: " 80, 443, 80-82 , 81 ",
			want:  []int{80, 443, 81, 82},
		},
		{
			name:    "empty string",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "port zero",
			input:   "0",
			wantErr: true,
		},
		{
			name:    "port above max",
			input:   "65536",
			wantErr: true,
		},
		{
			name:    "inverted range",
			input:   "1000-200",
			wantErr: true,
		},
		{
			name:    "malformed range",
			input:   "80-90-100",
			wantErr: true,
		},
		{
			name:    "non-numeric port",
			input:   "http",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePorts(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parsePorts(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parsePorts(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestResolvePortSelection(t *testing.T) {
	seen := make(map[int]bool, len(topPorts))
	for i, p := range topPorts {
		if p < minPort || p > maxPort {
			t.Errorf("topPorts[%d] = %d out of valid range", i, p)
		}
		if seen[p] {
			t.Errorf("duplicate port %d in topPorts at index %d", p, i)
		}
		seen[p] = true
		if lookupService("tcp", p) == "" {
			t.Errorf("topPorts[%d] = %d is missing an entry in tcpServices", i, p)
		}
	}

	ports, err := resolvePortSelection("80,443", 5, false, false)
	if err != nil {
		t.Fatalf("resolvePortSelection(-top 5) unexpected error: %v", err)
	}
	if len(ports) != 5 || !reflect.DeepEqual(ports, topPorts[:5]) {
		t.Errorf("got %v, want %v", ports, topPorts[:5])
	}

	all, err := resolvePortSelection("80,443", 0, true, false)
	if err != nil {
		t.Fatalf("resolvePortSelection(-all) unexpected error: %v", err)
	}
	if len(all) != 65535 || all[0] != 1 || all[len(all)-1] != 65535 {
		t.Errorf("unexpected -all slice length=%d", len(all))
	}

	if _, err := resolvePortSelection("80", 10, true, false); err == nil {
		t.Error("expected error when both -all and -top are set")
	}

	shuffled, err := resolvePortSelection("1-50", 0, false, true)
	if err != nil || len(shuffled) != 50 {
		t.Fatalf("resolvePortSelection(shuffle) = len %d, err %v", len(shuffled), err)
	}
}

func TestResolveHost(t *testing.T) {
	ctx := context.Background()

	ip4, err := resolveHost(ctx, "127.0.0.1", time.Second, 0)
	if err != nil || ip4 != "127.0.0.1" {
		t.Fatalf("resolveHost(127.0.0.1, 0) = %q, %v", ip4, err)
	}

	ip6, err := resolveHost(ctx, "::1", time.Second, 0)
	if err != nil || ip6 != "::1" {
		t.Fatalf("resolveHost(::1, 0) = %q, %v", ip6, err)
	}

	ip6Bracketed, err := resolveHost(ctx, "[::1]", time.Second, 6)
	if err != nil || ip6Bracketed != "::1" {
		t.Fatalf("resolveHost([::1], 6) = %q, %v", ip6Bracketed, err)
	}

	// Forcing -4 on an IPv6 literal must fail
	if _, err := resolveHost(ctx, "::1", time.Second, 4); err == nil {
		t.Fatal("expected error for IPv6 literal with ipVersion=4")
	}

	// Forcing -6 on an IPv4 literal must fail
	if _, err := resolveHost(ctx, "127.0.0.1", time.Second, 6); err == nil {
		t.Fatal("expected error for IPv4 literal with ipVersion=6")
	}

	// Resolving localhost with -4 and -6
	local4, err := resolveHost(ctx, "localhost", time.Second, 4)
	if err != nil || local4 != "127.0.0.1" {
		t.Fatalf("resolveHost(localhost, 4) = %q, %v", local4, err)
	}
	local6, err := resolveHost(ctx, "localhost", time.Second, 6)
	if err != nil || local6 != "::1" {
		t.Fatalf("resolveHost(localhost, 6) = %q, %v", local6, err)
	}

	if _, err := resolveHost(ctx, "", time.Second, 0); err == nil {
		t.Fatal("expected error for empty host")
	}

	if got := selectedIPVersion(true, false); got != 4 {
		t.Errorf("selectedIPVersion(true, false) = %d, want 4", got)
	}
	if got := selectedIPVersion(false, true); got != 6 {
		t.Errorf("selectedIPVersion(false, true) = %d, want 6", got)
	}
	if got := selectedIPVersion(false, false); got != 0 {
		t.Errorf("selectedIPVersion(false, false) = %d, want 0", got)
	}
}

func TestClassifyError(t *testing.T) {
	if got := classifyError(nil); got != StatusOpen {
		t.Errorf("classifyError(nil) = %v, want %v", got, StatusOpen)
	}
	if got := classifyError(context.Canceled); got != StatusCanceled {
		t.Errorf("classifyError(Canceled) = %v, want %v", got, StatusCanceled)
	}
	if got := classifyError(context.DeadlineExceeded); got != StatusFiltered {
		t.Errorf("classifyError(DeadlineExceeded) = %v, want %v", got, StatusFiltered)
	}
	if got := classifyError(fmt.Errorf("wrapped: %w", syscall.ECONNREFUSED)); got != StatusClosed {
		t.Errorf("classifyError(ECONNREFUSED) = %v, want %v", got, StatusClosed)
	}
	if got := classifyError(fmt.Errorf("wrapped: %w", syscall.EMFILE)); got != StatusResourceExhausted {
		t.Errorf("classifyError(EMFILE) = %v, want %v", got, StatusResourceExhausted)
	}
}

func TestScanTCPPortsAndBanners(t *testing.T) {
	// Server-speaks-first listener (e.g. SSH banner)
	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer sshLn.Close()

	go func() {
		for {
			conn, err := sshLn.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
			_ = conn.Close()
		}
	}()
	sshPort := sshLn.Addr().(*net.TCPAddr).Port

	// HTTP-style listener (waits for request before responding)
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer httpLn.Close()

	go func() {
		for {
			conn, err := httpLn.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\nServer: TestHTTP/1.0\r\n\r\n"))
			_ = conn.Close()
		}
	}()
	httpPort := httpLn.Addr().(*net.TCPAddr).Port

	// Closed port
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for closed port: %v", err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	ctx := context.Background()
	cfg := ScanConfig{
		TargetAddr: "127.0.0.1",
		HostHeader: "localhost",
		Protocol:   "tcp",
		Workers:    3,
		Timeout:    500 * time.Millisecond,
		GrabBanner: true,
	}
	ch := emitPorts(ctx, []int{sshPort, httpPort, closedPort}, 0)
	results := scanPorts(ctx, cfg, ch)

	got := make(map[int]ScanResult)
	for res := range results {
		got[res.Port] = res
	}

	if !got[sshPort].Open() || got[sshPort].Banner != "SSH-2.0-OpenSSH_9.9" {
		t.Errorf("unexpected ssh port result: %+v", got[sshPort])
	}
	if !got[httpPort].Open() || got[httpPort].Banner != "HTTP/1.0 200 OK [TestHTTP/1.0]" {
		t.Errorf("unexpected http port result: %+v", got[httpPort])
	}
	if got[closedPort].Status != StatusClosed {
		t.Errorf("expected port %d to be closed, got %+v", closedPort, got[closedPort])
	}
}

func TestScanUDPPort(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = pc.WriteTo([]byte("PONG-UDP\n"), addr)
			}
		}
	}()

	openUDPPort := pc.LocalAddr().(*net.UDPAddr).Port

	ctx := context.Background()
	cfg := ScanConfig{
		TargetAddr: "127.0.0.1",
		Protocol:   "udp",
		Workers:    1,
		Timeout:    300 * time.Millisecond,
		GrabBanner: true,
	}
	ch := emitPorts(ctx, []int{openUDPPort}, 0)
	results := scanPorts(ctx, cfg, ch)

	res := <-results
	if !res.Open() || res.Banner != "PONG-UDP" {
		t.Errorf("expected open UDP port with banner PONG-UDP, got %+v", res)
	}
}

func TestInsertSortedAndReportFormats(t *testing.T) {
	var list []ScanResult
	for _, p := range []int{443, 22, 8080, 80} {
		list = insertSortedResult(list, ScanResult{
			Port:     p,
			Protocol: "tcp",
			Service:  lookupService("tcp", p),
			Status:   StatusOpen,
			Latency:  1500 * time.Microsecond,
			Banner:   "test-banner",
		})
	}

	wantPorts := []int{22, 80, 443, 8080}
	for i, want := range wantPorts {
		if list[i].Port != want {
			t.Fatalf("list[%d].Port = %d, want %d", i, list[i].Port, want)
		}
	}

	sum := ScanSummary{
		Host:         "localhost",
		ResolvedIP:   "127.0.0.1",
		Protocol:     "tcp",
		TotalPorts:   4,
		ScannedPorts: 4,
		Open:         4,
		StartedAt:    time.Now(),
		Duration:     10 * time.Millisecond,
		DurationMs:   10,
	}

	var jsonBuf bytes.Buffer
	if err := writeJSONReport(&jsonBuf, sum, list); err != nil {
		t.Fatalf("writeJSONReport failed: %v", err)
	}
	var parsed JSONReport
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON report: %v", err)
	}
	if parsed.Summary.Open != 4 || len(parsed.Results) != 4 || parsed.Results[0].Port != 22 {
		t.Errorf("unexpected JSON report content: %+v", parsed)
	}

	var csvBuf bytes.Buffer
	if err := writeCSVReport(&csvBuf, list); err != nil {
		t.Fatalf("writeCSVReport failed: %v", err)
	}
	records, err := csv.NewReader(&csvBuf).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV output: %v", err)
	}
	if len(records) != 5 || records[1][0] != "22" || records[1][3] != "ssh" {
		t.Errorf("unexpected CSV records: %v", records)
	}

	var tableBuf bytes.Buffer
	printFinalScrollbackReport(&tableBuf, sum, ScanConfig{Protocol: "tcp", Workers: 4, Timeout: time.Second, GrabBanner: true}, list, false)
	rendered := tableBuf.String()
	for _, expected := range []string{"PORTSCAN", "22", "80", "443", "8080", "OPEN", "test-banner"} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("expected scrollback report to contain %q, got:\n%s", expected, rendered)
		}
	}
}
