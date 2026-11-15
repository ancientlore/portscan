package main

import (
	"context"
	"fmt"
	"net"
	"reflect"
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

func TestResolveHost(t *testing.T) {
	ctx := context.Background()

	ip4, err := resolveHost(ctx, "127.0.0.1", time.Second)
	if err != nil || ip4 != "127.0.0.1" {
		t.Fatalf("resolveHost(127.0.0.1) = %q, %v", ip4, err)
	}

	ip6, err := resolveHost(ctx, "::1", time.Second)
	if err != nil || ip6 != "::1" {
		t.Fatalf("resolveHost(::1) = %q, %v", ip6, err)
	}

	ip6Bracketed, err := resolveHost(ctx, "[::1]", time.Second)
	if err != nil || ip6Bracketed != "::1" {
		t.Fatalf("resolveHost([::1]) = %q, %v", ip6Bracketed, err)
	}

	if _, err := resolveHost(ctx, "", time.Second); err == nil {
		t.Fatal("expected error for empty host")
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

func TestScanPortsIntegration(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	openPort := ln.Addr().(*net.TCPAddr).Port

	// Allocate and immediately close a listener to get a likely closed port.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for closed port: %v", err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	ctx := context.Background()
	ch := emitPorts(ctx, []int{openPort, closedPort})
	results := scanPorts(ctx, "127.0.0.1", ch, 2, 500*time.Millisecond)

	got := make(map[int]ScanResult)
	for res := range results {
		got[res.Port] = res
	}

	if !got[openPort].Open() {
		t.Errorf("expected port %d to be open, got %+v", openPort, got[openPort])
	}
	if got[closedPort].Status != StatusClosed {
		t.Errorf("expected port %d to be closed, got %+v", closedPort, got[closedPort])
	}
}
