# portscan

`portscan` is a fast, concurrent TCP and UDP port scanner written in Go with an interactive inline terminal UI powered by Charmbracelet (Bubble Tea v2, Bubbles v2, and Lipgloss v2).

## Features

- **Concurrent TCP & UDP Scanning**: Configurable worker pool, per-port timeout, and optional rate limiting (`-rate`) or randomized scan order (`-shuffle`).
- **Service Lookup & Banner Grabbing**: Identifies common services by port number and optionally grabs banners (`-banner`) via server greetings, HTTP `HEAD` probes, and TLS certificate inspection.
- **Port Presets**: Scan custom port ranges (`-range`), the top $N$ most common ports (`-top 100`), or all 65,535 ports (`-all`).
- **Inline Terminal UI & Structured Exports**: Displays a live progress bar, scan rate, and sorted open-port table in interactive terminals while keeping final results in scrollback, or exports directly to `-json` or `-csv`.

## Usage

```text
Usage of portscan:
  -4	Force IPv4 resolution and scanning
  -6	Force IPv6 resolution and scanning
  -all
    	Scan all ports (1-65535)
  -banner
    	Grab service banners on open ports
  -csv
    	Output results as CSV
  -host string
    	Host or IP to scan (default "localhost")
  -json
    	Output results as JSON
  -no-tui
    	Disable live interactive TUI
  -range string
    	Port ranges e.g. 80,443,200-1000,8000-9000 (default "80,443")
  -rate int
    	Max port probes per second (0 for unlimited)
  -shuffle
    	Randomize port scan order
  -threads int
    	Threads to use (default 100)
  -timeout duration
    	Timeout per port (default 1s)
  -top int
    	Scan the top N most common ports (1-120)
  -udp
    	Scan UDP ports instead of TCP
  -verbose
    	Show errors for failed ports
```
