package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// topPorts lists the 100 most commonly open network ports ordered by prevalence.
var topPorts = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
	6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
}

// tcpServices maps well-known TCP ports to service names.
var tcpServices = map[int]string{
	7:     "echo",
	9:     "discard",
	13:    "daytime",
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	26:    "rsftp",
	37:    "time",
	53:    "domain",
	79:    "finger",
	80:    "http",
	81:    "hosts2-ns",
	88:    "kerberos",
	106:   "pop3pw",
	110:   "pop3",
	111:   "rpcbind",
	113:   "ident",
	119:   "nntp",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	144:   "news",
	179:   "bgp",
	199:   "smux",
	389:   "ldap",
	427:   "svrloc",
	443:   "https",
	444:   "snpp",
	445:   "microsoft-ds",
	465:   "smtps",
	513:   "login",
	514:   "shell",
	515:   "printer",
	543:   "klogin",
	544:   "kshell",
	548:   "afp",
	554:   "rtsp",
	587:   "submission",
	631:   "ipp",
	636:   "ldaps",
	646:   "ldp",
	873:   "rsync",
	990:   "ftps",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1433:  "ms-sql-s",
	1521:  "oracle",
	1720:  "h323q931",
	1723:  "pptp",
	1883:  "mqtt",
	2049:  "nfs",
	2121:  "ccproxy-ftp",
	2375:  "docker",
	2376:  "docker-s",
	3000:  "ppp",
	3128:  "squid-http",
	3306:  "mysql",
	3389:  "ms-wbt-server",
	5000:  "upnp",
	5060:  "sip",
	5432:  "postgresql",
	5631:  "pcanywheredata",
	5666:  "nrpe",
	5672:  "amqp",
	5900:  "vnc",
	6000:  "X11",
	6379:  "redis",
	6443:  "kubernetes",
	7070:  "realserver",
	8000:  "http-alt",
	8008:  "http",
	8009:  "ajp13",
	8080:  "http-proxy",
	8081:  "blackice-icecap",
	8443:  "https-alt",
	8888:  "sun-answerbook",
	9000:  "cslistener",
	9090:  "zeus-admin",
	9100:  "jetdirect",
	9200:  "wap-wsp",
	9999:  "abyss",
	10000: "snet-sensor-mgmt",
	11211: "memcache",
	27017: "mongodb",
}

// udpServices maps well-known UDP ports to service names.
var udpServices = map[int]string{
	7:    "echo",
	9:    "discard",
	19:   "chargen",
	53:   "domain",
	67:   "dhcps",
	68:   "dhcpc",
	69:   "tftp",
	111:  "rpcbind",
	123:  "ntp",
	137:  "netbios-ns",
	138:  "netbios-dgm",
	161:  "snmp",
	162:  "snmptrap",
	500:  "isakmp",
	514:  "syslog",
	520:  "route",
	1194: "openvpn",
	1900: "upnp",
	4500: "nat-t-ike",
	5060: "sip",
	5353: "mdns",
}

// lookupService returns the known service name for a given port and protocol.
func lookupService(proto string, port int) string {
	if proto == "udp" {
		if name, ok := udpServices[port]; ok {
			return name
		}
	}
	if name, ok := tcpServices[port]; ok {
		return name
	}
	return ""
}

var tlsPorts = map[int]bool{
	443:  true,
	465:  true,
	636:  true,
	990:  true,
	993:  true,
	995:  true,
	8443: true,
}

// sanitizeBanner cleans raw network bytes into a single printable line safe for terminal output.
func sanitizeBanner(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Take the first non-empty line unless we extracted headers separately.
	lines := strings.Split(raw, "\n")
	first := strings.TrimSpace(lines[0])

	var b strings.Builder
	for _, r := range first {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	const maxLen = 96
	if len(out) > maxLen {
		out = out[:maxLen] + "..."
	}
	return out
}

// grabTCPBanner attempts to identify the running service banner on an open TCP connection.
func grabTCPBanner(ctx context.Context, conn net.Conn, hostHeader string, port int, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	// If it's a known TLS port, attempt a TLS handshake and inspect cert / HTTP over TLS.
	if tlsPorts[port] {
		_ = conn.SetDeadline(deadline)
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         hostHeader,
			InsecureSkipVerify: true, //nolint:gosec // Scanner inspects untrusted endpoints
		})
		if err := tlsConn.HandshakeContext(ctx); err == nil {
			state := tlsConn.ConnectionState()
			var certInfo string
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				if cert.Subject.CommonName != "" {
					certInfo = "TLS CN=" + cert.Subject.CommonName
				} else if len(cert.DNSNames) > 0 {
					certInfo = "TLS SAN=" + cert.DNSNames[0]
				}
			}
			httpBanner := probeHTTP(tlsConn, hostHeader, deadline)
			if httpBanner != "" && certInfo != "" {
				return sanitizeBanner(httpBanner + " (" + certInfo + ")")
			}
			if httpBanner != "" {
				return sanitizeBanner(httpBanner)
			}
			if certInfo != "" {
				return sanitizeBanner(certInfo)
			}
			return "TLS"
		}
		return ""
	}

	// Wait briefly for server-speaks-first protocols (SSH, SMTP, FTP, POP3, IMAP).
	waitFirst := timeout / 3
	if waitFirst > 250*time.Millisecond {
		waitFirst = 250 * time.Millisecond
	}
	if waitFirst < 50*time.Millisecond {
		waitFirst = 50 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(waitFirst))

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if n > 0 {
		return sanitizeBanner(string(buf[:n]))
	}
	if err != nil {
		var netErr net.Error
		if ok := isTimeoutErr(err, &netErr); !ok {
			return ""
		}
	}

	// Fallback: send an HTTP HEAD probe for silent servers (HTTP, proxies, etc.).
	return sanitizeBanner(probeHTTP(conn, hostHeader, deadline))
}

func isTimeoutErr(err error, netErr *net.Error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		*netErr = ne
		return true
	}
	return false
}

func probeHTTP(conn net.Conn, hostHeader string, deadline time.Time) string {
	_ = conn.SetDeadline(deadline)
	req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: portscan/1.0\r\n\r\n", hostHeader)
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}

	reader := bufio.NewReader(ioLimitReader(conn, 2048))
	statusLine, err := reader.ReadString('\n')
	statusLine = strings.TrimSpace(statusLine)
	if err != nil && statusLine == "" {
		return ""
	}
	if !strings.HasPrefix(statusLine, "HTTP/") {
		return statusLine
	}

	var serverHeader string
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			serverHeader = strings.TrimSpace(line[len("server:"):])
			break
		}
		if err != nil {
			break
		}
	}

	if serverHeader != "" {
		return fmt.Sprintf("%s [%s]", statusLine, serverHeader)
	}
	return statusLine
}

type limitedConnReader struct {
	r net.Conn
	n int
}

func ioLimitReader(r net.Conn, n int) *limitedConnReader {
	return &limitedConnReader{r: r, n: n}
}

func (l *limitedConnReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, fmt.Errorf("limit reached")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}

// udpPayloadForPort returns a protocol-specific datagram for well-known UDP ports,
// or a minimal probe payload for generic ports so an ICMP Port Unreachable or reply can be triggered.
func udpPayloadForPort(port int) []byte {
	switch port {
	case 53:
		// Minimal DNS standard query for "." NS
		return []byte{
			0x12, 0x34, // Transaction ID
			0x01, 0x00, // Standard query, recursion desired
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			0x00,       // Root zone "."
			0x00, 0x02, // Type NS
			0x00, 0x01, // Class IN
		}
	case 123:
		// Minimal 48-byte NTPv3 client request
		pkt := make([]byte, 48)
		pkt[0] = 0x1b // LI=0, VN=3, Mode=3 (Client)
		return pkt
	default:
		return []byte("\r\n")
	}
}

// scanUDPPort probes a single UDP port using a connected UDP socket so ICMP Port Unreachable
// errors surface as ECONNREFUSED on Read.
func scanUDPPort(ctx context.Context, dialer *net.Dialer, cfg ScanConfig, port int) ScanResult {
	addr := net.JoinHostPort(cfg.TargetAddr, strconv.Itoa(port))
	network := dialNetwork("udp", cfg.IPVersion)
	start := time.Now()
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return ScanResult{
			Port:     port,
			Protocol: "udp",
			Service:  lookupService("udp", port),
			Status:   classifyError(err),
			Latency:  time.Since(start),
			Err:      err,
		}
	}
	defer conn.Close()

	deadline := time.Now().Add(cfg.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	payload := udpPayloadForPort(port)
	if _, err := conn.Write(payload); err != nil {
		return ScanResult{
			Port:     port,
			Protocol: "udp",
			Service:  lookupService("udp", port),
			Status:   classifyError(err),
			Latency:  time.Since(start),
			Err:      err,
		}
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	latency := time.Since(start)
	if err != nil {
		status := classifyError(err)
		// For UDP, a read timeout means no response AND no ICMP Port Unreachable was received.
		if status == StatusFiltered {
			status = StatusOpenFiltered
		}
		return ScanResult{
			Port:     port,
			Protocol: "udp",
			Service:  lookupService("udp", port),
			Status:   status,
			Latency:  latency,
			Err:      err,
		}
	}

	var banner string
	if cfg.GrabBanner && n > 0 {
		banner = sanitizeBanner(string(buf[:n]))
	}
	return ScanResult{
		Port:     port,
		Protocol: "udp",
		Service:  lookupService("udp", port),
		Status:   StatusOpen,
		Latency:  latency,
		Banner:   banner,
	}
}
