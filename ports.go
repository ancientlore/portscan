package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// topPorts lists the 120 most commonly open network ports ordered by prevalence,
// combining Nmap's empirical top-100 dataset with common modern cloud, database,
// and development ports.
var topPorts = []int{
	// Tier 1: Core web, remote access, mail, DNS, and file sharing
	80,   // HTTP (HyperText Transfer Protocol web server)
	443,  // HTTPS (HTTP over TLS/SSL)
	22,   // SSH (Secure Shell remote login and file transfer)
	21,   // FTP (File Transfer Protocol control)
	25,   // SMTP (Simple Mail Transfer Protocol)
	3389, // RDP (Microsoft Terminal Server / Remote Desktop Protocol)
	53,   // DNS (Domain Name System resolver/authoritative server)
	8080, // HTTP Proxy / Alternate HTTP (Tomcat, Jenkins, web apps)
	8443, // HTTPS Alternate (TLS web apps, admin panels, Tomcat SSL)
	3306, // MySQL / MariaDB relational database
	445,  // SMB (Microsoft-DS Active Directory / Windows file sharing)
	139,  // NetBIOS Session Service (Windows file and printer sharing)
	135,  // MSRPC (Microsoft DCE/RPC Endpoint Mapper)
	110,  // POP3 (Post Office Protocol v3 email retrieval)
	143,  // IMAP (Internet Message Access Protocol email retrieval)
	993,  // IMAPS (IMAP over TLS/SSL)
	995,  // POP3S (POP3 over TLS/SSL)
	587,  // SMTP Message Submission (authenticated email relay)
	465,  // SMTPS (SMTP over implicit TLS/SSL)
	23,   // Telnet (legacy unencrypted remote terminal)

	// Tier 2: Databases, containers, cloud infrastructure, and common app servers
	5432,  // PostgreSQL relational database
	6379,  // Redis in-memory key-value data store
	27017, // MongoDB NoSQL document database
	1433,  // Microsoft SQL Server (MSSQL) database
	1521,  // Oracle Database TNS listener
	8000,  // HTTP Alternate (Python/Django, local dev servers, Icecast)
	8888,  // HTTP Alternate (Jupyter Notebook, Sun AnswerBook, proxies)
	3000,  // Web Dev / Dashboards (Grafana, Node.js, Ruby on Rails, Gitea)
	5000,  // HTTP App / UPnP (Docker Registry, Flask, Synology DSM, UPnP)
	9000,  // App Server (PHP-FPM, MinIO, SonarQube, Portainer, CSlistener)
	6443,  // Kubernetes API Server (HTTPS)
	9200,  // Elasticsearch REST HTTP API
	9090,  // Prometheus Server / Cockpit Linux web console / Zeus admin
	5900,  // VNC (Virtual Network Computing remote desktop, display :0)
	111,   // SunRPC / rpcbind (portmapper for NFS and NIS)
	2049,  // NFS (Network File System)
	389,   // LDAP (Lightweight Directory Access Protocol)
	636,   // LDAPS (LDAP over TLS/SSL)
	88,    // Kerberos v5 authentication key distribution center (KDC)
	3128,  // Squid HTTP Web Proxy / caching proxy

	// Tier 3: Messaging, caching, orchestration, VPNs, and network management
	5672,  // AMQP (RabbitMQ / Advanced Message Queuing Protocol)
	9092,  // Apache Kafka broker protocol
	1883,  // MQTT (Message Queuing Telemetry Transport IoT broker)
	11211, // Memcached distributed memory caching daemon
	2375,  // Docker Engine REST API (unencrypted)
	2376,  // Docker Engine REST API (TLS encrypted)
	2379,  // etcd client communication API (Kubernetes backing store)
	8500,  // HashiCorp Consul HTTP API and web UI
	50051, // gRPC default server port
	10000, // Webmin sysadmin UI / Symantec NetBackup / NDMP
	8081,  // HTTP Alternate (Nexus, McAfee ePO, BlackIce IceCap)
	8008,  // HTTP Alternate (Google Cast, IBM HTTP Server)
	8009,  // Apache JServ Protocol (AJP13 connector for Tomcat)
	873,   // rsync file synchronization daemon
	631,   // IPP (Internet Printing Protocol / CUPS print server)
	9100,  // HP JetDirect / RAW network printer port
	5060,  // SIP (Session Initiation Protocol VoIP signaling, unencrypted)
	554,   // RTSP (Real Time Streaming Protocol for IP cameras/media)
	179,   // BGP (Border Gateway Protocol internet routing)
	1723,  // PPTP (Point-to-Point Tunneling Protocol VPN)
	123,   // NTP (Network Time Protocol time synchronization)
	1080,  // SOCKS proxy server
	990,   // FTPS (FTP control over implicit TLS/SSL)
	548,   // AFP (Apple Filing Protocol over TCP)

	// Tier 4: Enterprise services, Windows RPC range, and legacy protocols
	199,   // SMUX (SNMP Unix Multiplexer)
	1720,  // H.323 (Q.931 VoIP / video conferencing call signaling)
	113,   // ident / auth (Authentication Service identification protocol)
	81,    // HTTP Alternate / hosts2-ns name server
	6000,  // X11 Window System display :0
	6001,  // X11 Window System display :1
	514,   // BSD rsh (remote shell) / syslog over TCP
	515,   // LPD (Line Printer Daemon print spooler)
	513,   // BSD rlogin (remote login)
	2000,  // Cisco SCCP (Skinny Client Control Protocol VoIP)
	2001,  // Cisco terminal server / wizard / HTTP alt
	1900,  // SSDP / Microsoft UPnP discovery
	5353,  // mDNS (Multicast DNS / Bonjour service discovery)
	5357,  // WSDAPI (Microsoft Web Services for Devices HTTP)
	5666,  // Nagios NRPE (Nagios Remote Plugin Executor)
	5800,  // VNC over HTTP (Java applet viewer, display :0)
	5631,  // Symantec pcAnywhere data port
	4899,  // Radmin (Remote Administrator remote control)
	2121,  // FTP Alternate / CCProxy FTP
	7070,  // RealServer / RTSP alternate / AnyDesk
	9999,  // Abyss web server / Lantronix / Urchin / Dash
	427,   // SLP (Service Location Protocol)
	646,   // LDP (Label Distribution Protocol for MPLS routers)
	119,   // NNTP (Network News Transfer Protocol Usenet)
	79,    // Finger user information protocol
	26,    // RSFTP / alternate SMTP port
	106,   // POP3PW (Eudora / Qualcomm password change server)
	144,   // Universal Management Architecture / news
	444,   // SNPP (Simple Network Paging Protocol)
	543,   // klogin (Kerberos v4/v5 remote login)
	544,   // kshell (Kerberos v4/v5 remote shell)

	// Tier 5: Ephemeral/dynamic RPC ports and specialized/legacy services
	1025,  // Windows RPC dynamic port / NFS or IIS listener
	1026,  // Windows RPC dynamic port / Calendar Access Protocol
	1027,  // Windows RPC dynamic port
	1028,  // Windows RPC dynamic port
	1029,  // Windows RPC dynamic port / MS LSA
	32768, // Linux/Solaris ephemeral RPC port (filenet-tms)
	49152, // Windows Vista+ IANA dynamic/ephemeral RPC port
	49153, // Windows Vista+ IANA dynamic/ephemeral RPC port
	49154, // Windows Vista+ IANA dynamic/ephemeral RPC port
	49155, // Windows Vista+ IANA dynamic/ephemeral RPC port
	49156, // Windows Vista+ IANA dynamic/ephemeral RPC port
	49157, // Windows Vista+ IANA dynamic/ephemeral RPC port
	1110,  // NFS status / WebAdm / cluster status
	1755,  // MMS (Microsoft Media Server streaming protocol)
	2717,  // PN-Requester
	3986,  // Mapper Workstation Server
	5009,  // Apple AirPort Admin Utility
	5051,  // IDA-Agent (Symantec Intruder Alert)
	5101,  // Talarian TCP / Yahoo Messenger
	5190,  // AOL Instant Messenger (AIM) / ICQ OSCAR protocol
	6646,  // McAfee Network Agent
	7,     // Echo protocol (RFC 862)
	9,     // Discard protocol (RFC 863)
	13,    // Daytime protocol (RFC 867)
	37,    // Time protocol (RFC 868)
}

// tcpServices maps well-known TCP ports to service names.
var tcpServices = map[int]string{
	7:     "echo",             // Echo protocol (RFC 862)
	9:     "discard",          // Discard protocol (RFC 863)
	13:    "daytime",          // Daytime protocol (RFC 867)
	20:    "ftp-data",         // FTP data transfer
	21:    "ftp",              // File Transfer Protocol control
	22:    "ssh",              // Secure Shell
	23:    "telnet",           // Telnet terminal
	25:    "smtp",             // Simple Mail Transfer Protocol
	26:    "rsftp",            // RSFTP / alternate SMTP
	37:    "time",             // Time protocol (RFC 868)
	53:    "domain",           // Domain Name System (DNS)
	79:    "finger",           // Finger user lookup
	80:    "http",             // HyperText Transfer Protocol
	81:    "hosts2-ns",        // Hosts2 Name Server / alternate HTTP
	88:    "kerberos",         // Kerberos v5 authentication
	106:   "pop3pw",           // POP3 password change
	110:   "pop3",             // Post Office Protocol v3
	111:   "rpcbind",          // ONC RPC portmapper
	113:   "ident",            // Authentication/ident service
	119:   "nntp",             // Network News Transfer Protocol
	123:   "ntp",              // Network Time Protocol
	135:   "msrpc",            // Microsoft DCE/RPC Endpoint Mapper
	139:   "netbios-ssn",      // NetBIOS Session Service
	143:   "imap",             // Internet Message Access Protocol
	144:   "news",             // Universal Management Architecture / news
	179:   "bgp",              // Border Gateway Protocol
	199:   "smux",             // SNMP Unix Multiplexer
	389:   "ldap",             // Lightweight Directory Access Protocol
	427:   "svrloc",           // Service Location Protocol
	443:   "https",            // HTTP over TLS/SSL
	444:   "snpp",             // Simple Network Paging Protocol
	445:   "microsoft-ds",     // SMB over TCP (Active Directory / file sharing)
	465:   "smtps",            // SMTP over implicit TLS/SSL
	513:   "login",            // BSD rlogin
	514:   "shell",            // BSD rsh / syslog over TCP
	515:   "printer",          // Line Printer Daemon (LPD)
	543:   "klogin",           // Kerberos rlogin
	544:   "kshell",           // Kerberos remote shell
	548:   "afp",              // Apple Filing Protocol
	554:   "rtsp",             // Real Time Streaming Protocol
	587:   "submission",       // Email message submission (RFC 6409)
	631:   "ipp",              // Internet Printing Protocol (CUPS)
	636:   "ldaps",            // LDAP over TLS/SSL
	646:   "ldp",              // MPLS Label Distribution Protocol
	873:   "rsync",            // rsync file sync daemon
	990:   "ftps",             // FTP control over implicit TLS/SSL
	993:   "imaps",            // IMAP over TLS/SSL
	995:   "pop3s",            // POP3 over TLS/SSL
	1025:  "msrpc-dyn",        // Windows dynamic RPC / network blackjack
	1026:  "msrpc-dyn",        // Windows dynamic RPC
	1027:  "msrpc-dyn",        // Windows dynamic RPC
	1028:  "msrpc-dyn",        // Windows dynamic RPC
	1029:  "msrpc-dyn",        // Windows dynamic RPC
	1080:  "socks",            // SOCKS proxy
	1110:  "nfsd-status",      // NFS cluster status
	1433:  "ms-sql-s",         // Microsoft SQL Server
	1521:  "oracle",           // Oracle Database listener
	1720:  "h323q931",         // H.323 VoIP call signaling
	1723:  "pptp",             // Point-to-Point Tunneling Protocol VPN
	1755:  "mms",              // Microsoft Media Server
	1883:  "mqtt",             // MQTT IoT broker
	1900:  "upnp",             // Universal Plug and Play SSDP
	2000:  "cisco-sccp",       // Cisco Skinny VoIP protocol
	2001:  "dc",               // Cisco terminal server / HTTP alt
	2049:  "nfs",              // Network File System
	2121:  "ccproxy-ftp",      // FTP proxy / alternate FTP
	2375:  "docker",           // Docker REST API (plain)
	2376:  "docker-s",         // Docker REST API (TLS)
	2379:  "etcd-client",      // etcd key-value store client API
	2717:  "pn-requester",     // PN-Requester
	3000:  "http-dev",         // Grafana / Node.js / Rails dev server
	3128:  "squid-http",       // Squid web proxy
	3306:  "mysql",            // MySQL / MariaDB database
	3389:  "ms-wbt-server",    // Microsoft Remote Desktop (RDP)
	3986:  "mapper-ws_ethd",   // Mapper Workstation Server
	4899:  "radmin",           // Radmin remote control
	5000:  "upnp",             // Flask / Docker Registry / UPnP
	5009:  "airport-admin",    // Apple AirPort Admin Utility
	5051:  "ida-agent",        // Symantec IDA Agent
	5060:  "sip",              // Session Initiation Protocol (VoIP)
	5101:  "admdog",           // Talarian TCP / Yahoo Messenger
	5190:  "aol",              // AIM / ICQ OSCAR protocol
	5353:  "mdns",             // Multicast DNS
	5357:  "wsdapi",           // Microsoft Web Services for Devices
	5432:  "postgresql",       // PostgreSQL database
	5631:  "pcanywheredata",   // Symantec pcAnywhere data
	5666:  "nrpe",             // Nagios Remote Plugin Executor
	5672:  "amqp",             // RabbitMQ / AMQP messaging
	5800:  "vnc-http",         // VNC over HTTP viewer
	5900:  "vnc",              // Virtual Network Computing (VNC)
	6000:  "X11",              // X Window System display :0
	6001:  "X11:1",            // X Window System display :1
	6379:  "redis",            // Redis key-value store
	6443:  "kubernetes",       // Kubernetes API server
	6646:  "mcafee-agent",     // McAfee Network Agent
	7070:  "realserver",       // RealServer / RTSP alt
	8000:  "http-alt",         // Alternate HTTP server
	8008:  "http",             // Alternate HTTP / Google Cast
	8009:  "ajp13",            // Apache JServ Protocol (Tomcat)
	8080:  "http-proxy",       // HTTP proxy / alternate HTTP
	8081:  "blackice-icecap",  // Alternate HTTP / Nexus
	8443:  "https-alt",        // Alternate HTTPS server
	8500:  "consul",           // HashiCorp Consul HTTP API
	8888:  "sun-answerbook",   // Jupyter / alternate HTTP proxy
	9000:  "cslistener",       // PHP-FPM / MinIO / SonarQube / Portainer
	9090:  "prometheus",       // Prometheus / Cockpit web console
	9092:  "kafka",            // Apache Kafka broker
	9100:  "jetdirect",        // HP JetDirect network printing
	9200:  "elasticsearch",    // Elasticsearch REST API
	9999:  "abyss",            // Abyss web server / admin port
	10000: "snet-sensor-mgmt", // Webmin / NetBackup
	11211: "memcache",         // Memcached caching daemon
	27017: "mongodb",          // MongoDB NoSQL database
	32768: "filenet-tms",      // Ephemeral RPC / FileNet
	49152: "msrpc-ephem",      // Windows IANA dynamic RPC
	49153: "msrpc-ephem",      // Windows IANA dynamic RPC
	49154: "msrpc-ephem",      // Windows IANA dynamic RPC
	49155: "msrpc-ephem",      // Windows IANA dynamic RPC
	49156: "msrpc-ephem",      // Windows IANA dynamic RPC
	49157: "msrpc-ephem",      // Windows IANA dynamic RPC
	50051: "grpc",             // gRPC default server port
}

// udpServices maps well-known UDP ports to service names.
var udpServices = map[int]string{
	7:    "echo",        // Echo protocol (RFC 862)
	9:    "discard",     // Discard protocol (RFC 863)
	19:   "chargen",     // Character Generator protocol (RFC 864)
	53:   "domain",      // Domain Name System (DNS)
	67:   "dhcps",       // DHCP server
	68:   "dhcpc",       // DHCP client
	69:   "tftp",        // Trivial File Transfer Protocol
	111:  "rpcbind",     // ONC RPC portmapper
	123:  "ntp",         // Network Time Protocol
	137:  "netbios-ns",  // NetBIOS Name Service
	138:  "netbios-dgm", // NetBIOS Datagram Service
	161:  "snmp",        // Simple Network Management Protocol
	162:  "snmptrap",    // SNMP Trap receiver
	500:  "isakmp",      // IPsec IKE (Internet Key Exchange)
	514:  "syslog",      // Syslog logging receiver
	520:  "route",       // RIP (Routing Information Protocol)
	1194: "openvpn",     // OpenVPN tunnel
	1900: "upnp",        // Universal Plug and Play SSDP
	4500: "nat-t-ike",   // IPsec NAT Traversal
	5060: "sip",         // Session Initiation Protocol (VoIP)
	5353: "mdns",        // Multicast DNS (Bonjour)
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
	if err != nil && !isTimeoutErr(err) {
		return ""
	}

	// Fallback: send an HTTP HEAD probe for silent servers (HTTP, proxies, etc.).
	return sanitizeBanner(probeHTTP(conn, hostHeader, deadline))
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func probeHTTP(conn net.Conn, hostHeader string, deadline time.Time) string {
	_ = conn.SetDeadline(deadline)
	req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: portscan/1.0\r\n\r\n", hostHeader)
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}

	reader := bufio.NewReader(io.LimitReader(conn, 2048))
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
