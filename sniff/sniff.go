package sniff

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// SniffResult contains the result of domain sniffing
type SniffResult struct {
	Domain   string // Detected domain
	Protocol string // Detected protocol (http, https, quic, etc.)
	Source   string // Source of the domain (http_host, tls_sni, etc.)
	Metadata map[string]interface{}
}

// Sniffer handles domain sniffing from traffic
type Sniffer struct {
	enabledProtocols []string
	timeout          int // milliseconds
}

// NewSniffer creates a new domain sniffer
func NewSniffer() *Sniffer {
	return &Sniffer{
		enabledProtocols: []string{"http", "tls", "quic", "websocket"},
		timeout:          100,
	}
}

// NewSnifferWithConfig creates a sniffer with custom config
func NewSnifferWithConfig(protocols []string, timeoutMs int) *Sniffer {
	return &Sniffer{
		enabledProtocols: protocols,
		timeout:          timeoutMs,
	}
}

// SniffDomain attempts to extract domain from various protocols
func (s *Sniffer) SniffDomain(data []byte, isUDP bool) (*SniffResult, error) {
	if len(data) < 4 {
		return nil, errors.New("data too short for sniffing")
	}

	// Check for UDP protocols first (QUIC)
	if isUDP {
		return s.sniffQUIC(data)
	}

	// TCP protocols
	// Check for TLS ClientHello (HTTPS)
	if s.isTLSHandshake(data) {
		return s.sniffTLS(data)
	}

	// Check for HTTP requests
	if s.isHTTPRequest(data) {
		return s.sniffHTTP(data)
	}

	return nil, errors.New("unable to detect protocol for domain extraction")
}

// isTLSHandshake checks if data starts with TLS ClientHello
func (s *Sniffer) isTLSHandshake(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// TLS record: content type (22 = handshake) + version (0x03 0x01-0x03) + length
	return data[0] == 0x16 && // Handshake
		data[1] == 0x03 && // TLS major version
		data[2] <= 0x03 // TLS minor version <= 3
}

// isHTTPRequest checks if data starts with HTTP request
func (s *Sniffer) isHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// HTTP request methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, CONNECT, etc.
	methods := []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "OPTI", "CONN", "PATC", "HTTP"}
	for _, m := range methods {
		if bytes.HasPrefix(data, []byte(m)) {
			return true
		}
	}
	return false
}

// sniffTLS extracts SNI from TLS ClientHello
func (s *Sniffer) sniffTLS(data []byte) (*SniffResult, error) {
	if !s.isTLSHandshake(data) {
		return nil, errors.New("not a TLS handshake")
	}

	// Parse TLS record
	// Content Type: 1 byte (0x16 = handshake)
	// Version: 2 bytes (0x03 0x01-0x03)
	// Length: 2 bytes
	if len(data) < 5 {
		return nil, errors.New("TLS record too short")
	}

	recordLen := binary.BigEndian.Uint16(data[3:5])
	if len(data) < 5+int(recordLen) {
		return nil, errors.New("incomplete TLS record")
	}

	// Parse handshake
	handshakeData := data[5 : 5+recordLen]
	if len(handshakeData) < 4 || handshakeData[0] != 0x01 {
		return nil, errors.New("not a ClientHello")
	}

	// ClientHello: type(1) + length(3) + client_version(2) + random(32) + session_id_length(1) + ...
	clientHelloData := handshakeData[4:]

	if len(clientHelloData) < 34 {
		return nil, errors.New("ClientHello too short")
	}

	offset := 34 // client_version(2) + random(32)

	// Session ID
	sessionIDLen := int(clientHelloData[offset])
	offset += 1 + sessionIDLen

	if offset >= len(clientHelloData) {
		return nil, errors.New("missing cipher suites")
	}

	// Cipher Suites
	cipherSuitesLen := binary.BigEndian.Uint16(clientHelloData[offset : offset+2])
	offset += 2 + int(cipherSuitesLen)

	if offset >= len(clientHelloData) {
		return nil, errors.New("missing compression methods")
	}

	// Compression Methods
	compressionLen := int(clientHelloData[offset])
	offset += 1 + compressionLen

	if offset >= len(clientHelloData) {
		return nil, errors.New("no extensions")
	}

	// Extensions
	extensionsLen := binary.BigEndian.Uint16(clientHelloData[offset : offset+2])
	offset += 2

	extensionsEnd := offset + int(extensionsLen)
	if extensionsEnd > len(clientHelloData) {
		return nil, errors.New("incomplete extensions")
	}

	// Parse extensions to find SNI (type 0x0000)
	for offset < extensionsEnd {
		if offset+4 > len(clientHelloData) {
			break
		}
		extType := binary.BigEndian.Uint16(clientHelloData[offset : offset+2])
		extLen := binary.BigEndian.Uint16(clientHelloData[offset+2 : offset+4])
		offset += 4

		if extType == 0 && extLen > 0 { // SNI extension
			sniData := clientHelloData[offset : offset+int(extLen)]
			if len(sniData) < 3 || sniData[0] != 0 { // type must be 0 (host_name)
				break
			}
			nameLen := binary.BigEndian.Uint16(sniData[1:3])
			if len(sniData) < 3+int(nameLen) {
				return nil, errors.New("invalid SNI length")
			}
			domain := string(sniData[3 : 3+nameLen])
			return &SniffResult{
				Domain:   domain,
				Protocol: "tls",
				Source:   "sni",
				Metadata: map[string]interface{}{
					"sni_type": "server_name",
				},
			}, nil
		}
		offset += int(extLen)
	}

	return nil, errors.New("SNI extension not found")
}

// sniffHTTP extracts domain from HTTP Host header
func (s *Sniffer) sniffHTTP(data []byte) (*SniffResult, error) {
	// Parse HTTP request
	reader := bufio.NewReader(bytes.NewReader(data))

	// Read request line
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, errors.New("failed to read request line")
	}
	line = strings.TrimSpace(line)

	// Parse request line
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, errors.New("invalid HTTP request line")
	}

	method := parts[0]
	url := parts[1]

	var domain string
	var port string

	// For CONNECT method (used in HTTPS tunneling)
	if method == "CONNECT" {
		if idx := strings.Index(url, ":"); idx != -1 {
			domain = url[:idx]
			port = url[idx+1:]
		} else {
			domain = url
			port = "443"
		}
		return &SniffResult{
			Domain:   domain,
			Protocol: "http",
			Source:   "connect_target",
			Metadata: map[string]interface{}{
				"port":     port,
				"method":   "CONNECT",
				"is_https": port == "443",
			},
		}, nil
	}

	// For regular HTTP requests, extract Host from headers
	// Read headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}

		header := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(header), "host:") {
			hostValue := strings.TrimPrefix(header, "Host:")
			hostValue = strings.TrimSpace(hostValue)

			// Remove port if present
			if idx := strings.Index(hostValue, ":"); idx != -1 {
				domain = hostValue[:idx]
				port = hostValue[idx+1:]
			} else {
				domain = hostValue
				port = "80"
			}

			return &SniffResult{
				Domain:   domain,
				Protocol: "http",
				Source:   "http_host",
				Metadata: map[string]interface{}{
					"port":         port,
					"method":       method,
					"original_url": url,
				},
			}, nil
		}
	}

	return nil, errors.New("Host header not found")
}

// sniffQUIC extracts domain from QUIC packet
func (s *Sniffer) sniffQUIC(data []byte) (*SniffResult, error) {
	if len(data) < 5 {
		return nil, errors.New("QUIC packet too short")
	}

	// QUIC long header: first byte (version-independent) + version(4) + DCID(1-20) + SCID(1-20)
	// We look for the SNI in the CRYPTO frame

	// Check for long header (first bit set)
	if data[0]&0x80 == 0 {
		// Short header - no SNI in short header packets
		return nil, errors.New("QUIC short header - no SNI")
	}

	// Get DCID length (first byte after header form + fixed bit + long packet type + unused)
	// Simplified: skip to possible SNI area
	// This is a basic implementation; real QUIC parsing is more complex

	// For QUIC v1, SNI is in the crypto frame with handshakes
	// Look for SNI in the packet - this is a simplified detection

	// Search for SNI indicator pattern
	sniPattern := []byte{0x00, 0x00} // SNI type in wire format
	for i := 1; i < len(data)-4; i++ {
		if data[i] == sniPattern[0] && data[i+1] == sniPattern[1] {
			// Found potential SNI type
			// SNI is UTF-8 encoded hostname
			strLen := binary.BigEndian.Uint16(data[i+2 : i+4])
			if i+4+int(strLen) <= len(data) {
				domain := string(data[i+4 : i+4+int(strLen)])
				if isValidDomain(domain) {
					return &SniffResult{
						Domain:   domain,
						Protocol: "quic",
						Source:   "quic_sni",
						Metadata: map[string]interface{}{
							"packet_type": "long_header",
						},
					}, nil
				}
			}
		}
	}

	return nil, errors.New("SNI not found in QUIC packet")
}

// SniffFromConn sniffs domain from an active connection
func (s *Sniffer) SniffFromConn(conn net.Conn) (*SniffResult, error) {
	// Peek at the first few bytes
	buf := make([]byte, 512)
	deadline := time.Now().Add(100 * time.Millisecond)
	conn.SetReadDeadline(deadline)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("no data read")
	}

	// Restore the data that was read
	result, err := s.SniffDomain(buf[:n], false)
	if err != nil {
		return nil, err
	}

	// Note: In a real implementation, we would need to handle
	// putting the data back or handling the connection properly

	return result, nil
}

// isValidDomain checks if a string looks like a valid domain
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for valid characters
	hasDot := false
	for i, c := range domain {
		if c == '.' {
			if i == 0 || i == len(domain)-1 {
				return false
			}
			hasDot = true
			continue
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}

	// Check label lengths
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return false
		}
	}

	return hasDot
}

// Matcher handles traffic sniffing for routing decisions
type Matcher struct {
	sniffer       *Sniffer
	domainFilters []string // Whitelist of domains to sniff
}

// NewMatcher creates a new sniff matcher
func NewMatcher() *Matcher {
	return &Matcher{
		sniffer:       NewSniffer(),
		domainFilters: []string{},
	}
}

// SetFilters sets domain filters (only sniff these domains)
func (m *Matcher) SetFilters(domains []string) {
	m.domainFilters = domains
}

// Match performs sniffing and returns enriched context
func (m *Matcher) Match(data []byte, isUDP bool) (*SniffResult, bool) {
	result, err := m.sniffer.SniffDomain(data, isUDP)
	if err != nil {
		return nil, false
	}

	// Apply filters if set
	if len(m.domainFilters) > 0 {
		matched := false
		for _, filter := range m.domainFilters {
			if filter == "*" || filter == result.Domain {
				matched = true
				break
			}
			// Check suffix match
			if strings.HasSuffix(result.Domain, "."+filter) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, false
		}
	}

	return result, true
}

// GetDomainFromRequest extracts domain from HTTP request bytes
func GetDomainFromRequest(data []byte) string {
	if len(data) < 10 {
		return ""
	}

	// Try HTTP first
	result, err := NewSniffer().sniffHTTP(data)
	if err == nil && result != nil {
		return result.Domain
	}

	return ""
}

// GetSNIFromTLS extracts SNI from TLS ClientHello
func GetSNIFromTLS(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	result, err := NewSniffer().sniffTLS(data)
	if err == nil && result != nil {
		return result.Domain
	}

	return ""
}

// Quick extract domain from any supported protocol
func QuickExtractDomain(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// Try TLS
	result, err := NewSniffer().sniffTLS(data)
	if err == nil && result != nil {
		return result.Domain
	}

	// Try HTTP
	result, err = NewSniffer().sniffHTTP(data)
	if err == nil && result != nil {
		return result.Domain
	}

	return ""
}
