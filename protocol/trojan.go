package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"crypto/tls"
)

// Protocol link prefix
const prefixTrojan = "trojan://"

// TrojanProtocol implements Trojan protocol
type TrojanProtocol struct {
	config *TrojanConfig
}

// TrojanConfig holds Trojan configuration
type TrojanConfig struct {
	Address     string   `json:"address"`
	Port        int      `json:"port"`
	Password    string   `json:"password"`
	TLSSNI      string   `json:"sni"`
	TLSALPN     []string `json:"alpn"`
	TLSVersion  string   `json:"tls-version"`
	Fingerprint string   `json:"fingerprint"`
	UDP         bool     `json:"udp"`
}

// TrojanSession represents a Trojan session
type TrojanSession struct {
	password []byte
}

// NewTrojanProtocol creates a new Trojan protocol handler
func NewTrojanProtocol(cfg *TrojanConfig) *TrojanProtocol {
	return &TrojanProtocol{config: cfg}
}

// Dial creates a Trojan connection
func (p *TrojanProtocol) Dial(target string) (net.Conn, error) {
	server := fmt.Sprintf("%s:%d", p.config.Address, p.config.Port)
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS
	tlsConfig := &tls.Config{
		ServerName:         p.getSNI(),
		InsecureSkipVerify: false,
		NextProtos:         p.getALPN(),
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Send Trojan request
	if err := p.sendRequest(tlsConn, target); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (p *TrojanProtocol) getSNI() string {
	if p.config.TLSSNI != "" {
		return p.config.TLSSNI
	}
	return p.config.Address
}

func (p *TrojanProtocol) getALPN() []string {
	if len(p.config.TLSALPN) > 0 {
		return p.config.TLSALPN
	}
	return []string{"h2", "http/1.1"}
}

// Trojan request format:
// password@address:port\r\n
// Or with SNI:
// password@address:port?sni=xxx\r\n
func (p *TrojanProtocol) sendRequest(conn *tls.Conn, target string) error {
	_, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Build request
	sni := p.getSNI()
	_ = sni
	_ = port
	request := fmt.Sprintf("%s@%s:%d", p.config.Password, sni, p.config.Port)

	// Add CRLF
	request += "\r\n"

	// Send request
	_, err = conn.Write([]byte(request))
	return err
}

// TrojanConnection wraps a Trojan connection
type TrojanConnection struct {
	conn    *tls.Conn
	session *TrojanSession
}

// Read reads data
func (c *TrojanConnection) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

// Write writes data
func (c *TrojanConnection) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

// Close closes the connection
func (c *TrojanConnection) Close() error {
	return c.conn.Close()
}

// LocalAddr returns local address
func (c *TrojanConnection) LocalAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (c *TrojanConnection) RemoteAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

// SetDeadline sets deadline
func (c *TrojanConnection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *TrojanConnection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *TrojanConnection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// ParseTrojanLink parses Trojan link configuration
func ParseTrojanLink(link string) (*TrojanConfig, error) {
	if !strings.HasPrefix(link, prefixTrojan) {
		return nil, fmt.Errorf("invalid Trojan link")
	}

	// trojan://password@host:port?params#name
	rest := link[len(prefixTrojan):]
	atIdx := strings.Index(rest, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid Trojan link format")
	}

	password := rest[:atIdx]
	serverInfo := rest[atIdx+1:]

	// Parse server info
	hashIdx := strings.Index(serverInfo, "#")
	if hashIdx != -1 {
		serverInfo = serverInfo[:hashIdx]
	}

	// Parse query parameters
	queryIdx := strings.Index(serverInfo, "?")
	var host, port string
	var params map[string]string

	if queryIdx != -1 {
		hostPort := serverInfo[:queryIdx]
		paramsStr := serverInfo[queryIdx+1:]

		colonIdx := strings.LastIndex(hostPort, ":")
		if colonIdx != -1 {
			host = hostPort[:colonIdx]
			port = hostPort[colonIdx+1:]
		}

		params = parseQueryString(paramsStr)
	} else {
		colonIdx := strings.LastIndex(serverInfo, ":")
		if colonIdx != -1 {
			host = serverInfo[:colonIdx]
			port = serverInfo[colonIdx+1:]
		}
	}

	var portNum int
	fmt.Sscanf(port, "%d", &portNum)

	if portNum == 0 {
		return nil, fmt.Errorf("missing or invalid port")
	}

	cfg := &TrojanConfig{
		Password: password,
		Address:  host,
		Port:     portNum,
	}

	// Parse params
	if sni, ok := params["sni"]; ok {
		cfg.TLSSNI = sni
	}
	if alpn, ok := params["alpn"]; ok {
		cfg.TLSALPN = strings.Split(alpn, ",")
	}
	if udp, ok := params["udp"]; ok {
		cfg.UDP = udp == "true"
	}

	return cfg, nil
}

func parseQueryString(query string) map[string]string {
	params := make(map[string]string)
	for _, pair := range strings.Split(query, "&") {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		}
	}
	return params
}

// TrojanProxySession handles Trojan session
type TrojanProxySession struct {
	conn     net.Conn
	target   string
	password []byte
}

// NewTrojanProxySession creates a new Trojan proxy session
func NewTrojanProxySession(conn net.Conn, password string) *TrojanProxySession {
	return &TrojanProxySession{
		conn:     conn,
		password: []byte(password),
	}
}

// Handle handles the Trojan session
func (s *TrojanProxySession) Handle() error {
	// Read request line
	buf := make([]byte, 256)
	n, err := s.conn.Read(buf)
	if err != nil {
		return err
	}

	data := string(buf[:n])
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return fmt.Errorf("invalid request")
	}

	// Parse command
	parts := strings.Split(lines[0], "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid command")
	}

	password := parts[0]
	target := parts[1]

	// Verify password
	if !hmac.Equal([]byte(password), s.password) {
		return fmt.Errorf("invalid password")
	}

	s.target = target
	return nil
}

// GetTarget returns the target address
func (s *TrojanProxySession) GetTarget() string {
	return s.target
}

// GetConn returns the connection
func (s *TrojanProxySession) GetConn() net.Conn {
	return s.conn
}

// TrojanCommand represents Trojan protocol command
type TrojanCommand struct {
	Version     byte
	Command     byte // 0x01: TCP connect, 0x02: UDP associate
	Address     []byte
	AddressType byte
	Port        uint16
	Password    []byte
}

// BuildCommand builds Trojan command
func BuildCommand(cmd byte, address string, port uint16, password string) *TrojanCommand {
	// Extract host from address, handling IPv6 in brackets [IPv6]:port
	host := address
	if strings.HasPrefix(address, "[") {
		// IPv6 format: [::1]:443
		if idx := strings.LastIndex(address, "]"); idx > 0 {
			host = address[1:idx]
		}
	} else {
		// Regular format: host:port or IPv4:port
		var portStr string
		if h, p, err := net.SplitHostPort(address); err == nil {
			host = h
			portStr = p
		}
		_ = portStr
	}

	addrType := byte(0x03) // Default to Domain
	var addr []byte

	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		addrType = 0x03
		addr = []byte{byte(len(host))}
		addr = append(addr, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		addrType = 0x01
		addr = ip4
	} else {
		// IPv6
		addrType = 0x04
		addr = ip.To16()
	}

	return &TrojanCommand{
		Version:     0x01,
		Command:     cmd,
		Address:     addr,
		AddressType: addrType,
		Port:        port,
		Password:    []byte(password),
	}
}

// GeneratePasswordHash generates SHA256 hash of password
func GeneratePasswordHash(password string) string {
	h := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(h[:])
}
