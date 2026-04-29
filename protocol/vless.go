package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Protocol link prefix
const prefixVLESS = "vless://"

// VLESSProtocol implements VLESS protocol
type VLESSProtocol struct {
	config *VLESSConfig
}

// VLESSConfig holds VLESS configuration
type VLESSConfig struct {
	Address         string `json:"address"`
	Port            int    `json:"port"`
	UUID            string `json:"uuid"`
	Flow            string `json:"flow"`     // empty, xtls-rprx-origin, xtls-rprx-direct, etc.
	Network         string `json:"network"`  // tcp, ws, grpc, h2
	Security        string `json:"security"` // tls,reality,reality-aead
	TLS             TLSConfig
	WSPath          string            `json:"ws-path"`
	WSHeaders       map[string]string `json:"ws-headers"`
	GRPCServiceName string            `json:"grpc-service-name"`
	H2Path          string            `json:"h2-path"`
	H2Host          []string          `json:"h2-host"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled     bool
	ServerName  string
	Insecure    bool
	ALPN        []string
	Fingerprint string
	Reality     RealityConfig
}

// RealityConfig holds Reality configuration
type RealityConfig struct {
	Enabled   bool
	PublicKey string
	ShortID   string
}

// VLESSRequestHeader is the VLESS request header
type VLESSRequestHeader struct {
	Version     byte
	UUID        [16]byte
	Command     byte // 0x01: TCP, 0x02: UDP, 0x03: MUX
	Port        uint16
	AddressType byte // 0x01: IPv4, 0x02: Domain, 0x03: IPv6
	Address     []byte
}

// NewVLESSProtocol creates a new VLESS protocol handler
func NewVLESSProtocol(cfg *VLESSConfig) *VLESSProtocol {
	return &VLESSProtocol{config: cfg}
}

// Dial creates a VLESS connection
func (p *VLESSProtocol) Dial(target string) (net.Conn, error) {
	var conn net.Conn
	var err error

	// Determine network type
	switch p.config.Network {
	case "ws", "websocket":
		conn, err = p.dialWebSocket(target)
	case "grpc":
		conn, err = p.dialGRPC(target)
	case "h2", "http":
		conn, err = p.dialHTTP2(target)
	default:
		conn, err = p.dialTCP(target)
	}

	return conn, err
}

func (p *VLESSProtocol) dialTCP(target string) (net.Conn, error) {
	// Connect to server
	server := fmt.Sprintf("%s:%d", p.config.Address, p.config.Port)
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Apply TLS if enabled
	if p.config.Security == "tls" || p.config.Security == "reality" {
		tlsConfig := &tls.Config{
			ServerName:         p.config.TLS.ServerName,
			InsecureSkipVerify: p.config.TLS.Insecure,
		}

		if p.config.Security == "reality" {
			// Reality TLS
			tlsConfig.ServerName = p.config.TLS.Reality.PublicKey
			tlsConfig.InsecureSkipVerify = true
		}

		conn = tls.Client(conn, tlsConfig)
	}

	// Send VLESS header
	if err := p.sendRequest(conn, target); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (p *VLESSProtocol) dialWebSocket(target string) (net.Conn, error) {
	// First establish TCP connection
	server := fmt.Sprintf("%s:%d", p.config.Address, p.config.Port)
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Apply TLS if enabled
	if p.config.TLS.Enabled {
		tlsConfig := &tls.Config{
			ServerName:         p.config.TLS.ServerName,
			InsecureSkipVerify: p.config.TLS.Insecure,
			NextProtos:         []string{"http/1.1"},
		}
		conn = tls.Client(conn, tlsConfig)
	}

	// Perform WebSocket handshake
	wsPath := p.config.WSPath
	if wsPath == "" {
		wsPath = "/"
	}

	host := p.config.TLS.ServerName
	if host == "" {
		host = p.config.Address
	}

	// Build WebSocket upgrade request
	req := "GET " + wsPath + " HTTP/1.1\r\n"
	req += "Host: " + host + "\r\n"
	req += "Upgrade: websocket\r\n"
	req += "Connection: Upgrade\r\n"
	req += "Sec-WebSocket-Version: 13\r\n"
	req += "Sec-WebSocket-Key: " + generateWebSocketKey() + "\r\n"

	// Add custom headers
	for k, v := range p.config.WSHeaders {
		req += k + ": " + v + "\r\n"
	}

	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "101 Switching Protocols") {
		conn.Close()
		return nil, fmt.Errorf("WebSocket upgrade failed")
	}

	// Wrap with WebSocket
	return newWebSocketConn(conn, target), nil
}

func (p *VLESSProtocol) dialGRPC(target string) (net.Conn, error) {
	// gRPC uses HTTP/2, connect via TLS
	server := fmt.Sprintf("%s:%d", p.config.Address, p.config.Port)
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Apply TLS with HTTP/2 ALPN
	tlsConfig := &tls.Config{
		ServerName:         p.config.TLS.ServerName,
		InsecureSkipVerify: p.config.TLS.Insecure,
		NextProtos:         []string{"h2"},
	}
	conn = tls.Client(conn, tlsConfig)

	// TODO: Implement full gRPC transport
	return conn, nil
}

func (p *VLESSProtocol) dialHTTP2(target string) (net.Conn, error) {
	// HTTP/2 transport
	server := fmt.Sprintf("%s:%d", p.config.Address, p.config.Port)
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Apply TLS with HTTP/2
	tlsConfig := &tls.Config{
		ServerName:         p.config.TLS.ServerName,
		InsecureSkipVerify: p.config.TLS.Insecure,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	conn = tls.Client(conn, tlsConfig)

	return conn, nil
}

func (p *VLESSProtocol) sendRequest(conn net.Conn, target string) error {
	// Parse target
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Determine address type
	var addrType byte
	var addr []byte

	ip := net.ParseIP(host)
	if ip == nil {
		addrType = 0x02 // Domain
		addr = []byte{byte(len(host))}
		addr = append(addr, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		addrType = 0x01 // IPv4
		addr = ip4
	} else {
		addrType = 0x03 // IPv6
		addr = ip.To16()
	}

	// Build header
	header := VLESSRequestHeader{
		Version:     0,
		UUID:        parseUUIDString(p.config.UUID),
		Command:     0x01, // TCP
		Port:        port,
		AddressType: addrType,
		Address:     addr,
	}

	// Write header
	var buf bytes.Buffer
	buf.WriteByte(header.Version)
	buf.Write(header.UUID[:])
	buf.WriteByte(header.Command)
	binary.Write(&buf, binary.BigEndian, header.Port)
	buf.WriteByte(header.AddressType)
	buf.Write(header.Address)

	_, err = conn.Write(buf.Bytes())
	return err
}

// WebSocketConn wraps a connection with WebSocket framing
type WebSocketConn struct {
	conn     net.Conn
	target   string
	readBuf  []byte
	writeBuf []byte
}

// newWebSocketConn creates a new WebSocket connection
func newWebSocketConn(conn net.Conn, target string) *WebSocketConn {
	return &WebSocketConn{
		conn:     conn,
		target:   target,
		readBuf:  make([]byte, 65535),
		writeBuf: make([]byte, 65535),
	}
}

func (c *WebSocketConn) Read(b []byte) (int, error) {
	// Read WebSocket frame
	// This is a simplified implementation
	return c.conn.Read(b)
}

func (c *WebSocketConn) Write(b []byte) (int, error) {
	// Write WebSocket frame
	// This is a simplified implementation
	return c.conn.Write(b)
}

func (c *WebSocketConn) Close() error {
	// Send WebSocket close frame
	return c.conn.Close()
}

func (c *WebSocketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *WebSocketConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *WebSocketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *WebSocketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// WebSocket frame types
const (
	wsFrameCont   = 0x0
	wsFrameText   = 0x1
	wsFrameBinary = 0x2
	wsFrameClose  = 0x8
	wsFramePing   = 0x9
	wsFramePong   = 0xA
)

// Build WebSocket frame
func buildWSFrame(payload []byte, opcode byte) []byte {
	frame := make([]byte, 2+len(payload))
	frame[0] = 0x80 | opcode // FIN + opcode
	frame[1] = byte(len(payload))
	copy(frame[2:], payload)
	return frame
}

// Generate WebSocket key
func generateWebSocketKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// bufferConn implements net.Conn for bytes.Buffer
type bufferConn struct {
	data []byte
	pos  int
}

func (b *bufferConn) Read(p []byte) (n int, err error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n = copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func (b *bufferConn) Write(p []byte) (n int, err error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *bufferConn) Close() error {
	return nil
}

func (b *bufferConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (b *bufferConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (b *bufferConn) SetDeadline(t time.Time) error {
	return nil
}

func (b *bufferConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (b *bufferConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// ParseVLESSLink parses VLESS link configuration
func ParseVLESSLink(link string) (*VLESSConfig, error) {
	if !strings.HasPrefix(link, prefixVLESS) {
		return nil, fmt.Errorf("invalid VLESS link")
	}

	// vless://uuid@host:port?params#name
	rest := link[len(prefixVLESS):]
	atIdx := strings.Index(rest, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid VLESS link format")
	}

	uuid := rest[:atIdx]
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

		params = make(map[string]string)
		for _, pair := range strings.Split(paramsStr, "&") {
			kv := strings.Split(pair, "=")
			if len(kv) == 2 {
				params[kv[0]] = kv[1]
			}
		}
	} else {
		colonIdx := strings.LastIndex(serverInfo, ":")
		if colonIdx != -1 {
			host = serverInfo[:colonIdx]
			port = serverInfo[colonIdx+1:]
		}
	}

	var portNum int
	fmt.Sscanf(port, "%d", &portNum)

	cfg := &VLESSConfig{
		UUID:    uuid,
		Address: host,
		Port:    portNum,
		Network: "tcp",
	}

	// Parse params
	if network, ok := params["type"]; ok {
		cfg.Network = network
	}
	if flow, ok := params["flow"]; ok {
		cfg.Flow = flow
	}
	if sni, ok := params["sni"]; ok {
		cfg.TLS.ServerName = sni
	}
	if security, ok := params["security"]; ok {
		cfg.Security = security
	}
	if path, ok := params["path"]; ok {
		cfg.WSPath = path
	}
	if serviceName, ok := params["serviceName"]; ok {
		cfg.GRPCServiceName = serviceName
	}

	return cfg, nil
}

func parseUUIDString(s string) [16]byte {
	var uuid [16]byte
	uuid, _ = parseUUID(s)
	return uuid
}

// rand is imported from crypto/rand
var _ = rand.Read
