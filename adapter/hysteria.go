package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Hysteria v2 Protocol Implementation
// Hysteria is a proxy protocol based on QUIC with BBR congestion control
// for maximum bandwidth utilization while mimicking HTTPS traffic

const (
	// Hysteria protocol version
	HysteriaVersion2 = 0x0002

	// Default ports
	DefaultHysteriaPort = 443

	// Control message types
	MsgTypePing       = 0x01
	MsgTypePong       = 0x02
	MsgTypeConnect    = 0x03
	MsgTypeConnected  = 0x04
	MsgTypeDisconnect = 0x05
	MsgTypeUDPFrame   = 0x06
	MsgTypeTCPSplice  = 0x07

	// UDP Frame flags
	UDPFlagEnd  = 0x01
	UDPFlagMore = 0x02
)

// HysteriaConfig holds Hysteria client configuration
type HysteriaConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ServerAddress string `yaml:"server-address"`
	ServerPort    int    `yaml:"server-port"`
	Auth          string `yaml:"auth"`          // Password or authentication string
	ObfsPassword  string `yaml:"obfs-password"` // Obfuscation password
	SNI           string `yaml:"sni"`           // TLS Server Name Indication
	Insecure      bool   `yaml:"insecure"`
	CA            string `yaml:"ca"`       // Custom CA certificate
	Protocol      string `yaml:"protocol"` // "hysteria2"
}

// HysteriaConn is a Hysteria connection wrapper
type HysteriaConn struct {
	conn      net.Conn
	config    *HysteriaConfig
	obfsKey   []byte
	localAddr net.Addr
}

// HysteriaUDPConn is a Hysteria UDP connection
type HysteriaUDPConn struct {
	conn      *HysteriaConn
	sessionID uint32
}

// HysteriaAdapter implements Hysteria protocol
type HysteriaAdapter struct {
	config *HysteriaConfig
}

// NewHysteriaAdapter creates a new Hysteria adapter
func NewHysteriaAdapter(cfg *Config) Adapter {
	return &HysteriaAdapter{
		config: &HysteriaConfig{
			Enabled:       cfg.Type == "hysteria" || cfg.Type == "hysteria2",
			ServerAddress: cfg.Address,
			ServerPort:    cfg.Port,
			Auth:          cfg.Password,
			SNI:           cfg.TLS.ServerName,
			Insecure:      cfg.TLS.Insecure,
		},
	}
}

// Name returns the adapter name
func (a *HysteriaAdapter) Name() string {
	return "hysteria"
}

// Connect establishes a Hysteria connection
func (a *HysteriaAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	return a.Dial(ctx, "tcp", target)
}

// Dial connects to target through Hysteria
func (a *HysteriaAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	serverAddr := fmt.Sprintf("%s:%d", a.config.ServerAddress, a.config.ServerPort)

	// Create TLS config
	tlsConfig := &tls.Config{
		ServerName:         a.config.SNI,
		InsecureSkipVerify: a.config.Insecure,
		NextProtos:         []string{"hysteria/2"},
		MinVersion:         tls.VersionTLS13,
	}

	// Custom dialer with timeout
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	// Dial QUIC-equivalent connection (simulated with TLS for v2)
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Hysteria server: %w", err)
	}

	// Wrap with TLS
	tlsConn := tls.Client(conn, tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Generate obfuscation key if configured
	var obfsKey []byte
	if a.config.ObfsPassword != "" {
		obfsKey = deriveOBFSKey(a.config.ObfsPassword)
	}

	hConn := &HysteriaConn{
		conn:      tlsConn,
		config:    a.config,
		obfsKey:   obfsKey,
		localAddr: conn.LocalAddr(),
	}

	// Send authentication
	if err := hConn.authenticate(); err != nil {
		hConn.Close()
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return hConn, nil
}

// authenticate sends authentication to Hysteria server
func (c *HysteriaConn) authenticate() error {
	// Build auth request: [version(2)][auth_len(2)][auth_data]
	authData := []byte(c.config.Auth)
	authLen := make([]byte, 2)
	binary.BigEndian.PutUint16(authLen, uint16(len(authData)))

	packet := make([]byte, 2+2+len(authData))
	binary.BigEndian.PutUint16(packet[0:2], HysteriaVersion2)
	copy(packet[2:4], authLen)
	copy(packet[4:], authData)

	// Apply obfuscation if configured
	if c.obfsKey != nil {
		packet = c.obfuscate(packet)
	}

	_, err := c.conn.Write(packet)
	return err
}

// obfuscate applies obfuscation to data
func (c *HysteriaConn) obfuscate(data []byte) []byte {
	if c.obfsKey == nil {
		return data
	}
	// Simple XOR obfuscation with key stretching
	result := make([]byte, len(data))
	keyStream := generateKeyStream(c.obfsKey, len(data))
	for i := range data {
		result[i] = data[i] ^ keyStream[i]
	}
	return result
}

// deobfuscate removes obfuscation from data
func (c *HysteriaConn) deobfuscate(data []byte) []byte {
	return c.obfuscate(data) // XOR is symmetric
}

// generateKeyStream generates pseudo-random key stream
func generateKeyStream(key []byte, length int) []byte {
	result := make([]byte, length)
	state := make([]byte, 32)
	copy(state, key)

	for i := 0; i < length; i++ {
		// Simple PRG based on mixing
		for j := 0; j < 32; j++ {
			state[j] ^= state[(j+1)%32] ^ byte(i+j)
		}
		result[i] = state[i%32]
	}
	return result
}

// deriveOBFSKey derives obfuscation key from password using SHA256
func deriveOBFSKey(password string) []byte {
	// Simple key derivation using SHA256
	h := sha256.New()
	h.Write([]byte(password))
	h.Write([]byte("hysteria-obfs"))
	sum := h.Sum(nil)
	key := make([]byte, 32)
	copy(key, sum)
	return key
}

// Read implements net.Conn Read
func (c *HysteriaConn) Read(b []byte) (n int, err error) {
	// Read length prefix (4 bytes)
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, err
	}

	// Deobfuscate header
	if c.obfsKey != nil {
		header = c.deobfuscate(header)
	}

	length := binary.BigEndian.Uint32(header)
	if length > uint32(len(b)) {
		return 0, errors.New("buffer too small")
	}

	// Read payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return 0, err
	}

	// Deobfuscate payload
	if c.obfsKey != nil {
		payload = c.deobfuscate(payload)
	}

	copy(b, payload)
	return int(length), nil
}

// Write implements net.Conn Write
func (c *HysteriaConn) Write(b []byte) (n int, err error) {
	// Build packet: [length(4)][payload]
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(b)))

	payload := make([]byte, 4+len(b))
	copy(payload[0:4], length)
	copy(payload[4:], b)

	// Obfuscate if configured
	if c.obfsKey != nil {
		header := c.obfuscate(length)
		body := c.obfuscate(b)
		payload = make([]byte, 4+len(body))
		copy(payload[0:4], header)
		copy(payload[4:], body)
	}

	_, err = c.conn.Write(payload)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close implements net.Conn Close
func (c *HysteriaConn) Close() error {
	// Send disconnect message
	if c.obfsKey != nil {
		msg := []byte{MsgTypeDisconnect}
		msg = c.obfuscate(msg)
		c.conn.Write(msg)
	}
	return c.conn.Close()
}

// LocalAddr implements net.Conn LocalAddr
func (c *HysteriaConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr implements net.Conn RemoteAddr
func (c *HysteriaConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline implements net.Conn SetDeadline
func (c *HysteriaConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn SetReadDeadline
func (c *HysteriaConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn SetWriteDeadline
func (c *HysteriaConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// DialUDP creates a UDP connection through Hysteria
func (c *HysteriaConn) DialUDP() (*HysteriaUDPConn, error) {
	// Generate session ID
	sessionID := make([]byte, 4)
	rand.Read(sessionID)

	return &HysteriaUDPConn{
		conn:      c,
		sessionID: binary.BigEndian.Uint32(sessionID),
	}, nil
}

// ReadFrom implements net.PacketConn ReadFrom
func (c *HysteriaUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// Read UDP frame header
	header := make([]byte, 8)
	if _, err := io.ReadFull(c.conn.conn, header); err != nil {
		return 0, nil, err
	}

	// Deobfuscate
	if c.conn.obfsKey != nil {
		header = c.conn.deobfuscate(header)
	}

	sessionID := binary.BigEndian.Uint32(header[0:4])
	_ = header[4] // flags field (UDPFlagEnd/UDPFlagMore)
	length := binary.BigEndian.Uint16(header[5:7])

	if sessionID != c.sessionID {
		return 0, nil, errors.New("session ID mismatch")
	}

	if length > uint16(len(b)) {
		return 0, nil, errors.New("buffer too small")
	}

	// Read payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.conn.conn, payload); err != nil {
		return 0, nil, err
	}

	if c.conn.obfsKey != nil {
		payload = c.conn.deobfuscate(payload)
	}

	copy(b, payload)
	return int(length), nil, nil
}

// WriteTo implements net.PacketConn WriteTo
func (c *HysteriaUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// Build UDP frame: [session_id(4)][flags(1)][length(2)][payload]
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(b)))

	frame := make([]byte, 7+len(b))
	sessionIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sessionIDBytes, c.sessionID)
	copy(frame[0:4], sessionIDBytes)
	frame[4] = UDPFlagEnd
	copy(frame[5:7], length)
	copy(frame[7:], b)

	// Obfuscate
	if c.conn.obfsKey != nil {
		header := c.conn.obfuscate(frame[0:7])
		body := c.conn.obfuscate(b)
		frame = make([]byte, 7+len(body))
		copy(frame[0:7], header)
		copy(frame[7:], body)
	}

	_, err = c.conn.conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close implements net.PacketConn Close
func (c *HysteriaUDPConn) Close() error {
	return nil // Connection managed by underlying TCP conn
}

// LocalAddr implements net.PacketConn LocalAddr
func (c *HysteriaUDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDeadline implements net.PacketConn SetDeadline
func (c *HysteriaUDPConn) SetDeadline(t time.Time) error {
	return c.conn.conn.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn SetReadDeadline
func (c *HysteriaUDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn SetWriteDeadline
func (c *HysteriaUDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.conn.SetWriteDeadline(t)
}

// GenerateHysteriaKey generates a new Hysteria key pair
func GenerateHysteriaKey() (privateKey, publicKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

// ParseHysteriaURL parses hysteria:// or hysteria2:// URL
func ParseHysteriaURL(urlStr string) (*HysteriaConfig, error) {
	var cfg HysteriaConfig

	// Support both hysteria:// and hysteria2:// formats
	urlStr = strings.TrimPrefix(urlStr, "hysteria://")
	urlStr = strings.TrimPrefix(urlStr, "hysteria2://")

	// Format: [auth@]host:port[?sni=xxx][&obfs=xxx]
	parts := strings.SplitN(urlStr, "@", 2)

	var hostPart string
	if len(parts) == 2 {
		cfg.Auth = parts[0]
		hostPart = parts[1]
	} else {
		cfg.Auth = ""
		hostPart = parts[0]
	}

	// Parse host:port
	hostPortIdx := strings.LastIndex(hostPart, ":")
	if hostPortIdx == -1 {
		return nil, errors.New("invalid hysteria URL: missing port")
	}

	cfg.ServerAddress = hostPart[:hostPortIdx]
	var port int
	fmt.Sscanf(hostPart[hostPortIdx+1:], "%d", &port)
	cfg.ServerPort = port

	// Default SNI to server address
	cfg.SNI = cfg.ServerAddress

	// Parse query parameters
	queryStart := strings.Index(hostPart, "?")
	if queryStart != -1 {
		query := hostPart[queryStart+1:]
		for _, param := range strings.Split(query, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "sni":
				cfg.SNI = kv[1]
			case "obfs":
				cfg.ObfsPassword = kv[1]
			case "insecure":
				cfg.Insecure = kv[1] == "1" || kv[1] == "true"
			}
		}
	}

	cfg.Enabled = true
	cfg.Protocol = "hysteria2"
	return &cfg, nil
}

// ValidateHysteriaConfig validates Hysteria configuration
func ValidateHysteriaConfig(cfg *HysteriaConfig) error {
	if cfg.ServerAddress == "" {
		return errors.New("server address is required")
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = DefaultHysteriaPort
	}
	if cfg.Auth == "" {
		return errors.New("authentication is required")
	}
	return nil
}
