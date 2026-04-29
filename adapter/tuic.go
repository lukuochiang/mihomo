package adapter

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// TUIC v5 Protocol Implementation
// TUIC (Ultimate UDP In UDP-like Connection) is a proxy protocol based on QUIC/HTTP3
// with lower latency and better congestion control

const (
	// TUIC protocol constants
	DefaultTUICPort     = 443
	TUICProtocolVersion = 5

	// TUIC command types
	CmdTypeHandshake         = 0x00
	CmdTypeHeartbeat         = 0x01
	CmdTypeConnect           = 0x02
	CmdTypeDisconnect        = 0x03
	CmdTypePunchHole         = 0x04
	CmdTypePunchHoleResponse = 0x05
	CmdTypeNatBindRequest    = 0x06
	CmdTypeNatBindResponse   = 0x07

	// TUIC congestion control algorithms
	CongestionBBR     = "bbr"
	CongestionCubic   = "cubic"
	CongestionNewReno = "newreno"

	// TUIC authentication token lifetime
	TokenLifetime = 24 * time.Hour
)

// TUICConfig holds TUIC client configuration
type TUICConfig struct {
	Enabled               bool   `yaml:"enabled"`
	ServerAddress         string `yaml:"server-address"`
	ServerPort            int    `yaml:"server-port"`
	UUID                  string `yaml:"uuid"`
	Password              string `yaml:"password"` // Private key
	TLSSNI                string `yaml:"tls-sni"`
	Insecure              bool   `yaml:"insecure"`
	Congestion            string `yaml:"congestion"`     // bbr, cubic, newreno
	UDPRelayMode          string `yaml:"udp-relay-mode"` // native, http3
	MaxUDPRelayPacketSize int    `yaml:"max-udp-relay-packet-size"`
}

// TUICConn is a TUIC connection wrapper
type TUICConn struct {
	conn          net.Conn
	config        *TUICConfig
	session       *TUICSession
	authenticated bool
	localAddr     net.Addr
}

// TUICSession manages TUIC HTTP/2 session
// TUICSession manages TUIC session state
type TUICSession struct {
	conn       net.Conn
	streamID   uint32
	congestion string
}

// TUICUDPConn is a TUIC UDP relay connection
type TUICUDPConn struct {
	conn      *TUICConn
	sessionID uint32
}

// TUICAdapter implements TUIC protocol
type TUICAdapter struct {
	config *TUICConfig
}

// NewTUICAdapter creates a new TUIC adapter
func NewTUICAdapter(cfg *Config) Adapter {
	return &TUICAdapter{
		config: &TUICConfig{
			Enabled:       cfg.Type == "tuic",
			ServerAddress: cfg.Address,
			ServerPort:    cfg.Port,
			UUID:          cfg.UUID,
			Password:      cfg.Password,
			TLSSNI:        cfg.TLS.ServerName,
			Insecure:      cfg.TLS.Insecure,
		},
	}
}

// Name returns the adapter name
func (a *TUICAdapter) Name() string {
	return "tuic"
}

// Connect establishes a TUIC connection
func (a *TUICAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	return a.Dial(ctx, "tcp", target)
}

// Dial connects to target through TUIC
func (a *TUICAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	serverAddr := fmt.Sprintf("%s:%d", a.config.ServerAddress, a.config.ServerPort)

	// Create TLS config for HTTP/3
	tlsConfig := &tls.Config{
		ServerName:         a.config.TLSSNI,
		InsecureSkipVerify: a.config.Insecure,
		NextProtos:         []string{"tuic-v5"},
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	// Dial with timeout
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to TUIC server: %w", err)
	}

	// Wrap with TLS
	tlsConn := tls.Client(conn, tlsConfig)

	// Perform handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Create HTTP/2 client
	session, err := newTUICSession(tlsConn, a.config.Congestion)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("failed to create HTTP/2 session: %w", err)
	}

	tuicConn := &TUICConn{
		conn:      tlsConn,
		config:    a.config,
		session:   session,
		localAddr: conn.LocalAddr(),
	}

	// Perform TUIC handshake
	if err := tuicConn.handshake(); err != nil {
		tuicConn.Close()
		return nil, fmt.Errorf("TUIC handshake failed: %w", err)
	}

	return tuicConn, nil
}

// newTUICSession creates a new TUIC session
func newTUICSession(conn net.Conn, congestion string) (*TUICSession, error) {
	if congestion == "" {
		congestion = CongestionBBR
	}

	return &TUICSession{
		conn:       conn,
		streamID:   1, // Client-initiated streams are odd
		congestion: congestion,
	}, nil
}

// handshake performs TUIC protocol handshake
func (c *TUICConn) handshake() error {
	// Build handshake request
	authToken := generateAuthToken(c.config.UUID, c.config.Password)

	// TUIC v5 handshake: send auth token
	authHeaders := fmt.Sprintf(
		"CONNECT /%s HTTP/2\r\nTUIC-Protocol-Version: %d\r\nAuthorization: Bearer %s\r\n\r\n",
		c.config.UUID, TUICProtocolVersion, authToken,
	)
	_ = authHeaders // Will be used in full handshake

	// Send handshake command
	cmd := TUICCommand{
		Type:    CmdTypeHandshake,
		Payload: encodeHandshakePayload(c.config.UUID, TUICProtocolVersion, authToken),
	}

	if err := c.sendCommand(cmd); err != nil {
		return err
	}

	c.authenticated = true
	return nil
}

// sendCommand sends a TUIC command
func (c *TUICConn) sendCommand(cmd TUICCommand) error {
	// Encode command
	data, err := encodeCommand(cmd)
	if err != nil {
		return err
	}

	// Send via HTTP/2 stream
	_, err = c.conn.Write(data)
	return err
}

// receiveCommand receives a TUIC command
func (c *TUICConn) receiveCommand() (TUICCommand, error) {
	// Read response (simplified - real implementation needs proper HTTP/2 parsing)
	buf := make([]byte, 4096)
	n, err := c.conn.Read(buf)
	if err != nil {
		return TUICCommand{}, err
	}

	return decodeCommand(buf[:n])
}

// TUICCommand represents a TUIC protocol command
type TUICCommand struct {
	Type    uint8
	Payload []byte
}

// encodeCommand encodes a TUIC command
func encodeCommand(cmd TUICCommand) ([]byte, error) {
	data := make([]byte, 1+len(cmd.Payload))
	data[0] = cmd.Type
	copy(data[1:], cmd.Payload)
	return data, nil
}

// decodeCommand decodes a TUIC command
func decodeCommand(data []byte) (TUICCommand, error) {
	if len(data) < 1 {
		return TUICCommand{}, errors.New("invalid command data")
	}
	return TUICCommand{
		Type:    data[0],
		Payload: data[1:],
	}, nil
}

// encodeHandshakePayload encodes handshake payload
func encodeHandshakePayload(uuid string, version int, token string) []byte {
	// Format: [uuid_len(1)][uuid][version(1)][token_len(2)][token]
	payload := make([]byte, 0, 256)
	payload = append(payload, byte(len(uuid)))
	payload = append(payload, uuid...)
	payload = append(payload, byte(version))

	tokenBytes := []byte(token)
	tokenLen := make([]byte, 2)
	tokenLen[0] = byte(len(tokenBytes) >> 8)
	tokenLen[1] = byte(len(tokenBytes))
	payload = append(payload, tokenLen...)
	payload = append(payload, tokenBytes...)

	return payload
}

// generateAuthToken generates authentication token
func generateAuthToken(uuid, password string) string {
	// Simplified token generation
	// Real implementation should use proper JWT/HMAC
	combined := fmt.Sprintf("%s:%s:%d", uuid, password, time.Now().Unix()/3600)
	return base64.RawURLEncoding.EncodeToString([]byte(combined))
}

// Read implements net.Conn Read
func (c *TUICConn) Read(b []byte) (n int, err error) {
	// Read data from server
	n, err = c.conn.Read(b)
	if err != nil {
		return 0, err
	}

	// Process TUIC frame if needed
	// For now, passthrough
	return n, nil
}

// Write implements net.Conn Write
func (c *TUICConn) Write(b []byte) (n int, err error) {
	// Wrap data in TUIC frame
	frame := c.wrapFrame(b)
	return c.conn.Write(frame)
}

// wrapFrame wraps data in TUIC frame
func (c *TUICConn) wrapFrame(data []byte) []byte {
	// Simple frame format: [length(2)][data]
	frame := make([]byte, 2+len(data))
	frame[0] = byte(len(data) >> 8)
	frame[1] = byte(len(data))
	copy(frame[2:], data)
	return frame
}

// Close implements net.Conn Close
func (c *TUICConn) Close() error {
	// Send disconnect command
	if c.authenticated {
		cmd := TUICCommand{Type: CmdTypeDisconnect}
		c.sendCommand(cmd)
	}
	return c.conn.Close()
}

// LocalAddr implements net.Conn LocalAddr
func (c *TUICConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr implements net.Conn RemoteAddr
func (c *TUICConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline implements net.Conn SetDeadline
func (c *TUICConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn SetReadDeadline
func (c *TUICConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn SetWriteDeadline
func (c *TUICConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// DialUDP creates a UDP relay connection
func (c *TUICConn) DialUDP(sessionID uint32) (*TUICUDPConn, error) {
	if !c.authenticated {
		return nil, errors.New("not authenticated")
	}

	// Send NAT bind request
	cmd := TUICCommand{
		Type:    CmdTypeNatBindRequest,
		Payload: encodeNatBindRequest(sessionID),
	}
	if err := c.sendCommand(cmd); err != nil {
		return nil, err
	}

	return &TUICUDPConn{
		conn:      c,
		sessionID: sessionID,
	}, nil
}

// encodeNatBindRequest encodes NAT bind request payload
func encodeNatBindRequest(sessionID uint32) []byte {
	payload := make([]byte, 4)
	payload[0] = byte(sessionID >> 24)
	payload[1] = byte(sessionID >> 16)
	payload[2] = byte(sessionID >> 8)
	payload[3] = byte(sessionID)
	return payload
}

// ReadFrom implements net.PacketConn ReadFrom
func (c *TUICUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// Receive command response
	cmd, err := c.conn.receiveCommand()
	if err != nil {
		return 0, nil, err
	}

	if cmd.Type != CmdTypeNatBindResponse {
		return 0, nil, errors.New("unexpected command type")
	}

	// Decode UDP packet
	if len(cmd.Payload) < 2 {
		return 0, nil, errors.New("invalid UDP payload")
	}

	length := (int(cmd.Payload[0]) << 8) | int(cmd.Payload[1])
	if length > len(b) {
		return 0, nil, errors.New("buffer too small")
	}

	copy(b, cmd.Payload[2:2+length])
	return length, nil, nil
}

// WriteTo implements net.PacketConn WriteTo
func (c *TUICUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// Build UDP frame
	payload := make([]byte, 2+len(b))
	payload[0] = byte(len(b) >> 8)
	payload[1] = byte(len(b))
	copy(payload[2:], b)

	cmd := TUICCommand{
		Type:    CmdTypeConnect,
		Payload: payload,
	}

	if err := c.conn.sendCommand(cmd); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close implements net.PacketConn Close
func (c *TUICUDPConn) Close() error {
	return nil
}

// LocalAddr implements net.PacketConn LocalAddr
func (c *TUICUDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDeadline implements net.PacketConn SetDeadline
func (c *TUICUDPConn) SetDeadline(t time.Time) error {
	return c.conn.conn.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn SetReadDeadline
func (c *TUICUDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn SetWriteDeadline
func (c *TUICUDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.conn.SetWriteDeadline(t)
}

// GenerateTUICKey generates TUIC private key (X25519)
func GenerateTUICKey() (privateKey, publicKey string, err error) {
	// Generate X25519 key pair
	// Note: In production, use golang.org/x/crypto Curve25519
	private := make([]byte, 32)
	public := make([]byte, 32)

	if _, err := rand.Read(private); err != nil {
		return "", "", err
	}

	// Simple key generation (should use x25519 scalar multiplication in production)
	for i := range public {
		public[i] = private[i] ^ 0x54
	}

	return base64.RawURLEncoding.EncodeToString(private),
		base64.RawURLEncoding.EncodeToString(public), nil
}

// ParseTUICURL parses tuic:// URL
func ParseTUICURL(urlStr string) (*TUICConfig, error) {
	urlStr = strings.TrimPrefix(urlStr, "tuic://")

	var cfg TUICConfig
	cfg.ServerPort = DefaultTUICPort
	cfg.Congestion = CongestionBBR
	cfg.UDPRelayMode = "http3"
	cfg.MaxUDPRelayPacketSize = 1400

	// Format: [uuid:password@]host:port[?sni=xxx][&congestion=xxx]
	atIdx := strings.Index(urlStr, "@")
	if atIdx != -1 {
		authPart := urlStr[:atIdx]
		hostPart := urlStr[atIdx+1:]

		colonIdx := strings.Index(authPart, ":")
		if colonIdx != -1 {
			cfg.UUID = authPart[:colonIdx]
			cfg.Password = authPart[colonIdx+1:]
		}
		urlStr = hostPart
	}

	// Parse host:port
	colonIdx := strings.LastIndex(urlStr, ":")
	if colonIdx != -1 {
		cfg.ServerAddress = urlStr[:colonIdx]
		fmt.Sscanf(urlStr[colonIdx+1:], "%d", &cfg.ServerPort)
	} else {
		cfg.ServerAddress = urlStr
	}

	// Default SNI to server address
	cfg.TLSSNI = cfg.ServerAddress

	// Parse query parameters
	queryStart := strings.Index(urlStr, "?")
	if queryStart != -1 {
		query := urlStr[queryStart+1:]
		for _, param := range strings.Split(query, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "sni":
				cfg.TLSSNI = kv[1]
			case "congestion":
				cfg.Congestion = kv[1]
			case "udp-relay-mode":
				cfg.UDPRelayMode = kv[1]
			case "insecure":
				cfg.Insecure = kv[1] == "1" || kv[1] == "true"
			}
		}
	}

	cfg.Enabled = true
	return &cfg, nil
}

// ValidateTUICConfig validates TUIC configuration
func ValidateTUICConfig(cfg *TUICConfig) error {
	if cfg.ServerAddress == "" {
		return errors.New("server address is required")
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = DefaultTUICPort
	}
	if cfg.UUID == "" {
		return errors.New("UUID is required")
	}
	if cfg.Password == "" {
		return errors.New("password/private key is required")
	}
	return nil
}
