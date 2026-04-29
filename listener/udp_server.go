package listener

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mihomo/smart/core/outbound"
	"github.com/mihomo/smart/core/policy/smart"
)

// TUICServerConfig holds TUIC server configuration
type TUICServerConfig struct {
	Enabled               bool
	Port                  int
	Bind                  string
	Version               int        // 4 or 5
	Users                 []TUICUser // TUIC v5 users
	Token                 string     // TUIC v4 token
	CertFile              string
	KeyFile               string
	MaxUDPRelayPacketSize int
}

// TUICUser represents a TUIC user (v5)
type TUICUser struct {
	UUID     string
	Password string
}

// TUICServer represents a TUIC server
type TUICServer struct {
	config      *TUICServerConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	tlsConfig   *tls.Config
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewTUICServer creates a new TUIC server
func NewTUICServer(cfg *TUICServerConfig, dialer *outbound.Dialer, sm *smart.Smart) (*TUICServer, error) {
	server := &TUICServer{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	server.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"tuic"},
	}

	return server, nil
}

// Start starts the TUIC server
func (s *TUICServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.config.Enabled || s.closed {
		return nil
	}

	bind := s.config.Bind
	if bind == "" {
		bind = "0.0.0.0"
	}

	addr := fmt.Sprintf("%s:%d", bind, s.config.Port)

	ln, err := tls.Listen("tcp", addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = ln

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop()
	}()

	return nil
}

// Close closes the TUIC server
func (s *TUICServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.wg.Wait()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *TUICServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

func (s *TUICServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// TUIC protocol (simplified implementation)
	// Real TUIC uses QUIC over TLS, which is complex

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	// For TUIC v5, read authentication
	if s.config.Version == 5 {
		if !s.authenticateV5(tlsConn) {
			return
		}
	}

	// Read command frame
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	if err != nil {
		return
	}

	// Parse command
	// TUIC command format: [1 byte cmd_type] + [payload]
	cmdType := buf[0]
	if cmdType == 0x00 { // CONNECT command
		// Parse target address
		target, err := s.parseTargetAddress(buf[1:n])
		if err != nil {
			return
		}

		// Get selected node
		nodeName := s.getSelectedNode()

		// Connect to target
		targetConn, err := s.dialer.Dial(context.Background(), nodeName, target)
		if err != nil {
			return
		}
		defer targetConn.Close()

		// Send connect response
		tlsConn.Write([]byte{0x00, 0x00}) // Success response

		// Bridge connections
		bridgeConns(tlsConn, targetConn)
	}
}

func (s *TUICServer) authenticateV5(conn *tls.Conn) bool {
	// TUIC v5 authentication:
	// Client sends: [1 byte auth_type] + [username] + [password]
	// Server validates against configured users

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	if n < 3 {
		return false
	}

	authType := buf[0]
	if authType != 0x01 { // USER_PASS_AUTH
		return false
	}

	// Read username length and username
	usernameLen := int(buf[1])
	if n < 2+usernameLen+1 {
		return false
	}
	username := string(buf[2 : 2+usernameLen])

	// Read password length and password
	passwordStart := 2 + usernameLen
	passwordLen := int(buf[passwordStart])
	if n < passwordStart+1+passwordLen {
		return false
	}
	password := string(buf[passwordStart+1 : passwordStart+1+passwordLen])

	// Validate against configured users
	for _, user := range s.config.Users {
		if user.UUID == username && user.Password == password {
			return true
		}
	}

	return false
}

func (s *TUICServer) parseTargetAddress(data []byte) (string, error) {
	if len(data) < 3 {
		return "", errors.New("address too short")
	}

	addrType := data[0]
	var host string
	var port int

	switch addrType {
	case 0x01: // IPv4
		if len(data) < 7 {
			return "", errors.New("invalid IPv4 address")
		}
		host = fmt.Sprintf("%d.%d.%d.%d", data[1], data[2], data[3], data[4])
		port = int(data[5])<<8 | int(data[6])

	case 0x03: // Domain
		domainLen := int(data[1])
		if len(data) < 2+domainLen+2 {
			return "", errors.New("invalid domain address")
		}
		host = string(data[2 : 2+domainLen])
		port = int(data[2+domainLen])<<8 | int(data[2+domainLen+1])

	case 0x04: // IPv6
		if len(data) < 19 {
			return "", errors.New("invalid IPv6 address")
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			data[1:3], data[3:5], data[5:7], data[7:9],
			data[9:11], data[11:13], data[13:15], data[15:17])
		port = int(data[17])<<8 | int(data[18])
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *TUICServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

// ============ Hysteria2 Server ============

// Hysteria2ServerConfig holds Hysteria2 server configuration
type Hysteria2ServerConfig struct {
	Enabled  bool
	Port     int
	Bind     string
	Auth     Hysteria2Auth
	CertFile string
	KeyFile  string
	UpMbps   int    // Upload bandwidth limit
	DownMbps int    // Download bandwidth limit
	Obfs     string // Obfuscation password
}

// Hysteria2Auth holds Hysteria2 authentication config
type Hysteria2Auth struct {
	Type     string // "password" or "ExternalAuth"
	Password string
}

// Hysteria2Server represents a Hysteria2 server
type Hysteria2Server struct {
	config      *Hysteria2ServerConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	tlsConfig   *tls.Config
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewHysteria2Server creates a new Hysteria2 server
func NewHysteria2Server(cfg *Hysteria2ServerConfig, dialer *outbound.Dialer, sm *smart.Smart) (*Hysteria2Server, error) {
	server := &Hysteria2Server{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	server.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"hysteria2"},
	}

	return server, nil
}

// Start starts the Hysteria2 server
func (s *Hysteria2Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.config.Enabled || s.closed {
		return nil
	}

	bind := s.config.Bind
	if bind == "" {
		bind = "0.0.0.0"
	}

	addr := fmt.Sprintf("%s:%d", bind, s.config.Port)

	ln, err := tls.Listen("tcp", addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = ln

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop()
	}()

	return nil
}

// Close closes the Hysteria2 server
func (s *Hysteria2Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.wg.Wait()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Hysteria2Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

func (s *Hysteria2Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Hysteria2 protocol:
	// 1. Client sends auth frame (with password)
	// 2. Server validates
	// 3. Client sends connect request

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	// Read auth frame
	// Hysteria2 uses its own framing over QUIC
	// Simplified: read password authentication

	// Read frame header: [2 bytes length] + [1 byte frame type]
	header := make([]byte, 3)
	if _, err := io.ReadFull(tlsConn, header); err != nil {
		return
	}

	frameLen := binary.BigEndian.Uint16(header[:2])
	frameType := header[2]

	if frameType != 0x01 { // AUTH frame
		return
	}

	// Read auth payload
	authData := make([]byte, frameLen-1)
	if _, err := io.ReadFull(tlsConn, authData); err != nil {
		return
	}

	// Parse auth (simplified)
	// Format: [1 byte auth_type] + [auth_data]
	if len(authData) < 2 {
		return
	}

	authType := authData[0]
	if authType == 0x01 { // Password auth
		passwordLen := int(authData[1])
		if len(authData) < 2+passwordLen {
			return
		}
		password := string(authData[2 : 2+passwordLen])

		if password != s.config.Auth.Password {
			// Send auth fail response
			tlsConn.Write([]byte{0x00, 0x02})
			return
		}
	}

	// Send auth success
	tlsConn.Write([]byte{0x00, 0x00})

	// Read connect request
	reqHeader := make([]byte, 3)
	if _, err := io.ReadFull(tlsConn, reqHeader); err != nil {
		return
	}

	reqLen := binary.BigEndian.Uint16(reqHeader[:2])
	reqType := reqHeader[2]

	if reqType != 0x03 { // CONNECT request
		return
	}

	// Read connect payload
	reqData := make([]byte, reqLen-1)
	if _, err := io.ReadFull(tlsConn, reqData); err != nil {
		return
	}

	// Parse target address
	target, err := s.parseTargetAddress(reqData)
	if err != nil {
		return
	}

	// Get selected node
	nodeName := s.getSelectedNode()

	// Connect to target
	targetConn, err := s.dialer.Dial(context.Background(), nodeName, target)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Send connect response
	tlsConn.Write([]byte{0x00, 0x00})

	// Bridge connections
	bridgeConns(tlsConn, targetConn)
}

func (s *Hysteria2Server) parseTargetAddress(data []byte) (string, error) {
	if len(data) < 3 {
		return "", errors.New("address too short")
	}

	addrType := data[0]
	var host string
	var port int

	switch addrType {
	case 0x01: // IPv4
		if len(data) < 7 {
			return "", errors.New("invalid IPv4 address")
		}
		host = fmt.Sprintf("%d.%d.%d.%d", data[1], data[2], data[3], data[4])
		port = int(data[5])<<8 | int(data[6])

	case 0x03: // Domain
		domainLen := int(data[1])
		if len(data) < 2+domainLen+2 {
			return "", errors.New("invalid domain address")
		}
		host = string(data[2 : 2+domainLen])
		port = int(data[2+domainLen])<<8 | int(data[2+domainLen+1])

	case 0x04: // IPv6
		if len(data) < 19 {
			return "", errors.New("invalid IPv6 address")
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			data[1:3], data[3:5], data[5:7], data[7:9],
			data[9:11], data[11:13], data[13:15], data[15:17])
		port = int(data[17])<<8 | int(data[18])
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *Hysteria2Server) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}
