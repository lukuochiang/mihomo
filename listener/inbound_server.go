package listener

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mihomo/smart/core/outbound"
	"github.com/mihomo/smart/core/policy/smart"
)

// VMessServerConfig holds VMess server configuration
type VMessServerConfig struct {
	Enabled bool
	Port    int
	Bind    string
	Users   []VMessUser // VMess users with UUID and alterId
}

// VMessUser represents a VMess user
type VMessUser struct {
	Username string // Alias/name for the user
	UUID     string
	AlterId  int
}

// VLESSServerConfig holds VLESS server configuration
type VLESSServerConfig struct {
	Enabled   bool
	Port      int
	Bind      string
	Users     []VLESSUser
	CertFile  string
	KeyFile   string
	TLSConfig *TLSConfig
}

// VLESSUser represents a VLESS user
type VLESSUser struct {
	UUID string
	Name string
}

// TrojanServerConfig holds Trojan server configuration
type TrojanServerConfig struct {
	Enabled  bool
	Port     int
	Bind     string
	Password string
	CertFile string
	KeyFile  string
}

// TLSConfig holds TLS server configuration
type TLSConfig struct {
	Enabled    bool
	CertFile   string
	KeyFile    string
	ServerName string
}

// VMessServer represents a VMess server
type VMessServer struct {
	config      *VMessServerConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewVMessServer creates a new VMess server
func NewVMessServer(cfg *VMessServerConfig, dialer *outbound.Dialer, sm *smart.Smart) *VMessServer {
	return &VMessServer{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}
}

// Start starts the VMess server
func (s *VMessServer) Start() error {
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
	ln, err := net.Listen("tcp", addr)
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

// Close closes the VMess server
func (s *VMessServer) Close() error {
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

func (s *VMessServer) acceptLoop() {
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

func (s *VMessServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read first byte - version (must be 1 for VMess)
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return
	}
	if version[0] != 1 {
		return
	}

	// Read header
	// [1 byte version] + [16 bytes IV/method] + [16+ bytes encrypted header]
	headerBuf := make([]byte, 38) // 1 + 16 + 21 minimum header
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return
	}

	// Find matching user by trying all users
	var authenticated bool
	var targetAddr string

	for _, user := range s.config.Users {
		// Try to decrypt header with this user's key
		addr, ok := s.tryDecryptHeader(headerBuf, user.UUID, user.AlterId)
		if ok {
			targetAddr = addr
			authenticated = true
			break
		}
	}

	if !authenticated {
		return
	}

	// Get selected node
	nodeName := s.getSelectedNode()

	// Connect to target
	targetConn, err := s.dialer.Dial(context.Background(), nodeName, targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Bridge connections
	bridgeConns(conn, targetConn)
}

func (s *VMessServer) tryDecryptHeader(data []byte, uuid string, alterId int) (string, bool) {
	// VMess header decryption is complex
	// For simplicity, this is a placeholder that returns false
	// Real implementation would:
	// 1. Derive key from UUID
	// 2. Decrypt the header
	// 3. Parse the decrypted header for target address
	return "", false
}

func (s *VMessServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

// ============ VLESS Server ============

// VLESSServer represents a VLESS server
type VLESSServer struct {
	config      *VLESSServerConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	server      *http.Server
	tlsConfig   *tls.Config
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewVLESSServer creates a new VLESS server
func NewVLESSServer(cfg *VLESSServerConfig, dialer *outbound.Dialer, sm *smart.Smart) (*VLESSServer, error) {
	server := &VLESSServer{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}

	// Setup TLS if enabled
	if cfg.TLSConfig != nil && cfg.TLSConfig.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLSConfig.CertFile, cfg.TLSConfig.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		server.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	return server, nil
}

// Start starts the VLESS server
func (s *VLESSServer) Start() error {
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

	// Setup HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	s.server = &http.Server{
		Handler: mux,
		Addr:    addr,
	}

	var err error
	if s.tlsConfig != nil {
		s.listener, err = tls.Listen("tcp", addr, s.tlsConfig)
	} else {
		s.listener, err = net.Listen("tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.server.Serve(s.listener)
	}()

	return nil
}

// Close closes the VLESS server
func (s *VLESSServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *VLESSServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// VLESS protocol: UUID is sent in the HTTP Host header or as query parameter
	// Format: vless://uuid@host:port

	// Extract UUID from the request
	// VLESS over TLS uses the UUID as user identification
	uuid := s.extractUUID(r)
	if uuid == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify UUID is valid
	if !s.isValidUUID(uuid) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// For VLESS, the target address is specified by the client
	// It can be in the query string or the request Host header
	targetHost := r.Host
	if v := r.URL.Query().Get("host"); v != "" {
		targetHost = v
	}

	// Get selected node
	nodeName := s.getSelectedNode()

	// Connect to target
	target := targetHost
	if !strings.Contains(target, ":") {
		if r.URL.Scheme == "https" || r.TLS != nil {
			target = fmt.Sprintf("%s:443", target)
		} else {
			target = fmt.Sprintf("%s:80", target)
		}
	}

	targetConn, err := s.dialer.Dial(context.Background(), nodeName, target)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// For HTTP CONNECT-like behavior
	if r.Method == http.MethodConnect {
		// Send 200 Connection Established
		w.WriteHeader(http.StatusOK)
		// Bridge connections
		bridgeConnsHijack(w, r, targetConn)
	} else {
		// Forward HTTP request
		// This is simplified - real implementation would handle HTTP properly
		bridgeConnsHijack(w, r, targetConn)
	}
}

func (s *VLESSServer) extractUUID(r *http.Request) string {
	// Try to extract UUID from query parameter
	if u := r.URL.Query().Get("uuid"); u != "" {
		return u
	}

	// Try to extract from Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}

	// VLESS may also use the Host header for UUID in some configurations
	return ""
}

func (s *VLESSServer) isValidUUID(uuid string) bool {
	for _, user := range s.config.Users {
		if user.UUID == uuid {
			return true
		}
	}
	return false
}

func (s *VLESSServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

// ============ Trojan Server ============

// TrojanServer represents a Trojan server
type TrojanServer struct {
	config      *TrojanServerConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	tlsConfig   *tls.Config
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewTrojanServer creates a new Trojan server
func NewTrojanServer(cfg *TrojanServerConfig, dialer *outbound.Dialer, sm *smart.Smart) (*TrojanServer, error) {
	server := &TrojanServer{
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
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
	}

	return server, nil
}

// Start starts the Trojan server
func (s *TrojanServer) Start() error {
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

// Close closes the Trojan server
func (s *TrojanServer) Close() error {
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

func (s *TrojanServer) acceptLoop() {
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

func (s *TrojanServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Trojan protocol:
	// 1. Client sends password (in cleartext, over TLS)
	// 2. Password ends with \r\n
	// 3. Then client sends SOCKS5-like address

	// Verify it's a TLS connection (for documentation purposes)
	if _, ok := conn.(*tls.Conn); !ok {
		// Trojan requires TLS, but we handle non-TLS gracefully
	}

	// Read password line
	line, err := readLine(conn)
	if err != nil {
		return
	}

	// Verify password
	password := strings.TrimSuffix(line, "\r\n")
	if password != s.config.Password {
		return
	}

	// Read target address (SOCKS5-like format)
	// [1 byte cmd] + [1 byte addr type] + [addr] + [2 bytes port]
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	if buf[0] != 0x01 { // CMD_CONNECT only
		return
	}

	var target string
	switch buf[1] {
	case 0x01: // IPv4
		addrBuf := make([]byte, 6)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d", addrBuf[0], addrBuf[1], addrBuf[2], addrBuf[3],
			binary.BigEndian.Uint16(addrBuf[4:6]))

	case 0x03: // Domain
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return
		}
		target = fmt.Sprintf("%s:%d", string(domain), binary.BigEndian.Uint16(port))

	case 0x04: // IPv6
		addrBuf := make([]byte, 18)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return
		}
		target = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			addrBuf[0:2], addrBuf[2:4], addrBuf[4:6], addrBuf[6:8],
			addrBuf[8:10], addrBuf[10:12], addrBuf[12:14], addrBuf[14:16],
			binary.BigEndian.Uint16(addrBuf[16:18]))
	}

	// Send success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Get selected node
	nodeName := s.getSelectedNode()

	// Connect to target
	targetConn, err := s.dialer.Dial(context.Background(), nodeName, target)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Bridge connections
	bridgeConns(conn, targetConn)
}

func (s *TrojanServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

// Helper functions

func readLine(r io.Reader) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n == 0 || err != nil {
			if len(line) > 0 {
				return string(line), nil
			}
			return "", err
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	return string(line), nil
}

func bridgeConns(left, right net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(left, right)
		left.Close()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(right, left)
		right.Close()
		done <- struct{}{}
	}()

	<-done
}

func bridgeConnsHijack(w http.ResponseWriter, r *http.Request, targetConn net.Conn) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Bridge between client and target
	bridgeConns(clientConn, targetConn)
}

// ============ Utility Functions ============

// deriveVMessKey derives VMess encryption key from UUID
func deriveVMessKey(uuid string) []byte {
	// VMess uses MD5-based key derivation
	h := md5.New()
	h.Write([]byte(uuid))
	h.Write([]byte("-c486e9fe-8693-4d34-9ce2-0e62e0a8c2b9")) // Default IV
	return h.Sum(nil)
}

// createVMessRequest creates a VMess request header
func createVMessRequest(target string, uuid string, alterId int) ([]byte, error) {
	// Parse target address
	var addrType byte
	var addrData []byte
	var port uint16

	// Simple implementation - real VMess has more complex header format
	if ip := net.ParseIP(target); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addrType = 0x01
			addrData = ip4
		} else {
			addrType = 0x04
			addrData = ip.To16()
		}
	} else {
		// Domain
		host, pStr, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		port = parsePort(pStr)
		addrType = 0x03
		addrData = []byte{byte(len(host))}
		addrData = append(addrData, []byte(host)...)
	}

	header := make([]byte, 0, 22+len(addrData))
	header = append(header, addrType)
	header = append(header, addrData...)
	header = append(header, byte(port>>8), byte(port&0xff))

	return header, nil
}

func parsePort(s string) uint16 {
	var port uint16
	fmt.Sscanf(s, "%d", &port)
	return port
}
