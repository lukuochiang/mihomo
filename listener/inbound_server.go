package listener

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
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

	// Set read deadline for header
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read first byte - version (must be 1 for VMess)
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return
	}
	if version[0] != 1 {
		return
	}

	// Read IV (16 bytes)
	iv := make([]byte, 16)
	if _, err := io.ReadFull(conn, iv); err != nil {
		return
	}

	// Read encrypted header (at least 38 bytes)
	headerBuf := make([]byte, 38+16) // header + some extra
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return
	}

	// Combine IV and encrypted data for decryption
	encryptedData := append(iv, headerBuf...)

	// Find matching user by trying all users
	var authenticated bool
	var targetAddr string

	for _, user := range s.config.Users {
		// Try to decrypt header with this user's key
		addr, ok := s.tryDecryptHeader(encryptedData, user.UUID, user.AlterId)
		if ok {
			targetAddr = addr
			authenticated = true
			break
		}
	}

	if !authenticated {
		return
	}

	// Reset deadline for data transfer
	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	// Get selected node
	nodeName := s.getSelectedNode()
	if nodeName == "" {
		return
	}

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
	// VMess header decryption
	// Format: [1 byte version] + [16 bytes IV] + [encrypted header]

	if len(data) < 38 { // 1 + 16 + minimum header
		return "", false
	}

	// Parse UUID to 16 bytes
	uuidBytes, err := parseVMessUUID(uuid)
	if err != nil {
		return "", false
	}

	// Derive key using VMess key derivation (multiple MD5 rounds)
	key := deriveVMessKeyFromUUID(uuidBytes)

	// Extract IV (next 16 bytes after version)
	iv := data[1:17]
	encryptedData := data[17:]

	// Decrypt header using AES-128-CFB
	decrypted, err := decryptAESCFB(encryptedData, key, iv)
	if err != nil {
		return "", false
	}

	// Parse decrypted header
	// [1 byte version] + [16 bytes response header] + [4 bytes timestamp] + [1 byte command] + [1 byte address type] + [address] + [2 bytes port]

	if len(decrypted) < 26 {
		return "", false
	}

	offset := 1 // skip version

	// Verify response header (skip for now)
	offset += 16 // response auth

	// Check timestamp (4 bytes, big-endian, Unix time)
	timestamp := int64(binary.BigEndian.Uint32(decrypted[offset:]))
	offset += 4

	// Verify timestamp is within acceptable range (60 seconds)
	if time.Now().Unix()-timestamp > 60 || time.Now().Unix()-timestamp < -60 {
		return "", false
	}

	// Command (1 byte)
	command := decrypted[offset]
	offset++

	// Address type (1 byte)
	addrType := decrypted[offset]
	offset++

	// Parse address
	var target string
	switch addrType {
	case 0x01: // IPv4
		if len(decrypted) < offset+4+2 {
			return "", false
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", decrypted[offset], decrypted[offset+1], decrypted[offset+2], decrypted[offset+3])
		port := binary.BigEndian.Uint16(decrypted[offset+4 : offset+6])
		target = fmt.Sprintf("%s:%d", ip, port)

	case 0x02: // Domain
		if len(decrypted) < offset+1+2 {
			return "", false
		}
		domainLen := int(decrypted[offset])
		offset++
		if len(decrypted) < offset+domainLen+2 {
			return "", false
		}
		domain := string(decrypted[offset : offset+domainLen])
		port := binary.BigEndian.Uint16(decrypted[offset+domainLen : offset+domainLen+2])
		target = fmt.Sprintf("%s:%d", domain, port)

	case 0x03: // IPv6
		if len(decrypted) < offset+16+2 {
			return "", false
		}
		ip6 := fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			binary.BigEndian.Uint16(decrypted[offset:offset+2]),
			binary.BigEndian.Uint16(decrypted[offset+2:offset+4]),
			binary.BigEndian.Uint16(decrypted[offset+4:offset+6]),
			binary.BigEndian.Uint16(decrypted[offset+6:offset+8]),
			binary.BigEndian.Uint16(decrypted[offset+8:offset+10]),
			binary.BigEndian.Uint16(decrypted[offset+10:offset+12]),
			binary.BigEndian.Uint16(decrypted[offset+12:offset+14]),
			binary.BigEndian.Uint16(decrypted[offset+14:offset+16]),
		)
		port := binary.BigEndian.Uint16(decrypted[offset+16 : offset+18])
		target = fmt.Sprintf("%s:%d", ip6, port)

	default:
		return "", false
	}

	// Only support TCP command for now
	if command != 0x01 {
		return "", false
	}

	return target, true
}

// parseVMessUUID parses UUID string to 16 bytes
func parseVMessUUID(s string) ([16]byte, error) {
	var uuid [16]byte

	// Remove dashes and braces
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "{", "")
	s = strings.ReplaceAll(s, "}", "")

	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length")
	}

	// Parse hex
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return uuid, err
	}

	if len(decoded) != 16 {
		return uuid, fmt.Errorf("invalid UUID decoded length")
	}

	copy(uuid[:], decoded)
	return uuid, nil
}

// deriveVMessKeyFromUUID derives VMess encryption key from UUID bytes
func deriveVMessKeyFromUUID(uuid [16]byte) []byte {
	// VMess key derivation: multiple rounds of MD5
	md5sum := md5.Sum(uuid[:])

	result := make([]byte, 16)
	copy(result, md5sum[:])

	// 1024 rounds of MD5
	for i := 0; i < 1024; i++ {
		h := md5.New()
		h.Write(result)
		h.Write(md5sum[:])
		copy(result, h.Sum(nil))
	}

	return result
}

// decryptAESCFB decrypts data using AES-128-CFB
func decryptAESCFB(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	// Ensure we have enough data for CFB
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// decryptAESGCM decrypts data using AES-128-GCM
func decryptAESGCM(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// GCM nonce size is typically 12 bytes
	if len(nonce) > gcm.NonceSize() {
		nonce = nonce[:gcm.NonceSize()]
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
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
