package listener

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lukuochiang/mihomo/core/outbound"
	"github.com/lukuochiang/mihomo/core/policy/smart"
)

// SS2022Config holds Shadowsocks 2022 server configuration
type SS2022Config struct {
	Enabled   bool
	Port      int
	Bind      string
	Password  []byte // Key derived from password using HKDF-SHA256
	Method    string // Encryption method
	LocalAddr string // Optional: local address to connect
}

// SSAeadConfig holds Shadowsocks AEAD server configuration
type SSAeadConfig struct {
	Enabled  bool
	Port     int
	Bind     string
	Password []byte
	Method   string // aes-256-gcm, aes-128-gcm, chacha20-ietf-poly1305
}

// SSServer represents a Shadowsocks server
type SSServer struct {
	config      *SS2022Config
	aeadConfig  *SSAeadConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewSSServer creates a new Shadowsocks server
func NewSSServer(cfg interface{}, dialer *outbound.Dialer, sm *smart.Smart) (*SSServer, error) {
	server := &SSServer{
		dialer:      dialer,
		smartEngine: sm,
	}

	// Support both config types
	switch c := cfg.(type) {
	case *SS2022Config:
		server.config = c
		// Derive key from password
		if len(c.Password) > 0 {
			c.Password = deriveKey(c.Password, 32) // 256-bit key
		}
	case *SSAeadConfig:
		server.aeadConfig = c
		if len(c.Password) > 0 {
			c.Password = deriveKey(c.Password, 32)
		}
	}

	return server, nil
}

// Start starts the Shadowsocks server
func (s *SSServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	var port int
	var bind string
	if s.config != nil && s.config.Enabled {
		port = s.config.Port
		bind = s.config.Bind
	} else if s.aeadConfig != nil && s.aeadConfig.Enabled {
		port = s.aeadConfig.Port
		bind = s.aeadConfig.Bind
	} else {
		return nil
	}

	if bind == "" {
		bind = "0.0.0.0"
	}

	addr := fmt.Sprintf("%s:%d", bind, port)
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

// Close closes the Shadowsocks server
func (s *SSServer) Close() error {
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

func (s *SSServer) acceptLoop() {
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

func (s *SSServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	var password []byte
	if s.config != nil && s.config.Enabled {
		password = s.config.Password
	} else if s.aeadConfig != nil && s.aeadConfig.Enabled {
		password = s.aeadConfig.Password
	}

	// Read first packet - should be client handshake
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	// Check protocol version
	// SS2022: first byte is key length indicator
	// Traditional SS: first byte is encryption method
	keyLen := int(buf[0])

	if keyLen == 0 || keyLen > 64 {
		// Traditional Shadowsocks protocol
		s.handleTraditionalSS(conn, password)
	} else {
		// Shadowsocks 2022 protocol
		s.handleSS2022(conn, password)
	}
}

// handleSS2022 handles Shadowsocks 2022 protocol
func (s *SSServer) handleSS2022(conn net.Conn, password []byte) error {
	// SS2022 protocol:
	// 1. Read header (key length + session ID)
	// 2. Derive session key
	// 3. Read encrypted target address
	// 4. Connect to target

	// Read key length byte and session ID
	headerLen := 1 + 32 // key_length + session_id
	header := make([]byte, headerLen)
	header[0] = 32 // We expect 32-byte session ID
	if _, err := io.ReadFull(conn, header[1:]); err != nil {
		return err
	}

	sessionID := header[1:33]

	// Derive session key using HKDF-like derivation
	sessionKey := deriveSessionKey(password, sessionID)

	// Read encrypted address (16 bytes nonce + encrypted data)
	encryptedAddr := make([]byte, 48)
	if _, err := io.ReadFull(conn, encryptedAddr); err != nil {
		return err
	}

	// Decrypt address
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := encryptedAddr[:12]
	ciphertext := encryptedAddr[12:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Parse target address
	target, err := parseTargetAddress(plaintext)
	if err != nil {
		return err
	}

	// Get selected node
	nodeName := s.getSelectedNode()

	// Connect to target through proxy
	targetConn, err := s.dialer.Dial(nil, nodeName, target)
	if err != nil {
		return err
	}
	defer targetConn.Close()

	// Bridge connections
	return bridgeConnections(conn, targetConn)
}

// handleTraditionalSS handles traditional Shadowsocks protocol
func (s *SSServer) handleTraditionalSS(conn net.Conn, password []byte) error {
	// Traditional SS: method(1) + encrypted address + data
	// For AEAD methods: nonce(12) + encrypted address + data

	method := "aes-256-gcm"
	if s.aeadConfig != nil {
		method = s.aeadConfig.Method
	}

	// Derive key from password
	key := deriveKey(password, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	var target string

	switch method {
	case "aes-256-gcm", "aes-128-gcm":
		// AEAD mode
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}

		// Read nonce + encrypted address
		encryptedHeader := make([]byte, 38) // 12 nonce + up to 26 bytes encrypted address
		if _, err := io.ReadFull(conn, encryptedHeader); err != nil {
			return err
		}

		plaintext, err := gcm.Open(nil, encryptedHeader[:12], encryptedHeader[12:], nil)
		if err != nil {
			return err
		}

		target, err = parseTargetAddress(plaintext)
		if err != nil {
			return err
		}

	default:
		// Stream mode (legacy)
		// Read address directly
		addrLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, addrLen); err != nil {
			return err
		}

		addrData := make([]byte, addrLen[0]+2)
		if _, err := io.ReadFull(conn, addrData); err != nil {
			return err
		}

		// Decrypt address
		stream := cipher.NewCFBDecrypter(block, make([]byte, block.BlockSize()))
		stream.XORKeyStream(addrData, addrData)

		target, err = parseTargetAddress(addrData)
		if err != nil {
			return err
		}
	}

	// Get selected node
	nodeName := s.getSelectedNode()

	// Connect to target
	targetConn, err := s.dialer.Dial(nil, nodeName, target)
	if err != nil {
		return err
	}
	defer targetConn.Close()

	// Bridge connections
	return bridgeConnections(conn, targetConn)
}

func (s *SSServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

// deriveKey derives a key from password using SHA256
func deriveKey(password []byte, keyLen int) []byte {
	hash := sha256.Sum256(password)
	return hash[:keyLen]
}

// deriveSessionKey derives session key for SS2022
func deriveSessionKey(password, sessionID []byte) []byte {
	// HKDF-like derivation
	h := sha256.New()
	h.Write(password)
	h.Write(sessionID)
	h.Write([]byte("ss-subkey"))
	return h.Sum(nil)[:32]
}

// parseTargetAddress parses target address from bytes
func parseTargetAddress(data []byte) (string, error) {
	if len(data) < 2 {
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
		if len(data) < 2 {
			return "", errors.New("invalid domain address")
		}
		domainLen := int(data[1])
		if len(data) < 2+domainLen+2 {
			return "", errors.New("invalid domain address length")
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

	default:
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

// bridgeConnections bridges two connections bidirectionally
func bridgeConnections(left, right net.Conn) error {
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(left, right)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(right, left)
		errChan <- err
	}()

	// Wait for one direction to complete
	err := <-errChan
	return err
}
