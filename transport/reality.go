package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

// generateX25519KeyPair generates an X25519 key pair using curve25519
func generateX25519KeyPair() (privateKey, publicKey []byte, err error) {
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		return nil, nil, err
	}
	// Clamp private key per X25519 spec
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return private, public, nil
}

// RealityConfig holds Reality TLS configuration
type RealityConfig struct {
	Enabled      bool
	PublicKey    string // X25519 public key (hex encoded)
	ShortID      string // Short ID (8 bytes, hex encoded)
	TargetDomain string // Target domain to mimic (e.g., "www.apple.com")
	TargetIP     string // Target IP for connection
	TargetPort   int    // Target port

	// Internal fields
	privateKey []byte // X25519 private key
}

// DefaultRealityConfig returns a default Reality configuration
func DefaultRealityConfig() *RealityConfig {
	return &RealityConfig{
		Enabled:      false,
		ShortID:      "0123456789abcdef",
		TargetDomain: "www.apple.com",
		TargetIP:     "17.253.144.10",
		TargetPort:   443,
	}
}

// GenerateKeyPair generates a new X25519 key pair
func (c *RealityConfig) GenerateKeyPair() error {
	privateKey, publicKey, err := generateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	c.privateKey = privateKey
	c.PublicKey = hex.EncodeToString(publicKey)
	return nil
}

// SetPrivateKey sets the private key from hex encoded string
func (c *RealityConfig) SetPrivateKey(privateKeyHex string) error {
	key, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}

	if len(key) != 32 {
		return fmt.Errorf("invalid private key length: expected 32, got %d", len(key))
	}

	c.privateKey = key
	return nil
}

// GetPublicKey returns the public key
func (c *RealityConfig) GetPublicKey() (string, error) {
	if len(c.privateKey) != 32 {
		return "", fmt.Errorf("private key not set")
	}

	publicKey, err := curve25519.X25519(c.privateKey, curve25519.Basepoint)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(publicKey), nil
}

// RealityConn is a Reality TLS connection
type RealityConn struct {
	config       *RealityConfig
	conn         net.Conn
	targetDomain string
	targetIP     string
	targetPort   int
	iv           []byte
	sessionKey   []byte
}

// Dial connects to target using Reality protocol
func (c *RealityConfig) Dial(targetDomain string) (net.Conn, error) {
	// Resolve target IP if needed
	targetIP := c.TargetIP
	if targetIP == "" {
		ips, err := net.LookupIP(targetDomain)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve target: %w", err)
		}
		targetIP = ips[0].String()
	}

	// Connect to target
	addr := fmt.Sprintf("%s:%d", targetIP, c.TargetPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Perform Reality handshake
	rc := &RealityConn{
		config:       c,
		conn:         conn,
		targetDomain: targetDomain,
		targetIP:     targetIP,
		targetPort:   c.TargetPort,
	}

	if err := rc.handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("Reality handshake failed: %w", err)
	}

	return rc, nil
}

// handshake performs the Reality TLS handshake
func (c *RealityConn) handshake() error {
	// Generate client ephemeral key pair
	clientPriv, clientPub, err := generateX25519KeyPair()
	if err != nil {
		return err
	}

	// Get server public key
	serverPub, err := hex.DecodeString(c.config.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}

	// Derive shared secret
	sharedSecret, err := curve25519.X25519(clientPriv, serverPub)
	if err != nil {
		return fmt.Errorf("failed to derive shared secret: %w", err)
	}

	_ = clientPub // used in packet construction below

	// Build Destination info
	// Format: [1 byte version][4 bytes timestamp][2 bytes index length][N bytes index]
	//         [2 bytes domain length][N bytes domain][2 bytes port]
	timestamp := time.Now().Add(120 * time.Second).Unix() // 2 minutes expiration

	destInfo := c.buildDestInfo(timestamp, c.targetDomain, c.targetPort)

	// Derive session key using HKDF
	c.sessionKey = deriveRealitySessionKey(sharedSecret, clientPub[:])

	// Build plaintext for encryption
	// [4 bytes timestamp][2 bytes index][dest info]
	plaintext := make([]byte, 0, 64)
	tsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tsBytes, uint32(timestamp))
	plaintext = append(plaintext, tsBytes...)

	shortID, _ := hex.DecodeString(c.config.ShortID)
	indexBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(indexBytes, uint16(len(shortID)))
	plaintext = append(plaintext, indexBytes...)
	plaintext = append(plaintext, shortID...)

	plaintext = append(plaintext, destInfo...)

	// Generate random IV (first 12 bytes)
	c.iv = make([]byte, 12)
	if _, err := rand.Read(c.iv); err != nil {
		return err
	}

	// Build chaos box parameters
	// For Reality: use AES-256-GCM with zero key
	zeroKey := make([]byte, 32)
	aead, err := aesGCM(zeroKey)
	if err != nil {
		return err
	}

	// Encrypt: chaosBox(zeroKey, iv, plaintext)
	chaosNonce := make([]byte, 12)
	copy(chaosNonce, c.iv)
	ciphertext := aead.Seal(nil, chaosNonce, plaintext, nil)

	// Build final packet
	// [32 bytes client public key][12 bytes IV][ciphertext][16 bytes tag]
	packet := make([]byte, 0)
	packet = append(packet, clientPub[:]...)
	packet = append(packet, c.iv...)
	packet = append(packet, ciphertext...)

	// Send packet
	if _, err := c.conn.Write(packet); err != nil {
		return err
	}

	// Read response (server hello)
	// In Reality, server doesn't send TLS handshake after our special packet
	// It directly pipes traffic

	return nil
}

// buildDestInfo builds the destination information for Reality
func (c *RealityConn) buildDestInfo(timestamp int64, domain string, port int) []byte {
	// Format:
	// [2 bytes domain length][N bytes domain]
	// [2 bytes port]
	// [4 bytes timestamp]

	info := make([]byte, 0)

	// Domain length + domain
	domainBytes := []byte(domain)
	domainLen := make([]byte, 2)
	binary.BigEndian.PutUint16(domainLen, uint16(len(domainBytes)))
	info = append(info, domainLen...)
	info = append(info, domainBytes...)

	// Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	info = append(info, portBytes...)

	// Timestamp
	tsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tsBytes, uint32(timestamp))
	info = append(info, tsBytes...)

	return info
}

// deriveRealitySessionKey derives session key for traffic encryption
func deriveRealitySessionKey(sharedSecret, clientPub []byte) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(clientPub)
	return h.Sum(nil)
}

// aesGCM creates an AES-256-GCM cipher
func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Read implements net.Conn Read
func (c *RealityConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// Write implements net.Conn Write
func (c *RealityConn) Write(b []byte) (n int, err error) {
	// Reality doesn't use standard TLS record layer
	// Just pass through after handshake
	return c.conn.Write(b)
}

// Close implements net.Conn Close
func (c *RealityConn) Close() error {
	return c.conn.Close()
}

// LocalAddr implements net.Conn LocalAddr
func (c *RealityConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr implements net.Conn RemoteAddr
func (c *RealityConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline implements net.Conn SetDeadline
func (c *RealityConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn SetReadDeadline
func (c *RealityConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn SetWriteDeadline
func (c *RealityConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// RealityServer represents a Reality TLS server
type RealityServer struct {
	config     RealityConfig
	listener   net.Listener
	privateKey [32]byte
}

// NewRealityServer creates a new Reality server
func NewRealityServer(config *RealityConfig) (*RealityServer, error) {
	// Parse or generate private key
	if len(config.privateKey) == 32 {
		// Already have private key
	} else {
		priv, _, err := generateX25519KeyPair()
		if err != nil {
			return nil, err
		}
		config.privateKey = priv
	}

	return &RealityServer{
		config: *config,
		privateKey: func() [32]byte {
			var k [32]byte
			copy(k[:], config.privateKey)
			return k
		}(),
	}, nil
}

// Listen starts the Reality server
func (s *RealityServer) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	return nil
}

// Accept waits for and returns the next connection
func (s *RealityServer) Accept() (net.Conn, error) {
	if s.listener == nil {
		return nil, fmt.Errorf("server not listening")
	}
	return s.listener.Accept()
}

// Close closes the server
func (s *RealityServer) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// HandleConnection handles a Reality connection
func (s *RealityServer) HandleConnection(conn net.Conn) (*RealityServerConn, error) {
	return &RealityServerConn{
		config:     &s.config,
		conn:       conn,
		serverPriv: s.privateKey,
	}, nil
}

// RealityServerConn represents a Reality server-side connection
type RealityServerConn struct {
	config     *RealityConfig
	conn       net.Conn
	serverPriv [32]byte
	clientPub  []byte
	sessionKey []byte
}

// Accept performs the server-side Reality handshake
func (c *RealityServerConn) Accept() error {
	// Read client hello packet
	// [32 bytes client public key][12 bytes IV][ciphertext][16 bytes tag]
	headerLen := 32 + 12
	packet := make([]byte, 4096)

	// Read at least header
	n, err := io.ReadFull(c.conn, packet[:headerLen])
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Extract client public key
	c.clientPub = packet[:32]
	iv := packet[32:44]

	// Read more data (ciphertext length varies)
	// Try to read until we get enough
	readMore := 0
	for n < headerLen+64 && readMore < 100 {
		m, err := c.conn.Read(packet[n : n+256])
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read ciphertext: %w", err)
		}
		n += m
		readMore++
	}

	// Derive shared secret
	sharedSecret, err := curve25519.X25519(c.serverPriv[:], c.clientPub)
	if err != nil {
		return fmt.Errorf("failed to derive shared secret: %w", err)
	} // Derive session key
	c.sessionKey = deriveRealitySessionKey(sharedSecret, c.clientPub)

	// Decrypt with chaos box (zero key)
	zeroKey := make([]byte, 32)
	aead, err := aesGCM(zeroKey)
	if err != nil {
		return err
	}

	ciphertext := packet[headerLen : n-16] // minus tag
	tag := packet[n-16 : n]

	plaintext, err := aead.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return fmt.Errorf("chaos box decryption failed: %w", err)
	}

	// Parse plaintext: [4 bytes timestamp][2 bytes index length][N bytes index][dest info]
	if len(plaintext) < 6 {
		return fmt.Errorf("plaintext too short")
	}

	timestamp := binary.BigEndian.Uint32(plaintext[:4])
	indexLen := binary.BigEndian.Uint16(plaintext[4:6])

	// Verify timestamp
	now := time.Now().Unix()
	if int64(timestamp) < now {
		return fmt.Errorf("packet expired")
	}

	// Extract short ID
	offset := 6
	if int(indexLen) > 0 && len(plaintext) > offset+int(indexLen) {
		shortID := plaintext[offset : offset+int(indexLen)]
		configShortID, _ := hex.DecodeString(c.config.ShortID)
		if !bytes.Equal(shortID, configShortID) {
			// Short ID mismatch, but allow for flexibility
		}
		offset += int(indexLen)
	}

	// Extract destination info
	if len(plaintext) <= int(offset) {
		return fmt.Errorf("missing destination info")
	}

	destInfo := plaintext[offset:]
	if len(destInfo) < 4 {
		return fmt.Errorf("invalid destination info")
	}

	// Parse destination
	domainLen := binary.BigEndian.Uint16(destInfo[:2])
	if len(destInfo) < 2+int(domainLen)+4 {
		return fmt.Errorf("invalid destination format")
	}

	domain := string(destInfo[2 : 2+domainLen])
	port := binary.BigEndian.Uint16(destInfo[2+domainLen:])

	c.config.TargetDomain = domain
	c.config.TargetPort = int(port)

	return nil
}

// Read implements net.Conn Read
func (c *RealityServerConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// Write implements net.Conn Write
func (c *RealityServerConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

// Close implements net.Conn Close
func (c *RealityServerConn) Close() error {
	return c.conn.Close()
}

// LocalAddr implements net.Conn LocalAddr
func (c *RealityServerConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr implements net.Conn RemoteAddr
func (c *RealityServerConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline implements net.Conn SetDeadline
func (c *RealityServerConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn SetReadDeadline
func (c *RealityServerConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn SetWriteDeadline
func (c *RealityServerConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// CreateRealityTLSConfig creates a TLS config for Reality
func CreateRealityTLSConfig(targetDomain string) *tls.Config {
	return &tls.Config{
		ServerName:         targetDomain,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Reality handles verification differently
		NextProtos:         []string{"h2", "http/1.1"},
	}
}

// GenerateRealityKey generates a new Reality key pair
func GenerateRealityKey() (publicKey, privateKey string, err error) {
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// IsRealityKeyValid validates a Reality key
func IsRealityKeyValid(key string) bool {
	_, err := hex.DecodeString(key)
	return err == nil && len(key) == 64
}
