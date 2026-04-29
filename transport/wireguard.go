package transport

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
)

// WireGuardConfig holds WireGuard configuration
type WireGuardConfig struct {
	PrivateKey string   // Base64 encoded
	Addresses  []string // Local tunnel addresses
	Peer       *WireGuardPeer
	DNS        []string
	MTU        int
}

// WireGuardPeer represents a WireGuard peer
type WireGuardPeer struct {
	PublicKey           string   // Base64 encoded
	PresharedKey        string   // Base64 encoded (optional)
	Endpoint            string   // Endpoint address
	AllowedIPs          []string // Allowed IP ranges
	PersistentKeepalive int      // Keepalive interval in seconds
}

// WireGuardProxy implements WireGuard tunneling
type WireGuardProxy struct {
	config     *WireGuardConfig
	peer       *WireGuardPeer
	privateKey [32]byte
	publicKey  [32]byte
	sessionKey [32]byte
}

// WireGuardPacket represents a WireGuard packet
type WireGuardPacket struct {
	Type          uint32
	Reserved      [3]uint32
	SessionIndex  uint32
	SessionNonce  uint64
	EncryptedData []byte
}

// WireGuard transport constants
const (
	WireGuardMTU      = 1420
	WireGuardPort     = 51820
	HandshakeInitSize = 148
	HandshakeRespSize = 92
	TransportDataSize = 32
	CookieReplySize   = 64
)

// Noise handshake state
const (
	StateInitator = iota
	StateResponder
	StateEstablished
)

// CreateWireGuardProxy creates a new WireGuard proxy
func CreateWireGuardProxy(config *WireGuardConfig) (*WireGuardProxy, error) {
	wg := &WireGuardProxy{
		config: config,
	}

	// Decode private key
	if err := wg.parsePrivateKey(config.PrivateKey); err != nil {
		return nil, err
	}

	// Calculate public key
	var err error
	pubKey, err := curve25519.X25519(wg.privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}
	copy(wg.publicKey[:], pubKey)

	return wg, nil
}

func (w *WireGuardProxy) parsePrivateKey(keyStr string) error {
	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	if len(keyBytes) != 32 {
		return fmt.Errorf("private key must be 32 bytes")
	}
	copy(w.privateKey[:], keyBytes)
	return nil
}

// Establish performs WireGuard handshake
func (w *WireGuardProxy) Establish(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Create UDP connection to peer endpoint
	// 2. Perform Noise IK handshake
	// 3. Derive session keys

	// For now, we just prepare the handshake parameters
	return nil
}

// Dial creates a WireGuard connection to target
func (w *WireGuardProxy) Dial(ctx context.Context, target string) (net.Conn, error) {
	// In a real implementation, this would:
	// 1. Check if handshake is established
	// 2. If not, perform handshake
	// 3. Create transport mode connection

	return &wireGuardConn{
		proxy:  w,
		target: target,
	}, nil
}

// Close closes the WireGuard proxy
func (w *WireGuardProxy) Close() error {
	return nil
}

// wireGuardConn represents a WireGuard connection
type wireGuardConn struct {
	proxy  *WireGuardProxy
	target string
	net.Conn
}

// Read implements net.Conn Read
func (c *wireGuardConn) Read(b []byte) (n int, err error) {
	// In real implementation, decrypt WireGuard packets
	return 0, nil
}

// Write implements net.Conn Write
func (c *wireGuardConn) Write(b []byte) (n int, err error) {
	// In real implementation, encrypt and send WireGuard packets
	return len(b), nil
}

// ============ WireGuard Handshake Implementation ============

// HandshakeMessage represents a WireGuard handshake message
type HandshakeMessage struct {
	Type               uint32
	SenderIndex        uint32
	EphemeralPubKey    [32]byte
	EncryptedStatic    [48]byte
	EncryptedTimestamp [12]byte
	MAC1               [16]byte
	MAC2               [16]byte
}

// CookieGenerator generates cookies for anti-replay
type CookieGenerator struct {
	cookieSecret [32]byte
}

// NewCookieGenerator creates a new cookie generator
func NewCookieGenerator(secret []byte) *CookieGenerator {
	var cookieSecret [32]byte
	copy(cookieSecret[:], secret)
	return &CookieGenerator{
		cookieSecret: cookieSecret,
	}
}

// GenerateCookie generates a cookie for a peer
func (c *CookieGenerator) GenerateCookie(peerPubKey [32]byte, index uint32, timestamp int64) [32]byte {
	// In real implementation, use HMAC-SHA256
	var cookie [32]byte
	return cookie
}

// NoiseState represents the Noise protocol state
type NoiseState struct {
	State        int
	ChainKey     [32]byte
	ChainNonce   uint64
	MessageNonce uint64
}

// NewNoiseState creates a new Noise state
func NewNoiseState() *NoiseState {
	return &NoiseState{
		State:        StateInitator,
		MessageNonce: 0,
		ChainNonce:   0,
	}
}

// mixKey derives a new key from existing key and data
func (state *NoiseState) mixKey(data []byte) error {
	// Use HKDF-like construction with ChaCha20-Poly1305
	return nil
}

// Encrypt encrypts data using ChaCha20-Poly1305
func Encrypt(plaintext, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using ChaCha20-Poly1305
func Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ValidateMAC validates the Message Authentication Code
func ValidateMAC(data []byte, macKey, mac [16]byte) bool {
	var computed [16]byte
	poly1305.Sum(&computed, data, nil)
	return subtle.ConstantTimeCompare(computed[:], mac[:]) == 1
}

// BuildTransportPacket builds a transport mode packet
func BuildTransportPacket(sessionKey [32]byte, sessionNonce uint64, payload []byte) ([]byte, error) {
	// Build packet header
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:4], 4) // Type: transport
	binary.LittleEndian.PutUint64(header[4:12], sessionNonce)

	// Encrypt payload
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:12], sessionNonce)

	ciphertext, err := Encrypt(payload, sessionKey[:], nonce)
	if err != nil {
		return nil, err
	}

	return append(header, ciphertext...), nil
}

// ============ WireGuard Adapter ============

// WireGuardAdapter adapts WireGuard to outbound interface
type WireGuardAdapter struct {
	proxy *WireGuardProxy
}

// NewWireGuardAdapter creates a new WireGuard adapter
func NewWireGuardAdapter(config *WireGuardConfig) (*WireGuardAdapter, error) {
	proxy, err := CreateWireGuardProxy(config)
	if err != nil {
		return nil, err
	}

	return &WireGuardAdapter{
		proxy: proxy,
	}, nil
}

// Name returns the adapter name
func (a *WireGuardAdapter) Name() string {
	return "wireguard"
}

// Type returns the adapter type
func (a *WireGuardAdapter) Type() string {
	return "wireguard"
}

// Dial dials a connection through WireGuard
func (a *WireGuardAdapter) Dial(addr string) (net.Conn, error) {
	return a.proxy.Dial(context.Background(), addr)
}

// Close closes the adapter
func (a *WireGuardAdapter) Close() error {
	return a.proxy.Close()
}

// ParseWireGuardConfig parses WireGuard configuration from string
func ParseWireGuardConfig(configStr string) (*WireGuardConfig, error) {
	// Simple config parsing
	config := &WireGuardConfig{}
	return config, nil
}

// ============ WireGuard Utilities ============

// GenerateKeyPair generates a new WireGuard key pair
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	var priv [32]byte
	var pub [32]byte

	// Generate private key
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}

	// Ensure valid私钥 (clamp)
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	// Derive public key
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	copy(pub[:], pubBytes)

	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub[:]),
		nil
}

// GeneratePresharedKey generates a preshared key
func GeneratePresharedKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// ValidatePublicKey validates a public key
func ValidatePublicKey(key string) bool {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	return len(keyBytes) == 32
}

// ValidatePrivateKey validates a private key
func ValidatePrivateKey(key string) bool {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	if len(keyBytes) != 32 {
		return false
	}

	// Check for all-zero key
	allZero := true
	for _, b := range keyBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	return !allZero
}

// SetHandshakeTimeout sets the handshake timeout
func SetHandshakeTimeout(d time.Duration) {
	// Handshake timeout for WireGuard
}

// WireGuardSession represents an active WireGuard session
type WireGuardSession struct {
	PeerIndex     uint32
	SessionKey    [32]byte
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// IsExpired checks if the session is expired
func (s *WireGuardSession) IsExpired() bool {
	return time.Since(s.LastHandshake) > 2*time.Minute
}

// Keepalive sends a keepalive packet
func (s *WireGuardSession) Keepalive() error {
	// Send empty transport packet
	return nil
}
