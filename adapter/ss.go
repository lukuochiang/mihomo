package adapter

import (
	"crypto/aes"
	goCipher "crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// SSAEADCipher defines Shadowsocks AEAD cipher interface
type SSAEADCipher interface {
	// KeySize returns the cipher key size
	KeySize() int
	// NonceSize returns the nonce size
	NonceSize() int
	// Encrypt encrypts data
	Encrypt(dst, iv, plain, authData []byte) ([]byte, error)
	// Decrypt decrypts data
	Decrypt(dst, iv, cipher, authData []byte) ([]byte, error)
}

// SS2022Cipher defines Shadowsocks 2022 cipher
type SS2022Cipher interface {
	SSAEADCipher
	// SaltSize returns the salt size
	SaltSize() int
	// DeriveKey derives key from password
	DeriveKey(password string) []byte
}

// SSMethod defines Shadowsocks encryption method
type SSMethod string

const (
	// Standard AEAD methods
	MethodAES128GCM          SSMethod = "aes-128-gcm"
	MethodAES256GCM          SSMethod = "aes-256-gcm"
	MethodCHACHA20IETF       SSMethod = "chacha20-ietf-poly1305"
	MethodXCHACHA20IETF      SSMethod = "xchacha20-ietf-poly1305"
	Method2022BLAKE3AES256G  SSMethod = "2022-blake3-aes-256-gcm"
	Method2022BLAKE3AES256G2 SSMethod = "ss2022-blake3-aes-256-gcm"

	// Default
	DefaultMethod = MethodAES128GCM
)

// aeadCipher implements AEAD cipher for Shadowsocks
type aeadCipher struct {
	keySize   int
	nonceSize int
	newAEAD   func(key []byte) (goCipher.AEAD, error)
}

// NewSSAEADCipher creates a new AEAD cipher by method name
func NewSSAEADCipher(method SSMethod) (SSAEADCipher, error) {
	switch method {
	case MethodAES128GCM:
		return &aeadCipher{
			keySize:   16,
			nonceSize: 12,
			newAEAD: func(key []byte) (goCipher.AEAD, error) {
				block, err := aes.NewCipher(key)
				if err != nil {
					return nil, err
				}
				return goCipher.NewGCM(block)
			},
		}, nil
	case MethodAES256GCM:
		return &aeadCipher{
			keySize:   32,
			nonceSize: 12,
			newAEAD: func(key []byte) (goCipher.AEAD, error) {
				block, err := aes.NewCipher(key)
				if err != nil {
					return nil, err
				}
				return goCipher.NewGCM(block)
			},
		}, nil
	case MethodCHACHA20IETF:
		return &aeadCipher{
			keySize:   32,
			nonceSize: 12,
			newAEAD: func(key []byte) (goCipher.AEAD, error) {
				return chacha20poly1305.NewX(key)
			},
		}, nil
	case MethodXCHACHA20IETF:
		return &aeadCipher{
			keySize:   32,
			nonceSize: 24,
			newAEAD: func(key []byte) (goCipher.AEAD, error) {
				return chacha20poly1305.NewX(key)
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported method: %s", method)
	}
}

// KeySize returns the cipher key size
func (c *aeadCipher) KeySize() int {
	return c.keySize
}

// NonceSize returns the nonce size
func (c *aeadCipher) NonceSize() int {
	return c.nonceSize
}

// Encrypt encrypts data with AEAD
func (c *aeadCipher) Encrypt(dst, iv, plain, authData []byte) ([]byte, error) {
	aead, err := c.newAEAD(dst[:c.keySize])
	if err != nil {
		return nil, err
	}

	if len(iv) != c.nonceSize {
		return nil, errors.New("invalid nonce size")
	}

	return aead.Seal(plain[:0], iv, plain, authData), nil
}

// Decrypt decrypts data with AEAD
func (c *aeadCipher) Decrypt(dst, iv, cipher, authData []byte) ([]byte, error) {
	aead, err := c.newAEAD(dst[:c.keySize])
	if err != nil {
		return nil, err
	}

	if len(iv) != c.nonceSize {
		return nil, errors.New("invalid nonce size")
	}

	return aead.Open(cipher[:0], iv, cipher, authData)
}

// ss2022Cipher implements Shadowsocks 2022 format
type ss2022Cipher struct {
	method    SSMethod
	saltSize  int
	keySize   int
	nonceSize int
}

// SaltSize returns the salt size
func (c *ss2022Cipher) SaltSize() int {
	return c.saltSize
}

// KeySize returns the key size
func (c *ss2022Cipher) KeySize() int {
	return c.keySize
}

// NonceSize returns the nonce size
func (c *ss2022Cipher) NonceSize() int {
	return c.nonceSize
}

// DeriveKey derives key from password using HKDF-SHA256
func (c *ss2022Cipher) DeriveKey(password string) []byte {
	key := make([]byte, c.keySize)
	hkdfSHA256 := hkdf.New(sha256.New, []byte(password), nil, nil)
	io.ReadFull(hkdfSHA256, key)
	return key
}

// Encrypt for SS2022
func (c *ss2022Cipher) Encrypt(dst, iv, plain, authData []byte) ([]byte, error) {
	key := dst[:c.keySize]
	var aead goCipher.AEAD
	var err error

	switch c.method {
	case Method2022BLAKE3AES256G, Method2022BLAKE3AES256G2:
		// SS2022 uses BLAKE3 for key derivation
		aead, err = chacha20poly1305.NewX(key)
	default:
		aead, err = newAESGCMAEAD(key)
	}

	if err != nil {
		return nil, err
	}

	return aead.Seal(plain[:0], iv, plain, authData), nil
}

// Decrypt for SS2022
func (c *ss2022Cipher) Decrypt(dst, iv, ciphertext, authData []byte) ([]byte, error) {
	key := dst[:c.keySize]
	var aead goCipher.AEAD
	var err error

	switch c.method {
	case Method2022BLAKE3AES256G, Method2022BLAKE3AES256G2:
		aead, err = chacha20poly1305.NewX(key)
	default:
		aead, err = newAESGCMAEAD(key)
	}

	if err != nil {
		return nil, err
	}

	return aead.Open(ciphertext[:0], iv, ciphertext, authData)
}

// newAESGCMAEAD creates AES-GCM AEAD
func newAESGCMAEAD(key []byte) (goCipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return goCipher.NewGCM(block)
}

// SSConn is a Shadowsocks AEAD connection
type SSConn struct {
	conn    net.Conn
	cipher  SSAEADCipher
	key     []byte
	recvIV  []byte
	sendIV  []byte
	recvbuf []byte
	sendbuf []byte
	nonce   uint64
}

// NewSSConn creates a new Shadowsocks AEAD connection
func NewSSConn(conn net.Conn, password string, method SSMethod) (*SSConn, error) {
	cipher, err := NewSSAEADCipher(method)
	if err != nil {
		return nil, err
	}

	// Derive key from password
	key := deriveKey(password, cipher.KeySize())

	return &SSConn{
		conn:    conn,
		cipher:  cipher,
		key:     key,
		recvIV:  make([]byte, cipher.NonceSize()),
		sendIV:  make([]byte, cipher.NonceSize()),
		recvbuf: make([]byte, 2*1024),
		sendbuf: make([]byte, 64*1024),
	}, nil
}

// deriveKey derives key from password using HKDF-SHA256
func deriveKey(password string, keyLen int) []byte {
	key := make([]byte, keyLen)
	hkdf := hkdf.New(sha256.New, []byte(password), nil, nil)
	io.ReadFull(hkdf, key)
	return key
}

// Read implements net.Conn Read
func (c *SSConn) Read(b []byte) (n int, err error) {
	// Read and decrypt data
	// Format: [salt(32)][IV(12)][len(2)][AEAD(len)][tag(16)]
	headerLen := 32 + 12 + 2 + 16 // salt + IV + length + tag

	if len(b) < headerLen {
		return 0, errors.New("buffer too small")
	}

	// Read salt
	salt := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, salt); err != nil {
		return 0, err
	}

	// Read IV
	iv := make([]byte, c.cipher.NonceSize())
	if _, err := io.ReadFull(c.conn, iv); err != nil {
		return 0, err
	}

	// Read length
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, lengthBuf); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lengthBuf)

	// Read encrypted data + tag
	encrypted := make([]byte, length+16)
	if _, err := io.ReadFull(c.conn, encrypted); err != nil {
		return 0, err
	}

	// Derive session key
	sessionKey := deriveSessionKey(c.key, salt)

	// Decrypt
	aead, err := c.newAEAD(sessionKey)
	if err != nil {
		return 0, err
	}

	plain, err := aead.Open(b[:0], iv, encrypted, nil)
	if err != nil {
		return 0, err
	}

	return len(plain), nil
}

// Write implements net.Conn Write
func (c *SSConn) Write(b []byte) (n int, err error) {
	// Generate random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}

	// Generate random IV
	iv := make([]byte, c.cipher.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return 0, err
	}

	// Derive session key
	sessionKey := deriveSessionKey(c.key, salt)

	// Encrypt
	aead, err := c.newAEAD(sessionKey)
	if err != nil {
		return 0, err
	}

	// Build packet: salt + IV + len + encrypted + tag
	lengthBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuf, uint16(len(b)))

	ciphertext := aead.Seal(nil, iv, b, nil)

	// Send header first
	if _, err := c.conn.Write(salt); err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(iv); err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(lengthBuf); err != nil {
		return 0, err
	}

	// Send encrypted data
	if _, err := c.conn.Write(ciphertext); err != nil {
		return 0, err
	}

	return len(b), nil
}

// newAEAD creates AEAD from key
func (c *SSConn) newAEAD(key []byte) (goCipher.AEAD, error) {
	switch c.cipher.(type) {
	case *aeadCipher:
		ac := c.cipher.(*aeadCipher)
		return ac.newAEAD(key)
	default:
		return newAESGCMAEAD(key)
	}
}

// Close implements net.Conn Close
func (c *SSConn) Close() error {
	return c.conn.Close()
}

// LocalAddr implements net.Conn LocalAddr
func (c *SSConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr implements net.Conn RemoteAddr
func (c *SSConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline implements net.Conn SetDeadline
func (c *SSConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn SetReadDeadline
func (c *SSConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn SetWriteDeadline
func (c *SSConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// deriveSessionKey derives session key from master key and salt
func deriveSessionKey(masterKey, salt []byte) []byte {
	h := hmac.New(sha256.New, masterKey)
	h.Write(salt)
	return h.Sum(nil)
}

// UDPConn is a Shadowsocks AEAD UDP connection
type UDPConn struct {
	conn   net.PacketConn
	cipher SSAEADCipher
	key    []byte
}

// NewUDPConn creates a new Shadowsocks UDP connection
func NewUDPConn(conn net.PacketConn, password string, method SSMethod) (*UDPConn, error) {
	cipher, err := NewSSAEADCipher(method)
	if err != nil {
		return nil, err
	}

	key := deriveKey(password, cipher.KeySize())

	return &UDPConn{
		conn:   conn,
		cipher: cipher,
		key:    key,
	}, nil
}

// ReadFrom implements net.PacketConn ReadFrom
func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// UDP AEAD format:
	// [salt(32)][IV(12)][encrypted payload]
	headerLen := 32 + 12

	if len(b) < headerLen {
		return 0, nil, errors.New("buffer too small")
	}

	// Read from underlying connection
	// This is a simplified version - full implementation needs addr handling
	packet := make([]byte, 64*1024)
	n, _, err = c.conn.ReadFrom(packet)
	if err != nil {
		return 0, nil, err
	}

	if n < headerLen+16 {
		return 0, nil, errors.New("packet too short")
	}

	salt := packet[:32]
	iv := packet[32 : 32+c.cipher.NonceSize()]
	encrypted := packet[32+c.cipher.NonceSize() : n]

	// Derive session key
	sessionKey := deriveSessionKey(c.key, salt)

	// Decrypt
	aead, err := c.newAEAD(sessionKey)
	if err != nil {
		return 0, nil, err
	}

	plain, err := aead.Open(b[:0], iv, encrypted, nil)
	if err != nil {
		return 0, nil, err
	}

	return len(plain), nil, nil
}

// WriteTo implements net.PacketConn WriteTo
func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// Generate random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}

	// Generate random IV
	iv := make([]byte, c.cipher.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return 0, err
	}

	// Derive session key
	sessionKey := deriveSessionKey(c.key, salt)

	// Encrypt
	aead, err := c.newAEAD(sessionKey)
	if err != nil {
		return 0, err
	}

	ciphertext := aead.Seal(nil, iv, b, nil)

	// Build packet
	packet := make([]byte, 0, len(salt)+len(iv)+len(ciphertext))
	packet = append(packet, salt...)
	packet = append(packet, iv...)
	packet = append(packet, ciphertext...)

	_, err = c.conn.WriteTo(packet, addr)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// newAEAD creates AEAD from key
func (c *UDPConn) newAEAD(key []byte) (goCipher.AEAD, error) {
	switch c.cipher.(type) {
	case *aeadCipher:
		ac := c.cipher.(*aeadCipher)
		return ac.newAEAD(key)
	default:
		return newAESGCMAEAD(key)
	}
}

// Close implements net.PacketConn Close
func (c *UDPConn) Close() error {
	return c.conn.Close()
}

// LocalAddr implements net.PacketConn LocalAddr
func (c *UDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDeadline implements net.PacketConn SetDeadline
func (c *UDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn SetReadDeadline
func (c *UDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn SetWriteDeadline
func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// genRandomBytes generates random bytes
func genRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// incrementNonce increments nonce as uint64 (little endian for chacha20)
func incrementNonce(nonce []byte) {
	var n uint64
	for i := 0; i < 8; i++ {
		n |= uint64(nonce[len(nonce)-1-i]) << uint(i*8)
	}
	n++
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] = byte(n >> uint(i*8))
	}
}

// ValidatePassword checks if password is valid for method
func ValidatePassword(method SSMethod, password string) bool {
	if password == "" {
		return false
	}
	_, err := NewSSAEADCipher(method)
	return err == nil
}

// GetSupportedMethods returns all supported encryption methods
func GetSupportedMethods() []SSMethod {
	return []SSMethod{
		MethodAES128GCM,
		MethodAES256GCM,
		MethodCHACHA20IETF,
		MethodXCHACHA20IETF,
		Method2022BLAKE3AES256G,
		Method2022BLAKE3AES256G2,
	}
}

// ParseSS2022URI parses SS2022 URI format
// Format: ss://BASE64(method:password)@host:port#fragment
func ParseSS2022URI(uri string) (method SSMethod, password, host string, port int, err error) {
	if !hasPrefix(uri, "ss://") {
		err = errors.New("invalid SS URI")
		return
	}

	rest := uri[5:]
	atIdx := indexByte(rest, '@')
	if atIdx < 0 {
		err = errors.New("invalid SS URI: missing @")
		return
	}

	userinfo := rest[:atIdx]
	hostport := rest[atIdx+1:]

	// Decode userinfo
	userinfoBytes, err := base64DecodeStd(userinfo)
	if err != nil {
		userinfoBytes, err = base64DecodeURL(userinfo)
		if err != nil {
			return
		}
	}

	// Parse method:password
	colonIdx := indexByte(string(userinfoBytes), ':')
	if colonIdx < 0 {
		err = errors.New("invalid userinfo format")
		return
	}

	method = SSMethod(string(userinfoBytes[:colonIdx]))
	password = string(userinfoBytes[colonIdx+1:])

	// Parse host:port
	portIdx := indexByte(hostport, ':')
	if portIdx < 0 {
		err = errors.New("invalid host:port format")
		return
	}

	host = hostport[:portIdx]
	portStr := hostport[portIdx+1:]

	// Parse port
	port64, _ := new(big.Int).SetString(portStr, 10)
	if port64 == nil {
		err = errors.New("invalid port")
		return
	}
	port = int(port64.Int64())

	return
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func index(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func base64DecodeStd(s string) ([]byte, error) {
	return base64Decode(s, false)
}

func base64DecodeURL(s string) ([]byte, error) {
	return base64Decode(s, true)
}

func base64Decode(s string, urlSafe bool) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	if urlSafe {
		return base64.URLEncoding.DecodeString(s)
	}
	return base64.StdEncoding.DecodeString(s)
}

// parseUserInfo parses SS2022 user info from base64
func parseUserInfo2022(userInfo string) (string, string, error) {
	decoded, err := base64Decode(userInfo, false)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode user info: %w", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid user info format")
	}

	return parts[0], parts[1], nil
}
