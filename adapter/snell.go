package adapter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// SnellProtocol is the Snell protocol implementation
type SnellProtocol struct {
	Version   uint8
	Command   uint8
	Response  uint8
	Reserved  uint8
	IPVersion uint8
	DstAddr   []byte
	DstPort   []byte
	SessionID []byte
	OTK       []byte
	HeaderLen int
}

// Snell connection states
const (
	SnellStateHandshake  = 0
	SnellStateConnected  = 1
	SnellStateUDPForward = 2
)

// Snell commands
const (
	SnellCmdConnect    = 0x01
	SnellCmdUDPForward = 0x02
	SnellCmdConnectUDP = 0x03
)

// Snell response codes
const (
	SnellRespOK          = 0x00
	SnellRespGenFailure  = 0x01
	SnellRespNotAlive    = 0x02
	SnellRespAuthFailure = 0x03
)

// SnellConn is a Snell connection
type SnellConn struct {
	conn     net.Conn
	password string
	key      []byte
	state    int
}

// NewSnellConn creates a new Snell connection
func NewSnellConn(conn net.Conn, password string) (*SnellConn, error) {
	// Derive key from password
	key := deriveSnellKey(password)

	return &SnellConn{
		conn:     conn,
		password: password,
		key:      key,
		state:    SnellStateHandshake,
	}, nil
}

// deriveSnellKey derives encryption key from password using HKDF-SHA256
func deriveSnellKey(password string) []byte {
	h := hmac.New(sha256.New, []byte("snellv1"))
	h.Write([]byte(password))
	return h.Sum(nil)
}

// Handshake performs the Snell protocol handshake
func (c *SnellConn) Handshake() error {
	// Generate random session ID
	sessionID := make([]byte, 16)
	if _, err := rand.Read(sessionID); err != nil {
		return err
	}

	// Generate one-time key
	otk := make([]byte, 32)
	if _, err := rand.Read(otk); err != nil {
		return err
	}

	// Build handshake request
	// Format: [version][cmd][session_id][otk][host_length][host][port]
	req := make([]byte, 0, 64)
	req = append(req, 0x01)            // Version 1
	req = append(req, SnellCmdConnect) // Connect command
	req = append(req, sessionID...)
	req = append(req, otk...)

	// Send handshake
	if _, err := c.conn.Write(req); err != nil {
		return err
	}

	// Read response
	resp := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, resp); err != nil {
		return err
	}

	// Verify response
	if resp[0] != 0x01 { // Version
		return errors.New("invalid version")
	}
	if resp[1] != SnellRespOK { // Response code
		return fmt.Errorf("handshake failed: %d", resp[1])
	}

	c.state = SnellStateConnected
	return nil
}

// Request sends a connection request to the target
func (c *SnellConn) Request(target string, port uint16) error {
	// Parse target (IP or domain)
	ip := net.ParseIP(target)
	var addr []byte
	var addrType byte

	if ip == nil {
		// Domain name
		addrType = 0x03 // Domain
		addr = []byte{byte(len(target))}
		addr = append(addr, []byte(target)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		addrType = 0x01
		addr = ip4
	} else {
		// IPv6
		addrType = 0x04
		addr = ip.To16()
	}

	// Build request: [addr_type][addr][port]
	req := make([]byte, 0, 64)
	req = append(req, addrType)
	req = append(req, addr...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	req = append(req, portBytes...)

	// Encrypt request
	encrypted, err := c.encryptRequest(req)
	if err != nil {
		return err
	}

	// Send encrypted request
	if _, err := c.conn.Write(encrypted); err != nil {
		return err
	}

	return nil
}

// encryptRequest encrypts a request using AES-256-CBC
func (c *SnellConn) encryptRequest(data []byte) ([]byte, error) {
	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Pad data to block size
	padded := pkcs7Pad(data, aes.BlockSize)

	// Encrypt
	block, err := aes.NewCipher(c.key[:32])
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	// Prepend IV
	result := make([]byte, 0, len(iv)+len(ciphertext))
	result = append(result, iv...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptResponse decrypts a response
func (c *SnellConn) decryptResponse(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("response too short")
	}

	// Extract IV
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	// Pad to block size
	if len(ciphertext)%aes.BlockSize != 0 {
		padded := make([]byte, ((len(ciphertext)/aes.BlockSize)+1)*aes.BlockSize)
		copy(padded, ciphertext)
		ciphertext = padded
	}

	// Decrypt
	block, err := aes.NewCipher(c.key[:32])
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Unpad
	return pkcs7Unpad(plaintext)
}

// pkcs7Pad pads data using PKCS7
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

// pkcs7Unpad removes PKCS7 padding
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

// Read implements net.Conn Read
func (c *SnellConn) Read(b []byte) (n int, err error) {
	if c.state != SnellStateConnected {
		return 0, errors.New("not connected")
	}

	// Read response length (2 bytes, big endian)
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, lengthBuf); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lengthBuf)

	// Read encrypted response
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(c.conn, encrypted); err != nil {
		return 0, err
	}

	// Decrypt
	plaintext, err := c.decryptResponse(encrypted)
	if err != nil {
		return 0, err
	}

	n = copy(b, plaintext)
	return n, nil
}

// Write implements net.Conn Write
func (c *SnellConn) Write(b []byte) (n int, err error) {
	if c.state != SnellStateConnected {
		return 0, errors.New("not connected")
	}

	// Encrypt data
	encrypted, err := c.encryptRequest(b)
	if err != nil {
		return 0, err
	}

	// Send length + encrypted data
	lengthBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuf, uint16(len(encrypted)))

	if _, err := c.conn.Write(lengthBuf); err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(encrypted); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close implements net.Conn Close
func (c *SnellConn) Close() error {
	return c.conn.Close()
}

// LocalAddr implements net.Conn LocalAddr
func (c *SnellConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr implements net.Conn RemoteAddr
func (c *SnellConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline implements net.Conn SetDeadline
func (c *SnellConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn SetReadDeadline
func (c *SnellConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn SetWriteDeadline
func (c *SnellConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// SnellUDPConn is a Snell UDP connection
type SnellUDPConn struct {
	conn     net.PacketConn
	password string
	key      []byte
}

// NewSnellUDPConn creates a new Snell UDP connection
func NewSnellUDPConn(conn net.PacketConn, password string) (*SnellUDPConn, error) {
	key := deriveSnellKey(password)

	return &SnellUDPConn{
		conn:     conn,
		password: password,
		key:      key,
	}, nil
}

// ReadFrom implements net.PacketConn ReadFrom
func (c *SnellUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// Read packet
	packet := make([]byte, 64*1024)
	n, addr, err = c.conn.ReadFrom(packet)
	if err != nil {
		return 0, nil, err
	}

	if n < aes.BlockSize {
		return 0, nil, errors.New("packet too short")
	}

	// Decrypt
	plaintext, err := c.decryptUDP(packet[:n])
	if err != nil {
		return 0, nil, err
	}

	copy(b, plaintext)
	return len(plaintext), addr, nil
}

// WriteTo implements net.PacketConn WriteTo
func (c *SnellUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// Encrypt packet
	encrypted, err := c.encryptUDP(b)
	if err != nil {
		return 0, err
	}

	_, err = c.conn.WriteTo(encrypted, addr)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *SnellUDPConn) encryptUDP(data []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	padded := pkcs7Pad(data, aes.BlockSize)

	block, err := aes.NewCipher(c.key[:32])
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	result := make([]byte, 0, len(iv)+len(ciphertext))
	result = append(result, iv...)
	result = append(result, ciphertext...)

	return result, nil
}

func (c *SnellUDPConn) decryptUDP(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("data too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		padded := make([]byte, ((len(ciphertext)/aes.BlockSize)+1)*aes.BlockSize)
		copy(padded, ciphertext)
		ciphertext = padded
	}

	block, err := aes.NewCipher(c.key[:32])
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

// Close implements net.PacketConn Close
func (c *SnellUDPConn) Close() error {
	return c.conn.Close()
}

// LocalAddr implements net.PacketConn LocalAddr
func (c *SnellUDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDeadline implements net.PacketConn SetDeadline
func (c *SnellUDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn SetReadDeadline
func (c *SnellUDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn SetWriteDeadline
func (c *SnellUDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
