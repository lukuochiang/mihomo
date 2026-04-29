package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Protocol link prefix
const prefixVMess = "vmess://"

// VMessProtocol implements VMess protocol
type VMessProtocol struct {
	config *VMessConfig
}

// VMessConfig holds VMess configuration
type VMessConfig struct {
	Address         string   `json:"add"`
	Port            int      `json:"port"`
	UserID          string   `json:"id"`
	AlterID         int      `json:"aid"`
	Security        string   `json:"scy"` // auto, aes-128-gcm, aes-128-cfb, aes-256-gcm, chacha20-poly1305, none
	Network         string   `json:"net"` // tcp, ws, grpc
	TLSSecurity     string   `json:"tls"` // none, tls
	SNI             string   `json:"sni"`
	Host            string   `json:"host"`
	Path            string   `json:"path"`
	grpcServiceName string   `json:"serviceName"`
	HTTP1Path       string   `json:"path"`
	HTTP1Host       []string `json:"host"`
	HTTP2Path       string   `json:"path"`
	HTTP2Host       []string `json:"host"`
}

// VMessRequestHeader is the VMess request header
type VMessRequestHeader struct {
	Version     byte
	IV          []byte
	Security    byte // 0: AES-128-CFB, 1: AES-128-GCM, 2: AES-256-GCM, 3: ChaCha20-Poly1305
	Command     byte // 0x01: TCP, 0x02: UDP
	Port        uint16
	AddressType byte // 0x01: IPv4, 0x02: Domain, 0x03: IPv6
	Address     []byte
}

// VMessSession is a VMess session
type VMessSession struct {
	UserID       [16]byte
	AlterID      uint16
	SecurityType byte
	Time         int64
	RandomBytes  [4]byte
}

// NewVMessProtocol creates a new VMess protocol handler
func NewVMessProtocol(cfg *VMessConfig) *VMessProtocol {
	return &VMessProtocol{config: cfg}
}

// NewVMessSession creates a new VMess session
func NewVMessSession(userID string, alterID int) *VMessSession {
	session := &VMessSession{
		AlterID: uint16(alterID),
	}

	// Parse UUID to bytes
	uuid, err := parseUUID(userID)
	if err != nil {
		// Use MD5 hash of userID as fallback
		h := md5.Sum([]byte(userID))
		copy(session.UserID[:], h[:16])
	} else {
		session.UserID = uuid
	}

	return session
}

// DialVMess creates a VMess connection
func (p *VMessProtocol) Dial(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.config.Address, p.config.Port), 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Apply TLS if enabled
	if p.config.TLSSecurity == "tls" {
		tlsConfig := &tls.Config{
			ServerName: p.config.SNI,
		}
		conn = tls.Client(conn, tlsConfig)
	}

	// Build and send request
	session := NewVMessSession(p.config.UserID, p.config.AlterID)
	request, err := session.BuildRequest(address)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Send request
	_, err = conn.Write(request)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// BuildRequest builds VMess request
func (s *VMessSession) BuildRequest(target string) ([]byte, error) {
	// Parse target
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Determine address type
	var addrType byte
	var addr []byte

	ip := net.ParseIP(host)
	if ip == nil {
		// Domain
		addrType = 0x02
		addr = []byte{byte(len(host))}
		addr = append(addr, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		addrType = 0x01
		addr = ip4
	} else {
		// IPv6
		addrType = 0x03
		addr = ip.To16()
	}

	// Generate time and random
	s.Time = time.Now().Unix()
	if _, err := io.ReadFull(rand.Reader, s.RandomBytes[:]); err != nil {
		return nil, err
	}

	// Build header
	header := VMessRequestHeader{
		Version:     1,
		IV:          make([]byte, s.getIVLength()),
		Security:    s.SecurityType,
		Command:     0x01, // TCP
		Port:        port,
		AddressType: addrType,
		Address:     addr,
	}

	// Generate IV
	if _, err := io.ReadFull(rand.Reader, header.IV); err != nil {
		return nil, err
	}

	// Build payload
	var payload bytes.Buffer
	payload.WriteByte(header.Version)
	payload.Write(header.IV)
	payload.WriteByte(header.Security)
	payload.WriteByte(header.Command)
	binary.Write(&payload, binary.BigEndian, header.Port)
	payload.WriteByte(header.AddressType)
	payload.Write(header.Address)

	// Add random bytes and time
	payload.Write(s.RandomBytes[:])
	binary.Write(&payload, binary.BigEndian, s.Time)

	// Authenticate
	auth := s.Authenticate(payload.Bytes())

	// Encrypt payload
	encrypted, err := s.Encrypt(payload.Bytes(), auth)
	if err != nil {
		return nil, err
	}

	// Combine auth + encrypted payload
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(len(auth)+len(encrypted)))
	result = append(result, auth...)
	result = append(result, encrypted...)

	return result, nil
}

func (s *VMessSession) getIVLength() int {
	switch s.SecurityType {
	case 0: // AES-128-CFB
		return 16
	case 1: // AES-128-GCM
		return 12
	case 2: // AES-256-GCM
		return 12
	case 3: // ChaCha20-Poly1305
		return 12
	default:
		return 16
	}
}

func (s *VMessSession) Authenticate(data []byte) []byte {
	// Calculate key
	key := s.deriveKey()

	// Use VMess AEAD
	return vmessAEADAuth(data, key)
}

func vmessAEADAuth(data, key []byte) []byte {
	h := md5.New()
	h.Write(key)
	h.Write([]byte("authentication"))
	authKey := h.Sum(nil)

	h2 := md5.New()
	h2.Write(authKey)
	h2.Write(data[:4]) // Use first 4 bytes of data
	return h2.Sum(nil)
}

func (s *VMessSession) Encrypt(data, auth []byte) ([]byte, error) {
	key := s.deriveKey()

	switch s.SecurityType {
	case 0: // AES-128-CFB
		return encryptAESCFB(data, key, s.Time)
	case 1: // AES-128-GCM
		return encryptAESGCM(data, key, s.Time)
	case 2: // AES-256-GCM
		return encryptAESGCM(data, key, s.Time)
	default:
		return encryptAESCFB(data, key, s.Time)
	}
}

func (s *VMessSession) deriveKey() []byte {
	// VMess key derivation
	h := md5.New()
	h.Write(s.UserID[:])

	md5sum := h.Sum(nil)

	// Multiple rounds of MD5
	result := make([]byte, 16)
	copy(result, md5sum)

	for i := 0; i < 8*1024; i++ {
		h2 := md5.New()
		h2.Write(result)
		h2.Write(md5sum)
		copy(result, h2.Sum(nil))
	}

	return result
}

func encryptAESCFB(plaintext, key []byte, timestamp int64) ([]byte, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	// Create IV from timestamp
	iv := make([]byte, 16)
	binary.BigEndian.PutUint64(iv, uint64(timestamp))

	plaintext = append(plaintext, make([]byte, 16-len(plaintext)%16)...)

	stream := cipher.NewCFBDecrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func encryptAESGCM(plaintext, key []byte, timestamp int64) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create nonce from timestamp
	nonce := make([]byte, gcm.NonceSize())
	binary.BigEndian.PutUint64(nonce, uint64(timestamp))

	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// VMessAEAD is the VMess AEAD protocol handler
type VMessAEAD struct{}

// NewVMessAEAD creates a new VMess AEAD handler
func NewVMessAEAD() *VMessAEAD {
	return &VMessAEAD{}
}

// ParseUUID parses a UUID string to 16 bytes
func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte

	// Remove braces and dashes
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "{", "")
	s = strings.ReplaceAll(s, "}", "")

	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length")
	}

	// Parse hex
	for i := 0; i < 16; i++ {
		var b byte
		_, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return uuid, err
		}
		uuid[i] = b
	}

	return uuid, nil
}

// VMessLinkConfig parses VMess subscription link
type VMessLinkConfig struct {
	Version  string `json:"v"`
	Name     string `json:"ps"`
	Address  string `json:"add"`
	Port     int    `json:"port"`
	UUID     string `json:"id"`
	AlterID  int    `json:"aid"`
	Security string `json:"scy"`
	Network  string `json:"net"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	TLS      string `json:"tls"`
	SNI      string `json:"sni"`
}

// ParseVMessLink parses VMess link configuration
func ParseVMessLink(link string) (*VMessConfig, error) {
	// Remove vmess:// prefix
	if len(link) < len(prefixVMess) {
		return nil, fmt.Errorf("invalid VMess link")
	}

	data, err := base64.StdEncoding.DecodeString(link[len(prefixVMess):])
	if err != nil {
		return nil, err
	}

	var vmess struct {
		Addr   string `json:"add"`
		Port   int    `json:"port"`
		UUID   string `json:"id"`
		User   int    `json:"aid"`
		Cipher string `json:"scy"`
		TLS    int    `json:"tls"`
		Net    string `json:"net"`
		Type   string `json:"type"`
		Host   string `json:"host"`
		Path   string `json:"path"`
	}

	if err := json.Unmarshal(data, &vmess); err != nil {
		return nil, err
	}

	cfg := &VMessConfig{
		Address:     vmess.Addr,
		Port:        vmess.Port,
		UserID:      vmess.UUID,
		AlterID:     0,
		Security:    vmess.Cipher,
		Network:     "tcp",
		TLSSecurity: "none",
	}

	if vmess.TLS == 1 {
		cfg.TLSSecurity = "tls"
		cfg.SNI = vmess.Host
	}

	if vmess.Net != "" {
		cfg.Network = vmess.Net
		cfg.Path = vmess.Path
		cfg.Host = vmess.Host
	}

	return cfg, nil
}

// GetSecurityType returns the security type byte
func GetSecurityType(security string) byte {
	switch security {
	case "aes-128-cfb", "auto":
		return 0
	case "aes-128-gcm":
		return 1
	case "aes-256-gcm":
		return 2
	case "chacha20-poly1305":
		return 3
	case "none":
		return 0
	default:
		return 0
	}
}

// VMessConnection wraps a VMess connection
type VMessConnection struct {
	conn    net.Conn
	session *VMessSession
	reader  *VMessPacketReader
	writer  *VMessPacketWriter
}

// VMessPacketReader reads VMess packets
type VMessPacketReader struct {
	conn  net.Conn
	key   []byte
	iv    []byte
	nonce []byte
}

// VMessPacketWriter writes VMess packets
type VMessPacketWriter struct {
	conn  net.Conn
	key   []byte
	iv    []byte
	nonce []byte
}

// Read reads data from VMess connection
func (c *VMessConnection) Read(b []byte) (int, error) {
	// TODO: Implement VMess AEAD reading
	return c.conn.Read(b)
}

// Write writes data to VMess connection
func (c *VMessConnection) Write(b []byte) (int, error) {
	// TODO: Implement VMess AEAD writing
	return c.conn.Write(b)
}

// Close closes the connection
func (c *VMessConnection) Close() error {
	return c.conn.Close()
}

// LocalAddr returns local address
func (c *VMessConnection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote address
func (c *VMessConnection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets deadline
func (c *VMessConnection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *VMessConnection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *VMessConnection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Unwrap returns underlying connection
func (c *VMessConnection) Unwrap() net.Conn {
	return c.conn
}
