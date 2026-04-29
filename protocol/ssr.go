package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/lukuochiang/mihomo/provider"
)

// SSRProtocol defines ShadowsocksR protocol types
type SSRProtocol string

const (
	SSRProtocolOrigin       SSRProtocol = "origin"
	SSRProtocolAuthSHA1V4   SSRProtocol = "auth_sha1_v4"
	SSRProtocolAuthChainA   SSRProtocol = "auth_chain_a"
	SSRProtocolAuthChainB   SSRProtocol = "auth_chain_b"
	SSRProtocolAuthChainC   SSRProtocol = "auth_chain_c"
	SSRProtocolAuthChainD   SSRProtocol = "auth_chain_d"
	SSRProtocolAuthChainE   SSRProtocol = "auth_chain_e"
	SSRProtocolAuthSHA256V4 SSRProtocol = "auth_sha256_v4"
)

// SSRObfuscator defines ShadowsocksR obfuscator types
type SSRObfuscator string

const (
	SSRObfuscatorPlain     SSRObfuscator = "plain"
	SSRObfuscatorRandomLen SSRObfuscator = "random_len"
	SSRObfuscatorRandomPKT SSRObfuscator = "random_pktsize"
)

// SSRConfig holds ShadowsocksR configuration
type SSRConfig struct {
	Server        string
	Port          int
	Password      string
	Method        string
	Protocol      SSRProtocol
	Obfuscator    SSRObfuscator
	OBFSParam     string
	ProtocolParam string
}

// SSRProxy represents a ShadowsocksR proxy connection
type SSRProxy struct {
	config *SSRConfig
	server *ssrServerInfo
}

// ssrServerInfo holds parsed server information
type ssrServerInfo struct {
	host     string
	port     int
	protocol string
	method   string
	password string
	obfs     string
}

// NewSSRProxy creates a new ShadowsocksR proxy
func NewSSRProxy(config *SSRConfig) *SSRProxy {
	return &SSRProxy{
		config: config,
	}
}

// ParseSSRLink parses ssr:// link
func ParseSSRLink(link string) (*SSRConfig, error) {
	// ssr://base64(host:port:protocol:method:obfs:password/?params)
	// or ssr://base64(host:port:protocol:method:obfs:password)/remark

	link = strings.TrimPrefix(link, "ssr://")

	data, err := base64Decode(link)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SSR link: %w", err)
	}

	parts := strings.Split(string(data), "/?")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid SSR link format")
	}

	mainParts := strings.Split(parts[0], ":")
	if len(mainParts) < 6 {
		return nil, fmt.Errorf("invalid SSR link parts")
	}

	cfg := &SSRConfig{
		Server:     mainParts[0],
		Port:       mustAtoi(mainParts[1]),
		Protocol:   SSRProtocol(mainParts[2]),
		Method:     mainParts[3],
		Obfuscator: SSRObfuscator(mainParts[4]),
		Password:   decodeURL(mainParts[5]),
	}

	// Parse optional params
	if len(parts) > 1 {
		params := parts[1]
		for _, param := range strings.Split(params, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				switch kv[0] {
				case "obfsparam":
					cfg.OBFSParam = decodeURL(kv[1])
				case "protoparam":
					cfg.ProtocolParam = decodeURL(kv[1])
				}
			}
		}
	}

	return cfg, nil
}

// BuildSSRLink builds ssr:// link from config
func BuildSSRLink(cfg *SSRConfig) string {
	parts := []string{
		cfg.Server,
		strconv.Itoa(cfg.Port),
		string(cfg.Protocol),
		cfg.Method,
		string(cfg.Obfuscator),
		encodeURL(cfg.Password),
	}

	base := strings.Join(parts, ":")
	encoded := base64EncodeString(base)

	if cfg.OBFSParam != "" || cfg.ProtocolParam != "" {
		params := []string{}
		if cfg.OBFSParam != "" {
			params = append(params, "obfsparam="+encodeURL(cfg.OBFSParam))
		}
		if cfg.ProtocolParam != "" {
			params = append(params, "protoparam="+encodeURL(cfg.ProtocolParam))
		}
		encoded += "/?" + strings.Join(params, "&")
	}

	return "ssr://" + encoded
}

// ssrConn wraps a ShadowsocksR connection
type ssrConn struct {
	net.Conn
	cipher     *ssrCipher
	protocol   *ssrProtocol
	obfuscator *ssrObfs
}

// ssrCipher handles encryption
type ssrCipher struct {
	enc cipher.Stream
	dec cipher.Stream
}

// ssrProtocol handles protocol logic
type ssrProtocol struct {
	typ    SSRProtocol
	params string
}

// ssrObfs handles obfuscation
type ssrObfs struct {
	typ SSRObfuscator
}

// newSSRCipher creates a new cipher
func newSSRCipher(method, password string) (*ssrCipher, error) {
	key := deriveKey(password, getCipherKeyLen(method))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &ssrCipher{
		enc: cipher.NewCFBEncrypter(block, make([]byte, block.BlockSize())),
		dec: cipher.NewCFBDecrypter(block, make([]byte, block.BlockSize())),
	}, nil
}

// deriveKey derives encryption key from password
func deriveKey(password string, keyLen int) []byte {
	key := make([]byte, keyLen)
	for i := 0; i < keyLen; {
		h := md5.New()
		h.Write([]byte(password))
		h.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		sum := h.Sum(nil)
		copy(key[i:], sum)
		i += len(sum)
	}
	return key[:keyLen]
}

// getCipherKeyLen returns key length for cipher method
func getCipherKeyLen(method string) int {
	switch strings.ToLower(method) {
	case "aes-128-cfb", "aes-128-ctr":
		return 16
	case "aes-192-cfb", "aes-192-ctr":
		return 24
	case "aes-256-cfb", "aes-256-ctr":
		return 32
	default:
		return 32
	}
}

// Connect establishes a ShadowsocksR connection
func (p *SSRProxy) Connect(addr string) (net.Conn, error) {
	// Connect to SSR server
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", p.config.Server, p.config.Port))
	if err != nil {
		return nil, err
	}

	// Create cipher
	cipher, err := newSSRCipher(p.config.Method, p.config.Password)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Perform handshake
	if err := p.handshake(conn, addr, cipher); err != nil {
		conn.Close()
		return nil, err
	}

	return &ssrConn{
		Conn:       conn,
		cipher:     cipher,
		protocol:   &ssrProtocol{typ: p.config.Protocol, params: p.config.ProtocolParam},
		obfuscator: &ssrObfs{typ: p.config.Obfuscator},
	}, nil
}

func (p *SSRProxy) handshake(conn net.Conn, target string, cipher *ssrCipher) error {
	// Send initial packet based on protocol
	switch p.config.Protocol {
	case SSRProtocolOrigin:
		return p.originHandshake(conn, target, cipher)
	case SSRProtocolAuthSHA1V4, SSRProtocolAuthSHA256V4:
		return p.authSHAHandshake(conn, target, cipher)
	case SSRProtocolAuthChainA:
		return p.authChainAHandshake(conn, target, cipher)
	default:
		return p.originHandshake(conn, target, cipher)
	}
}

func (p *SSRProxy) originHandshake(conn net.Conn, target string, cipher *ssrCipher) error {
	// Build target address
	addr := packAddr(target)

	// Encrypt and send
	buf := make([]byte, len(addr))
	cipher.enc.XORKeyStream(buf, addr)

	_, err := conn.Write(buf)
	return err
}

func (p *SSRProxy) authSHAHandshake(conn net.Conn, target string, cipher *ssrCipher) error {
	// Auth SHA1/SHA256 handshake with random data
	random := make([]byte, 4+12+4) // IV + random + timestamp
	rand.Read(random)

	// Append connection ID and target
	var connectionID uint32
	binary.Read(rand.Reader, binary.LittleEndian, &connectionID)
	data := append(random, packUint32(connectionID)...)
	data = append(data, packAddr(target)...)

	// Encrypt
	encrypted := make([]byte, len(data))
	cipher.enc.XORKeyStream(encrypted, data)

	_, err := conn.Write(encrypted)
	return err
}

func (p *SSRProxy) authChainAHandshake(conn net.Conn, target string, cipher *ssrCipher) error {
	// Auth Chain A handshake with HMAC
	random := make([]byte, 32)
	rand.Read(random)

	// Add HMAC
	key := deriveKey(p.config.Password, 32)
	h := md5.New()
	h.Write(key)
	h.Write(random)
	hmac := h.Sum(nil)

	data := append(hmac, random...)
	data = append(data, packAddr(target)...)

	// Encrypt
	encrypted := make([]byte, len(data))
	cipher.enc.XORKeyStream(encrypted, data)

	_, err := conn.Write(encrypted)
	return err
}

// packAddr packs a network address for ShadowsocksR
func packAddr(addr string) []byte {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return []byte{}
	}

	port, _ := strconv.Atoi(portStr)

	var data []byte

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			data = append(data, 1) // Type: IPv4
			data = append(data, ip4...)
		} else {
			data = append(data, 3) // Type: IPv6
			data = append(data, ip...)
		}
	} else {
		data = append(data, 3) // Type: Domain
		data = append(data, byte(len(host)))
		data = append(data, []byte(host)...)
	}

	data = append(data, byte(port>>8), byte(port))

	return data
}

// packUint32 packs uint32 to bytes
func packUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func (c *ssrConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil {
		return 0, err
	}

	// Decrypt
	c.cipher.dec.XORKeyStream(b[:n], b[:n])
	return n, nil
}

func (c *ssrConn) Write(b []byte) (n int, err error) {
	// Encrypt
	encrypted := make([]byte, len(b))
	c.cipher.enc.XORKeyStream(encrypted, b)

	n, err = c.Conn.Write(encrypted)
	if err != nil {
		return 0, err
	}
	return len(b), nil // Return original length
}

// base64Decode decodes base64 with URL-safe alphabet
func base64Decode(s string) ([]byte, error) {
	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return provider.Decode(s)
}

// base64EncodeString encodes to base64
func base64EncodeString(s string) string {
	return provider.Encode([]byte(s))
}

// decodeURL decodes URL-encoded string
func decodeURL(s string) string {
	s = strings.ReplaceAll(s, "%20", " ")
	s = strings.ReplaceAll(s, "%21", "!")
	s = strings.ReplaceAll(s, "%23", "#")
	s = strings.ReplaceAll(s, "%24", "$")
	s = strings.ReplaceAll(s, "%26", "&")
	s = strings.ReplaceAll(s, "%27", "'")
	s = strings.ReplaceAll(s, "%28", "(")
	s = strings.ReplaceAll(s, "%29", ")")
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, "%3A", ":")
	s = strings.ReplaceAll(s, "%3B", ";")
	s = strings.ReplaceAll(s, "%3D", "=")
	s = strings.ReplaceAll(s, "%3F", "?")
	s = strings.ReplaceAll(s, "%40", "@")
	return s
}

// encodeURL encodes string for URL
func encodeURL(s string) string {
	s = strings.ReplaceAll(s, "+", "%20")
	s = strings.ReplaceAll(s, "!", "%21")
	s = strings.ReplaceAll(s, "#", "%23")
	s = strings.ReplaceAll(s, "$", "%24")
	s = strings.ReplaceAll(s, "&", "%26")
	s = strings.ReplaceAll(s, "'", "%27")
	s = strings.ReplaceAll(s, "(", "%28")
	s = strings.ReplaceAll(s, ")", "%29")
	s = strings.ReplaceAll(s, "/", "%2F")
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ";", "%3B")
	s = strings.ReplaceAll(s, "=", "%3D")
	s = strings.ReplaceAll(s, "?", "%3F")
	s = strings.ReplaceAll(s, "@", "%40")
	return s
}

// mustAtoi converts string to int, returns 0 on error
func mustAtoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

// rc4Cipher for RC4-based methods
type rc4Cipher struct {
	enc *rc4.Cipher
	dec *rc4.Cipher
}

func newRC4Cipher(key []byte) (*rc4Cipher, error) {
	enc, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dec, _ := rc4.NewCipher(key)
	return &rc4Cipher{enc, dec}, nil
}

func (c *rc4Cipher) Encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *rc4Cipher) Decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

// ============ SSR Adapter for clash integration ============

// SSRAdapter adapts SSR proxy to outbound interface
type SSRAdapter struct {
	config *SSRConfig
	proxy  *SSRProxy
}

// NewSSRAdapter creates a new SSR adapter
func NewSSRAdapter(config *SSRConfig) (*SSRAdapter, error) {
	return &SSRAdapter{
		config: config,
		proxy:  NewSSRProxy(config),
	}, nil
}

// Name returns the adapter name
func (a *SSRAdapter) Name() string {
	return "shadowsocksr"
}

// Type returns the adapter type
func (a *SSRAdapter) Type() string {
	return "shadowsocksr"
}

// Dial dials a connection through the proxy
func (a *SSRAdapter) Dial(addr string) (net.Conn, error) {
	return a.proxy.Connect(addr)
}

// Close closes the adapter
func (a *SSRAdapter) Close() error {
	return nil
}
