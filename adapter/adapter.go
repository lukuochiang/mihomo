package adapter

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/lukuochiang/mihomo/protocol"
)

// Adapter defines the interface for protocol adapters
type Adapter interface {
	// Name returns adapter name
	Name() string

	// Connect establishes connection through this adapter
	Connect(ctx context.Context, target string) (net.Conn, error)

	// Dial connects to target through adapter
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// Config holds adapter configuration
type Config struct {
	Type      string
	Address   string
	Port      int
	UUID      string
	Username  string
	Password  string
	Cipher    string
	TLS       TLSConfig
	Transport TransportConfig
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled     bool
	ServerName  string
	Insecure    bool
	ALPN        []string
	Fingerprint string
	Reality     RealityConfig
}

// RealityConfig holds Reality TLS configuration
type RealityConfig struct {
	Enabled   bool
	PublicKey string
	ShortID   string
}

// TransportConfig holds transport layer configuration
type TransportConfig struct {
	Type        string // tcp, ws, wss, grpc, h2
	Path        string
	Host        string
	Headers     map[string]string
	ServiceName string
}

// Registry is the global adapter registry
var Registry = make(map[string]func(*Config) Adapter)

// Register registers an adapter
func Register(name string, factory func(*Config) Adapter) {
	Registry[name] = factory
}

// New creates an adapter by type
func New(cfg *Config) (Adapter, error) {
	factory, ok := Registry[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported adapter type: %s", cfg.Type)
	}
	return factory(cfg), nil
}

// VMessAdapter implements VMess protocol
type VMessAdapter struct {
	config *Config
}

// NewVMessAdapter creates a new VMess adapter
func NewVMessAdapter(cfg *Config) Adapter {
	return &VMessAdapter{config: cfg}
}

func (a *VMessAdapter) Name() string { return "vmess" }

func (a *VMessAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	return a.Dial(ctx, "tcp", target)
}

func (a *VMessAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// Connect to server
	serverAddr := fmt.Sprintf("%s:%d", a.config.Address, a.config.Port)

	// Create dialer with timeout
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS if enabled
	if a.config.TLS.Enabled {
		tlsConfig := &tls.Config{
			ServerName:         a.config.TLS.ServerName,
			InsecureSkipVerify: a.config.TLS.Insecure,
		}
		conn = tls.Client(conn, tlsConfig)
	}

	// Build VMess protocol configuration
	vmessCfg := &protocol.VMessConfig{
		Address:     a.config.Address,
		Port:        a.config.Port,
		UserID:      a.config.UUID,
		AlterID:     0,
		Security:    a.config.Cipher,
		Network:     "tcp",
		TLSSecurity: "none",
	}

	// Set TLS settings
	if a.config.TLS.Enabled {
		vmessCfg.TLSSecurity = "tls"
		vmessCfg.SNI = a.config.TLS.ServerName
	}

	// Apply transport settings
	if a.config.Transport.Type != "" && a.config.Transport.Type != "tcp" {
		vmessCfg.Network = a.config.Transport.Type
		vmessCfg.Path = a.config.Transport.Path
		vmessCfg.Host = a.config.Transport.Host
	}

	// Create VMess protocol handler
	vmessProto := protocol.NewVMessProtocol(vmessCfg)

	// Parse target address
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		portStr = "443"
	}
	targetAddr := net.JoinHostPort(host, portStr)

	// Establish VMess connection
	vmessConn, err := vmessProto.Dial(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("VMess dial failed: %w", err)
	}

	return vmessConn, nil
}

// VMessRequest is VMess request header
type VMessRequest struct {
	Version byte
	Cmd     byte // 0x01 = TCP, 0x02 = UDP
	Port    uint16
	Address []byte
}

func (a *VMessAdapter) buildRequest(address string) (*VMessRequest, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	return &VMessRequest{
		Version: 1,
		Cmd:     0x01,
		Port:    port,
		Address: net.ParseIP(host).To4(),
	}, nil
}

// TrojanAdapter implements Trojan protocol
type TrojanAdapter struct {
	config *Config
}

// NewTrojanAdapter creates a new Trojan adapter
func NewTrojanAdapter(cfg *Config) Adapter {
	return &TrojanAdapter{config: cfg}
}

func (a *TrojanAdapter) Name() string { return "trojan" }

func (a *TrojanAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	return a.Dial(ctx, "tcp", target)
}

func (a *TrojanAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// Use protocol layer for correct Trojan implementation
	trojanCfg := &protocol.TrojanConfig{
		Address:  a.config.Address,
		Port:     a.config.Port,
		Password: a.config.Password,
		TLSSNI:   a.config.TLS.ServerName,
		TLSALPN:  a.config.TLS.ALPN,
		UDP:      network == "udp",
	}

	trojanProto := protocol.NewTrojanProtocol(trojanCfg)

	// Parse target address
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		portStr = "443"
	}
	targetAddr := net.JoinHostPort(host, portStr)

	return trojanProto.Dial(targetAddr)
}

// ShadowsocksAdapter implements Shadowsocks protocol
type ShadowsocksAdapter struct {
	config *Config
}

// NewShadowsocksAdapter creates a new Shadowsocks adapter
func NewShadowsocksAdapter(cfg *Config) Adapter {
	return &ShadowsocksAdapter{config: cfg}
}

func (a *ShadowsocksAdapter) Name() string { return "shadowsocks" }

func (a *ShadowsocksAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	return a.Dial(ctx, "tcp", target)
}

func (a *ShadowsocksAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// Connect to server
	serverAddr := fmt.Sprintf("%s:%d", a.config.Address, a.config.Port)
	conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Parse method from cipher
	method := SSMethod(a.config.Cipher)
	if method == "" {
		method = MethodAES128GCM
	}

	// Wrap with Shadowsocks AEAD encryption
	ssConn, err := NewSSConn(conn, a.config.Password, method)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create SS connection: %w", err)
	}

	// Send connection request to target
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		portStr = "443"
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Build SOCKS5-like request for SS
	request := buildSSRequest(host, port)
	if _, err := ssConn.Write(request); err != nil {
		ssConn.Close()
		return nil, err
	}

	return ssConn, nil
}

// buildSSRequest builds a Shadowsocks target request
func buildSSRequest(host string, port uint16) []byte {
	// Format: [addr_type][addr][port]
	var req []byte

	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		req = append(req, 0x03) // Domain type
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else {
		// IPv6
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	}

	// Port (big endian)
	req = append(req, byte(port>>8), byte(port&0xff))

	return req
}

// VLESSAdapter implements VLESS protocol
type VLESSAdapter struct {
	config *Config
}

// NewVLESSAdapter creates a new VLESS adapter
func NewVLESSAdapter(cfg *Config) Adapter {
	return &VLESSAdapter{config: cfg}
}

func (a *VLESSAdapter) Name() string { return "vless" }

func (a *VLESSAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	return a.Dial(ctx, "tcp", target)
}

func (a *VLESSAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// Build VLESS configuration
	vlessCfg := &protocol.VLESSConfig{
		Address:  a.config.Address,
		Port:     a.config.Port,
		UUID:     a.config.UUID,
		Network:  "tcp",
		Security: "tls",
		TLS: protocol.TLSConfig{
			Enabled:    a.config.TLS.Enabled,
			ServerName: a.config.TLS.ServerName,
			Insecure:   a.config.TLS.Insecure,
			ALPN:       a.config.TLS.ALPN,
		},
	}

	// Apply Reality settings
	if a.config.TLS.Reality.Enabled {
		vlessCfg.Security = "reality"
		vlessCfg.TLS.Reality = protocol.RealityConfig{
			Enabled:   true,
			PublicKey: a.config.TLS.Reality.PublicKey,
			ShortID:   a.config.TLS.Reality.ShortID,
		}
	}

	// Apply transport settings
	if a.config.Transport.Type != "" {
		vlessCfg.Network = a.config.Transport.Type
		vlessCfg.WSPath = a.config.Transport.Path
		vlessCfg.WSHeaders = a.config.Transport.Headers
		vlessCfg.GRPCServiceName = a.config.Transport.ServiceName
	}

	// Create VLESS protocol handler
	vlessProto := protocol.NewVLESSProtocol(vlessCfg)

	// Parse target address
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		portStr = "443"
	}
	targetAddr := net.JoinHostPort(host, portStr)

	return vlessProto.Dial(targetAddr)
}

// WireGuardAdapter implements WireGuard protocol
type WireGuardAdapter struct {
	config *Config
}

// NewWireGuardAdapter creates a new WireGuard adapter
func NewWireGuardAdapter(cfg *Config) Adapter {
	return &WireGuardAdapter{config: cfg}
}

func (a *WireGuardAdapter) Name() string { return "wireguard" }

func (a *WireGuardAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	// WireGuard uses TUN device, not TCP connection
	return nil, fmt.Errorf("WireGuard requires TUN device")
}

func (a *WireGuardAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, fmt.Errorf("WireGuard requires TUN device")
}

// SnellAdapter implements Snell protocol
type SnellAdapter struct {
	config *Config
}

// NewSnellAdapter creates a new Snell adapter
func NewSnellAdapter(cfg *Config) Adapter {
	return &SnellAdapter{config: cfg}
}

func (a *SnellAdapter) Name() string { return "snell" }

func (a *SnellAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	return a.Dial(ctx, "tcp", target)
}

func (a *SnellAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// Connect to Snell server
	serverAddr := fmt.Sprintf("%s:%d", a.config.Address, a.config.Port)
	conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Create Snell connection
	snellConn, err := NewSnellConn(conn, a.config.Password)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create Snell connection: %w", err)
	}

	// Perform handshake
	if err := snellConn.Handshake(); err != nil {
		snellConn.Close()
		return nil, fmt.Errorf("Snell handshake failed: %w", err)
	}

	// Parse target address
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		portStr = "443"
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Send connection request
	if err := snellConn.Request(host, port); err != nil {
		snellConn.Close()
		return nil, fmt.Errorf("Snell request failed: %w", err)
	}

	return snellConn, nil
}

// Init registers all built-in adapters
func Init() {
	Register("vmess", NewVMessAdapter)
	Register("trojan", NewTrojanAdapter)
	Register("shadowsocks", NewShadowsocksAdapter)
	Register("ss", NewShadowsocksAdapter)
	Register("vless", NewVLESSAdapter)
	Register("wireguard", NewWireGuardAdapter)
	Register("snell", NewSnellAdapter)
	Register("hysteria", NewHysteriaAdapter)
	Register("hysteria2", NewHysteriaAdapter)
	Register("tuic", NewTUICAdapter)
}

// Helper functions

// ParseVMessLink parses VMess link
func ParseVMessLink(link string) (*Config, error) {
	if !strings.HasPrefix(link, "vmess://") {
		return nil, fmt.Errorf("invalid VMess link")
	}

	data, err := base64.StdEncoding.DecodeString(link[8:])
	if err != nil {
		return nil, err
	}

	var vmess struct {
		Addr   string `json:"add"`
		Port   int    `json:"port"`
		UUID   string `json:"id"`
		User   string `json:"aid"`
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

	return &Config{
		Type:    "vmess",
		Address: vmess.Addr,
		Port:    vmess.Port,
		UUID:    vmess.UUID,
		Cipher:  vmess.Cipher,
		TLS: TLSConfig{
			Enabled: vmess.TLS == 1,
		},
		Transport: TransportConfig{
			Type: vmess.Net,
			Path: vmess.Path,
			Host: vmess.Host,
		},
	}, nil
}

// ParseSSLink parses Shadowsocks link
func ParseSSLink(link string) (*Config, error) {
	if !strings.HasPrefix(link, "ss://") {
		return nil, fmt.Errorf("invalid SS link")
	}

	// ss://BASE64@host:port#name
	rest := link[5:]
	atIdx := strings.Index(rest, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid SS link format")
	}

	userInfo := rest[:atIdx]
	serverInfo := rest[atIdx+1:]

	// Decode user info
	decoded, err := base64.StdEncoding.DecodeString(userInfo)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(userInfo)
		if err != nil {
			return nil, err
		}
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid SS user info")
	}

	// Parse server
	serverParts := strings.Split(serverInfo, "#")
	addrPort := serverParts[0]

	hostPort := strings.Split(addrPort, ":")
	if len(hostPort) != 2 {
		return nil, fmt.Errorf("invalid SS address")
	}

	var port int
	fmt.Sscanf(hostPort[1], "%d", &port)

	return &Config{
		Type:     "shadowsocks",
		Address:  hostPort[0],
		Port:     port,
		Password: parts[1],
		Cipher:   parts[0],
	}, nil
}

// ParseTrojanLink parses Trojan link
func ParseTrojanLink(link string) (*Config, error) {
	if !strings.HasPrefix(link, "trojan://") {
		return nil, fmt.Errorf("invalid Trojan link")
	}

	// trojan://password@host:port?params#name
	rest := link[9:]

	atIdx := strings.Index(rest, "@")
	password := rest[:atIdx]
	serverInfo := rest[atIdx+1:]

	// Parse server info
	serverParts := strings.Split(serverInfo, "?")
	addrPort := serverParts[0]

	var sni string
	if len(serverParts) > 1 {
		queryParts := strings.Split(serverParts[1], "#")
		for _, q := range strings.Split(queryParts[0], "&") {
			kv := strings.Split(q, "=")
			if len(kv) == 2 && kv[0] == "sni" {
				sni = kv[1]
			}
		}
	}

	hostPort := strings.Split(addrPort, ":")
	if len(hostPort) != 2 {
		return nil, fmt.Errorf("invalid Trojan address")
	}

	var port int
	fmt.Sscanf(hostPort[1], "%d", &port)

	return &Config{
		Type:     "trojan",
		Password: password,
		Address:  hostPort[0],
		Port:     port,
		TLS: TLSConfig{
			Enabled:    true,
			ServerName: sni,
		},
	}, nil
}

// HTTPAdapter implements HTTP/SOCKS proxy adapter
type HTTPAdapter struct {
	config *Config
}

// NewHTTPAdapter creates a new HTTP adapter
func NewHTTPAdapter(cfg *Config) Adapter {
	return &HTTPAdapter{config: cfg}
}

func (a *HTTPAdapter) Name() string { return "http" }

func (a *HTTPAdapter) Connect(ctx context.Context, target string) (net.Conn, error) {
	return a.Dial(ctx, "tcp", target)
}

func (a *HTTPAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	serverAddr := fmt.Sprintf("%s:%d", a.config.Address, a.config.Port)
	conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Send CONNECT request
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address)
	_, err = conn.Write([]byte(req))
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Read response
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		conn.Close()
		return nil, err
	}

	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		conn.Close()
		return nil, fmt.Errorf("proxy error: %s", resp)
	}

	return conn, nil
}

func init() {
	Init()
}
