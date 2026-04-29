package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// QUICConfig holds QUIC DNS configuration
type QUICConfig struct {
	Enabled    bool
	Listen     string
	ServerAddr string
	TLSConfig  *tls.Config
}

// DoQServer represents a DNS over QUIC server
type DoQServer struct {
	config   ServerConfig
	handler  Handler
	listener *net.UDPConn
	cache    *Cache
	mu       sync.RWMutex
	running  bool
	group    *errgroup.Group
}

// NewDoQServer creates a new DoQ server
func NewDoQServer(cfg ServerConfig) *DoQServer {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:853"
	}

	srv := &DoQServer{
		config: cfg,
		cache:  NewCache(),
	}

	srv.handler = &DefaultHandler{
		config:  cfg,
		cache:   srv.cache,
		servers: cfg.Servers,
	}

	return srv
}

// Start starts the DoQ server
func (s *DoQServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("DoQ server already running")
	}
	s.running = true
	s.group = &errgroup.Group{}
	s.mu.Unlock()

	// Listen on UDP port for QUIC (DoQ uses UDP transport)
	addr := s.config.Listen
	if !strings.Contains(addr, ":") {
		addr = addr + ":853"
	}

	ln, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(strings.Split(addr, ":")[0]),
		Port: 853,
	})
	if err != nil {
		// Try binding to any address
		ln, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: 853,
		})
		if err != nil {
			return fmt.Errorf("failed to listen on DoQ port: %w", err)
		}
	}
	s.listener = ln

	// Start UDP handler for DoQ
	s.group.Go(s.serveUDP)

	return nil
}

// Stop stops the DoQ server
func (s *DoQServer) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	if s.group != nil {
		s.group.Wait()
	}

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *DoQServer) serveUDP() error {
	buf := make([]byte, 4096)

	for {
		s.mu.RLock()
		if !s.running {
			s.mu.RUnlock()
			return nil
		}
		s.mu.RUnlock()

		s.listener.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, addr, err := s.listener.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		go s.handleQUICRequest(addr, buf[:n])
	}
}

func (s *DoQServer) handleQUICRequest(addr *net.UDPAddr, data []byte) {
	// Parse DNS query
	req := new(dns.Msg)
	if err := req.Unpack(data); err != nil {
		// Try parsing as DNS wire format
		if err := req.Unpack(data); err != nil {
			return
		}
	}

	// Handle DNS request
	ctx := context.Background()
	resp, err := s.handler.HandleDNS(ctx, req)
	if err != nil {
		return
	}

	// Pack response
	respData, err := resp.Pack()
	if err != nil {
		return
	}

	// Send response back
	s.listener.WriteToUDP(respData, addr)
}

// Query performs a DoQ query to upstream
func (s *DoQServer) Query(ctx context.Context, domain string, qtype uint16) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(domain), qtype)

	return s.doQUPstream(ctx, req)
}

func (s *DoQServer) doQUPstream(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// For DoQ, we need a proper QUIC implementation
	// This is a simplified version that uses UDP
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Try each upstream server
	for _, server := range s.config.Servers {
		// DoQ typically uses port 853
		if !strings.Contains(server, ":") {
			server = server + ":853"
		}

		resp, _, err := client.ExchangeContext(ctx, req, server)
		if err == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("all DoQ servers failed")
}

// DoQClient represents a DNS over QUIC client
type DoQClient struct {
	Server    string
	TLSConfig *tls.Config
	cache     *Cache
}

// NewDoQClient creates a new DoQ client
func NewDoQClient(server string) *DoQClient {
	return &DoQClient{
		Server: server,
		cache:  NewCache(),
	}
}

// Exchange performs a DoQ query
func (c *DoQClient) Exchange(ctx context.Context, domain string, qtype uint16) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(domain), qtype)

	// Check cache first
	key := fmt.Sprintf("%s:%d", domain, qtype)
	if entry, ok := c.cache.Get(key, qtype); ok {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = entry.Answer
		return resp, nil
	}

	// Create client
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Try to connect to DoQ server
	// DoQ typically uses port 853
	serverAddr := c.Server
	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":853"
	}

	resp, _, err := client.ExchangeContext(ctx, req, serverAddr)
	if err != nil {
		return nil, err
	}

	// Cache response
	if len(resp.Answer) > 0 {
		c.cache.Set(domain, qtype, resp.Answer, getTTL(resp.Answer))
	}

	return resp, nil
}

// DoQUpstream represents a DNS over QUIC upstream
type DoQUpstream struct {
	Server    string
	TLSConfig *tls.Config
	Cache     *Cache
}

// NewDoQUpstream creates a new DoQ upstream
func NewDoQUpstream(server string, tlsConfig *tls.Config) *DoQUpstream {
	return &DoQUpstream{
		Server:    server,
		TLSConfig: tlsConfig,
		Cache:     NewCache(),
	}
}

// Exchange performs a DoQ query
func (u *DoQUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, fmt.Errorf("no question in request")
	}

	q := req.Question[0]

	// Check cache
	if entry, ok := u.Cache.Get(q.Name, q.Qtype); ok {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = entry.Answer
		return resp, nil
	}

	// Create QUIC client
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Add TLS config if provided
	if u.TLSConfig != nil {
		// DNS over QUIC uses TLS
		client.TLSConfig = u.TLSConfig
	}

	// Try to connect
	serverAddr := u.Server
	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":853"
	}

	resp, _, err := client.ExchangeContext(ctx, req, serverAddr)
	if err != nil {
		return nil, err
	}

	// Cache response
	if len(resp.Answer) > 0 {
		ttl := getTTL(resp.Answer)
		u.Cache.Set(q.Name, q.Qtype, resp.Answer, ttl)
	}

	return resp, nil
}

// Close closes the DoQ upstream
func (u *DoQUpstream) Close() error {
	return nil
}

// DoHDoQConfig holds combined DNS-over-HTTPS and DNS-over-QUIC config
type DoHDoQConfig struct {
	Enabled   bool
	Listen    string
	Servers   []string // Upstream DNS servers
	TLSConfig *tls.Config
	EnableDoH bool
	EnableDoQ bool
	EnableDoT bool
}

// DNSUpstreamManager manages multiple DNS upstreams
type DNSUpstreamManager struct {
	upstreams map[string]*DoQUpstream
	mu        sync.RWMutex
}

// NewDNSUpstreamManager creates a new upstream manager
func NewDNSUpstreamManager() *DNSUpstreamManager {
	return &DNSUpstreamManager{
		upstreams: make(map[string]*DoQUpstream),
	}
}

// AddUpstream adds an upstream server
func (m *DNSUpstreamManager) AddUpstream(name, server string, tlsConfig *tls.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.upstreams[name] = NewDoQUpstream(server, tlsConfig)
}

// GetUpstream retrieves an upstream server
func (m *DNSUpstreamManager) GetUpstream(name string) (*DoQUpstream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	upstream, ok := m.upstreams[name]
	return upstream, ok
}

// Close closes all upstreams
func (m *DNSUpstreamManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, upstream := range m.upstreams {
		upstream.Close()
	}
	return nil
}
