package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

// DoQ constants per RFC 9250
const (
	DoQALPN          = "doq"
	DoQDefaultPort   = 853
	DoQMaxPacketSize = 65535
	DoQBufSize       = 4096
)

// DoQClient represents a DNS over QUIC client
type DoQClient struct {
	Server     string
	QUICConfig *quic.Config
	TLSConfig  *tls.Config
	conn       quic.Connection
	cache      *Cache
	mu         sync.Mutex
}

// NewDoQClient creates a new DoQ client
func NewDoQClient(server string) *DoQClient {
	return &DoQClient{
		Server: server,
		QUICConfig: &quic.Config{
			KeepAlivePeriod: 30 * time.Second,
			MaxIdleTimeout:  60 * time.Second,
		},
		TLSConfig: &tls.Config{
			NextProtos: []string{DoQALPN},
		},
		cache: NewCache(),
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

	// Create QUIC connection
	if err := c.connect(ctx); err != nil {
		return nil, err
	}

	// Send DNS query
	resp, err := c.exchange(ctx, req)
	if err != nil {
		return nil, err
	}

	// Cache response
	if len(resp.Answer) > 0 {
		c.cache.Set(domain, qtype, resp.Answer, getTTL(resp.Answer))
	}

	return resp, nil
}

func (c *DoQClient) connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil
	}

	// Parse server address
	addr := c.Server
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", addr, DoQDefaultPort)
	}

	// Create QUIC connection
	conn, err := quic.DialAddr(ctx, addr, c.TLSConfig, c.QUICConfig)
	if err != nil {
		return fmt.Errorf("failed to dial QUIC: %w", err)
	}

	c.conn = conn
	return nil
}

func (c *DoQClient) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// Pack DNS message
	data, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Open stream and send
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Write DNS message length as varint (DoQ uses stream)
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(len(data)))
	if _, err := stream.Write(buf[:n]); err != nil {
		return nil, fmt.Errorf("failed to write length: %w", err)
	}

	if _, err := stream.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	// Read response length
	respLenBuf := make([]byte, binary.MaxVarintLen64)
	n, err = stream.Read(respLenBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}
	respLen, _ := binary.Uvarint(respLenBuf[:n])

	// Read response data
	respData := make([]byte, respLen)
	if _, err := stream.Read(respData); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Unpack DNS message
	resp := new(dns.Msg)
	if err := resp.Unpack(respData); err != nil {
		return nil, fmt.Errorf("failed to unpack response: %w", err)
	}

	return resp, nil
}

// Close closes the DoQ client
func (c *DoQClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.CloseWithError(0, "")
	}
	return nil
}

// DoQServer represents a DNS over QUIC server
type DoQServer struct {
	config  ServerConfig
	handler Handler
	server  *quic.Listener
	cache   *Cache
	mu      sync.RWMutex
	running bool
	group   *errgroup.Group
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

	// Parse listen address
	addr := s.config.Listen
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", addr, DoQDefaultPort)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		NextProtos: []string{DoQALPN},
	}

	// Create QUIC listener
	ln, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}
	s.server = ln

	// Start accepting connections
	s.group.Go(s.acceptLoop)

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

	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

func (s *DoQServer) acceptLoop() error {
	for {
		s.mu.RLock()
		if !s.running {
			s.mu.RUnlock()
			return nil
		}
		s.mu.RUnlock()

		// Accept QUIC connection
		conn, err := s.server.Accept(context.Background())
		if err != nil {
			continue
		}

		// Handle connection in goroutine
		go s.handleConnection(conn)
	}
}

func (s *DoQServer) handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		go s.handleStream(stream)
	}
}

func (s *DoQServer) handleStream(stream quic.Stream) {
	defer stream.Close()

	// Read message length
	var lenBuf [binary.MaxVarintLen64]byte
	n, err := stream.Read(lenBuf[:])
	if err != nil {
		return
	}
	msgLen, _ := binary.Uvarint(lenBuf[:n])

	// Read DNS message
	data := make([]byte, msgLen)
	if _, err := stream.Read(data); err != nil {
		return
	}

	// Parse DNS query
	req := new(dns.Msg)
	if err := req.Unpack(data); err != nil {
		return
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

	// Write response length
	var respLenBuf [binary.MaxVarintLen64]byte
	n = binary.PutUvarint(respLenBuf[:], uint64(len(respData)))
	if _, err := stream.Write(respLenBuf[:n]); err != nil {
		return
	}

	// Write response data
	stream.Write(respData)
}

// Query performs a DoQ query to upstream
func (s *DoQServer) Query(ctx context.Context, domain string, qtype uint16) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(domain), qtype)

	return s.doQUPstream(ctx, req)
}

func (s *DoQServer) doQUPstream(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// Try each upstream server
	for _, server := range s.config.Servers {
		client := NewDoQClient(server)
		resp, err := client.Exchange(ctx, req.Question[0].Name, req.Question[0].Qtype)
		if err == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("all DoQ servers failed")
}

// DoQUpstream represents a DNS over QUIC upstream
type DoQUpstream struct {
	Server    string
	TLSConfig *tls.Config
	Cache     *Cache
	client    *DoQClient
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

	// Create client if needed
	if u.client == nil {
		u.client = NewDoQClient(u.Server)
	}

	// Exchange
	resp, err := u.client.Exchange(ctx, q.Name, q.Qtype)
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
	if u.client != nil {
		return u.client.Close()
	}
	return nil
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
