package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Server is a DNS server
type Server struct {
	config  ServerConfig
	handler Handler
	server  *dns.Server
	cache   *Cache
	mu      sync.RWMutex
	running bool
}

// ServerConfig holds DNS server configuration
type ServerConfig struct {
	Listen       string   `yaml:"listen"`
	Servers      []string `yaml:"servers"`       // Upstream DNS servers
	Strategy     string   `yaml:"strategy"`      // prefer_ipv4, prefer_ipv6, only_ipv4, only_ipv6
	IPv6Subnet   string   `yaml:"ipv6-subnet"`   // IPv6 prefix for fake AAAA
	EnhancedMode bool     `yaml:"enhanced-mode"` // fake-ip, fake-ip-only, redir-host
	FakeIPRange  string   `yaml:"fake-ip-range"`
	FakeIPFilter []string `yaml:"fake-ip-filter"`
}

// Handler handles DNS requests
type Handler interface {
	// HandleDNS handles a DNS request and returns response
	HandleDNS(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// DefaultHandler is the default DNS handler
type DefaultHandler struct {
	config  ServerConfig
	cache   *Cache
	servers []string
}

// NewServer creates a new DNS server
func NewServer(cfg ServerConfig) *Server {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:53"
	}
	if len(cfg.Servers) == 0 {
		cfg.Servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	if cfg.FakeIPRange == "" {
		cfg.FakeIPRange = "198.18.0.0/15"
	}

	srv := &Server{
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

// Start starts the DNS server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Create DNS server
	s.server = &dns.Server{
		Addr:         s.config.Listen,
		Net:          "udp",
		ReusePort:    true,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	// Handle DNS requests
	dns.HandleFunc(".", s.handleDNS)

	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			// Log error
		}
	}()

	return nil
}

// Stop stops the DNS server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	ctx := context.Background()

	// Create response
	resp, err := s.handler.HandleDNS(ctx, r)
	if err != nil {
		// Send error response
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(msg)
		return
	}

	// Send response
	w.WriteMsg(resp)
}

// Cache implements DNS cache
type Cache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	maxSize int
}

// CacheEntry represents a cached DNS entry
type CacheEntry struct {
	Question string
	Type     uint16
	Answer   []dns.RR
	Expiry   time.Time
}

// NewCache creates a new DNS cache
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*CacheEntry),
		maxSize: 10000,
	}
}

// Get retrieves an entry from cache
func (c *Cache) Get(question string, qtype uint16) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := cacheKey(question, qtype)
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	// Check expiry
	if time.Now().After(entry.Expiry) {
		return nil, false
	}

	return entry, true
}

// Set stores an entry in cache
func (c *Cache) Set(question string, qtype uint16, answer []dns.RR, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(question, qtype)

	// Calculate expiry (use min of provided TTL and max cache time)
	expiry := time.Now().Add(time.Duration(ttl) * time.Second)
	maxTTL := uint32(300) // 5 minutes max
	if ttl > maxTTL {
		ttl = maxTTL
		expiry = time.Now().Add(time.Duration(ttl) * time.Second)
	}

	c.entries[key] = &CacheEntry{
		Question: question,
		Type:     qtype,
		Answer:   answer,
		Expiry:   expiry,
	}

	// Cleanup if too large
	if len(c.entries) > c.maxSize {
		c.cleanup()
	}
}

func (c *Cache) cleanup() {
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.Expiry) {
			delete(c.entries, key)
		}
	}
}

func cacheKey(question string, qtype uint16) string {
	return fmt.Sprintf("%s:%d", question, qtype)
}

// HandleDNS handles DNS requests
func (h *DefaultHandler) HandleDNS(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, fmt.Errorf("no question")
	}

	q := req.Question[0]
	question := q.Name

	// Check cache
	if entry, ok := h.cache.Get(question, q.Qtype); ok {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = entry.Answer
		return resp, nil
	}

	// Check fake-ip filter
	if h.shouldFakeIP(question) && q.Qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		resp.SetReply(req)
		// Return fake AAAA response
		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: net.IPv6zero,
		}
		resp.Answer = append(resp.Answer, rr)
		h.cache.Set(question, q.Qtype, resp.Answer, 300)
		return resp, nil
	}

	// Query upstream
	var lastErr error
	for _, server := range h.servers {
		resp, err := h.queryUpstream(ctx, server, req)
		if err != nil {
			lastErr = err
			continue
		}

		// Cache response
		if len(resp.Answer) > 0 {
			ttl := getTTL(resp.Answer)
			h.cache.Set(question, q.Qtype, resp.Answer, ttl)
		}

		return resp, nil
	}

	return nil, lastErr
}

func (h *DefaultHandler) queryUpstream(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Use TCP for large responses
	if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeAXFR {
		client.Net = "tcp"
	}

	resp, _, err := client.ExchangeContext(ctx, req, server)
	return resp, err
}

func (h *DefaultHandler) shouldFakeIP(question string) bool {
	if !h.config.EnhancedMode {
		return false
	}

	name := strings.ToLower(question)
	name = strings.TrimSuffix(name, ".")

	for _, filter := range h.config.FakeIPFilter {
		filter = strings.ToLower(strings.TrimSuffix(filter, "."))
		if strings.HasSuffix(name, filter) {
			return true
		}
	}

	return false
}

func getTTL(rrs []dns.RR) uint32 {
	if len(rrs) == 0 {
		return 300
	}
	return rrs[0].Header().Ttl
}

// FakeIPGenerator generates fake IPs
type FakeIPGenerator struct {
	baseIP  net.IP
	netmask *net.IPNet
	used    map[string]net.IP
	mu      sync.RWMutex
}

// NewFakeIPGenerator creates a new fake IP generator
func NewFakeIPGenerator(cidr string) (*FakeIPGenerator, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	return &FakeIPGenerator{
		baseIP:  ipnet.IP,
		netmask: ipnet,
		used:    make(map[string]net.IP),
	}, nil
}

// Get returns a fake IP for domain
func (g *FakeIPGenerator) Get(domain string) net.IP {
	g.mu.Lock()
	defer g.mu.Unlock()

	if ip, ok := g.used[domain]; ok {
		return ip
	}

	// Generate new IP
	ip := g.generateIP()
	g.used[domain] = ip
	return ip
}

func (g *FakeIPGenerator) generateIP() net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(g.baseIP.To4())+uint32(len(g.used)))
	return ip
}

// GetDomain returns domain for fake IP
func (g *FakeIPGenerator) GetDomain(ip net.IP) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for domain, usedIP := range g.used {
		if usedIP.Equal(ip) {
			return domain, true
		}
	}
	return "", false
}
