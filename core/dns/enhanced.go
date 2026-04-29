package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// EnhancedMode defines DNS enhanced mode
type EnhancedMode string

const (
	ModeFakeIP     EnhancedMode = "fake-ip"      // Return fake IP, record mapping
	ModeFakeIPOnly EnhancedMode = "fake-ip-only" // Return fake IP only
	ModeRedirHost  EnhancedMode = "redir-host"   // Return real IP, filter by domain
)

// UpstreamType defines DNS upstream type
type UpstreamType string

const (
	UpstreamDNS UpstreamType = "dns" // Standard DNS
	UpstreamDoh UpstreamType = "doh" // DNS over HTTPS
	UpstreamDot UpstreamType = "dot" // DNS over TLS
	UpstreamDoq UpstreamType = "doq" // DNS over QUIC
)

// UpstreamConfig holds upstream DNS configuration
type UpstreamConfig struct {
	Type       UpstreamType `yaml:"type"`
	Address    string       `yaml:"address"`
	Trusted    bool         `yaml:"trusted"`    // Trusted upstream (no fake IP for this)
	Interfaces []string     `yaml:"interfaces"` // Network interfaces to use
}

// DNSUpstream represents a DNS upstream server
type DNSUpstream interface {
	// Exchange sends a DNS query and returns response
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	// Close closes the upstream connection
	Close() error
}

// StandardUpstream implements standard DNS upstream
type StandardUpstream struct {
	address string
	conn    *dns.Client
}

// NewStandardUpstream creates a new standard DNS upstream
func NewStandardUpstream(address string) *StandardUpstream {
	return &StandardUpstream{
		address: address,
		conn: &dns.Client{
			Net:     "udp",
			Timeout: 5 * time.Second,
		},
	}
}

// Exchange sends a DNS query
func (u *StandardUpstream) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resp, _, err := u.conn.ExchangeContext(ctx, msg, u.address)
	return resp, err
}

// Close closes the connection
func (u *StandardUpstream) Close() error {
	return nil
}

// DoHUpstream implements DNS over HTTPS upstream
type DoHUpstream struct {
	address   string
	url       string
	transport *http.Transport
	client    *http.Client
}

// NewDoHUpstream creates a new DoH upstream
func NewDoHUpstream(address, url string) *DoHUpstream {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &DoHUpstream{
		address:   address,
		url:       url,
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// Exchange sends a DNS query over HTTPS
func (u *DoHUpstream) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// Serialize DNS message
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse DNS message
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, err
	}

	return dnsResp, nil
}

// Close closes the connection
func (u *DoHUpstream) Close() error {
	u.transport.CloseIdleConnections()
	return nil
}

// DoTUpstream implements DNS over TLS upstream
type DoTUpstream struct {
	address string
	conn    net.Conn
	client  *dns.Client
}

// NewDoTUpstream creates a new DoT upstream
func NewDoTUpstream(address string) *DoTUpstream {
	return &DoTUpstream{
		address: address,
	}
}

// Exchange sends a DNS query over TLS
func (u *DoTUpstream) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// Connect to DoT server
	conn, err := tls.Dial("tcp", u.address, &tls.Config{
		ServerName:         strings.Split(u.address, ":")[0],
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Pack DNS message
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// Write length prefix
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))

	if _, err := conn.Write(lenBuf); err != nil {
		return nil, err
	}
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	// Read response length
	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, respLenBuf); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(respLenBuf)

	// Read response
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return nil, err
	}

	// Parse DNS message
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(respData); err != nil {
		return nil, err
	}

	return dnsResp, nil
}

// Close closes the connection
func (u *DoTUpstream) Close() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// FakeIPStore manages fake IP allocation
type FakeIPStore struct {
	mu        sync.RWMutex
	domainIP  map[string]net.IP
	ipDomain  map[string]string
	currentIP net.IP
	subnet    *net.IPNet
}

// NewFakeIPStore creates a new FakeIP store
func NewFakeIPStore(cidr string) (*FakeIPStore, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Start from first usable IP (198.18.0.1)
	ip := make(net.IP, 4)
	copy(ip, ipnet.IP.To4())
	ip[3] = 1

	return &FakeIPStore{
		domainIP:  make(map[string]net.IP),
		ipDomain:  make(map[string]string),
		currentIP: ip,
		subnet:    ipnet,
	}, nil
}

// Get returns a fake IP for the given domain
func (s *FakeIPStore) Get(domain string) net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain = strings.ToLower(domain)

	// Return existing IP if available
	if ip, ok := s.domainIP[domain]; ok {
		return ip
	}

	// Allocate new IP
	ip := make(net.IP, 4)
	copy(ip, s.currentIP)

	s.domainIP[domain] = ip
	s.ipDomain[ip.String()] = domain

	// Increment current IP
	s.nextIP()

	return ip
}

// GetDomain returns the domain for a fake IP
func (s *FakeIPStore) GetDomain(ip net.IP) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domain, ok := s.ipDomain[ip.String()]
	return domain, ok
}

// Contains checks if an IP is a fake IP in our range
func (s *FakeIPStore) Contains(ip net.IP) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.subnet.Contains(ip)
}

// nextIP increments the current IP
func (s *FakeIPStore) nextIP() {
	// 198.18.x.x range, skip 198.18.255.255
	for {
		// Increment by 1
		carry := uint32(1)
		for i := 3; i >= 0 && carry > 0; i-- {
			sum := uint32(s.currentIP[i]) + carry
			s.currentIP[i] = byte(sum & 0xFF)
			carry = sum >> 8
		}

		// Skip network address (198.18.0.0/15) and broadcast (198.19.255.255)
		// Only use 198.18.0.1 - 198.19.255.254
		if s.subnet.Contains(s.currentIP) && !s.currentIP.Equal(net.IPv4(198, 19, 255, 255)) {
			return
		}
	}
}

// Size returns the total number of allocated fake IPs
func (s *FakeIPStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.domainIP)
}

// Clear removes all mappings
func (s *FakeIPStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.domainIP = make(map[string]net.IP)
	s.ipDomain = make(map[string]string)
}

// EnhancedDNSHandler handles DNS requests with enhanced mode
type EnhancedDNSHandler struct {
	store    *FakeIPStore
	upstream DNSUpstream
	mode     EnhancedMode
	filters  []string
	mu       sync.RWMutex
}

// NewEnhancedDNSHandler creates a new enhanced DNS handler
func NewEnhancedDNSHandler(mode EnhancedMode, fakeIPCIDR string, upstream DNSUpstream) (*EnhancedDNSHandler, error) {
	store, err := NewFakeIPStore(fakeIPCIDR)
	if err != nil {
		return nil, err
	}

	return &EnhancedDNSHandler{
		store:    store,
		upstream: upstream,
		mode:     mode,
		filters:  defaultFakeIPFilters,
	}, nil
}

// defaultFakeIPFilters contains default domains to fake
var defaultFakeIPFilters = []string{
	"+.google.com",
	"+.googleapis.com",
	"+.googleusercontent.com",
	"+.youtube.com",
	"+.googlevideo.com",
	"+.gstatic.com",
	"+.facebook.com",
	"+.instagram.com",
	"+.twitter.com",
	"+.github.com",
	"+.githubusercontent.com",
	"+.tiktok.com",
	"+.netflix.com",
	"+.spotify.com",
}

// HandleDNS handles a DNS request
func (h *EnhancedDNSHandler) HandleDNS(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, fmt.Errorf("no question in request")
	}

	q := req.Question[0]
	domain := strings.ToLower(drimStr(q.Name, "."))

	// Check if we should fake this domain
	shouldFake := h.shouldFake(domain)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Compress = true

	switch q.Qtype {
	case dns.TypeA:
		if shouldFake || h.mode == ModeFakeIPOnly {
			// Return fake IP for A record
			ip := h.store.Get(domain)
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: ip,
			}
			resp.Answer = append(resp.Answer, rr)
		} else {
			// Query upstream
			upstreamResp, err := h.upstream.Exchange(ctx, req)
			if err != nil {
				return nil, err
			}
			resp.Answer = upstreamResp.Answer
		}

	case dns.TypeAAAA:
		if shouldFake || h.mode == ModeFakeIPOnly {
			// Return fake AAAA (::0) or no response
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.IPv6zero,
			}
			resp.Answer = append(resp.Answer, rr)
		} else {
			// Query upstream
			upstreamResp, err := h.upstream.Exchange(ctx, req)
			if err != nil {
				return nil, err
			}
			resp.Answer = upstreamResp.Answer
		}

	default:
		// Pass through to upstream for other record types
		upstreamResp, err := h.upstream.Exchange(ctx, req)
		if err != nil {
			return nil, err
		}
		resp.Answer = upstreamResp.Answer
		resp.Extra = upstreamResp.Extra
	}

	return resp, nil
}

// shouldFake determines if a domain should use fake IP
func (h *EnhancedDNSHandler) shouldFake(domain string) bool {
	domain = strings.ToLower(domain)

	for _, filter := range h.filters {
		filter = strings.ToLower(filter)

		// + prefix means exact match
		if strings.HasPrefix(filter, "+.") {
			suffix := filter[2:]
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return true
			}
		} else if strings.HasPrefix(filter, "++") {
			// ++ means full domain match
			suffix := filter[2:]
			if domain == suffix {
				return true
			}
		} else {
			// Default: suffix match
			if strings.HasSuffix(domain, "."+filter) || domain == filter {
				return true
			}
		}
	}

	return false
}

// AddFilter adds a fake IP filter
func (h *EnhancedDNSHandler) AddFilter(filter string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.filters = append(h.filters, filter)
}

// SetFilters sets all fake IP filters
func (h *EnhancedDNSHandler) SetFilters(filters []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.filters = filters
}

// GetStats returns statistics
func (h *EnhancedDNSHandler) GetStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return map[string]interface{}{
		"fake_ip_count": h.store.Size(),
		"filter_count":  len(h.filters),
		"mode":          h.mode,
	}
}

// Helper function to trim string
func drimStr(s, cutset string) string {
	s = strings.TrimPrefix(s, cutset)
	return strings.TrimSuffix(s, cutset)
}

// ParseDoHConfig parses DoH configuration
func ParseDoHConfig(configJSON string) (string, error) {
	var config struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(configJSON), &config); err == nil && config.URL != "" {
		return config.URL, nil
	}
	return configJSON, nil // Assume it's already a URL
}

// BuildDoHURL builds a standard DoH URL
func BuildDoHURL(provider string) (string, error) {
	switch strings.ToLower(provider) {
	case "google", "google-doh":
		return "https://dns.google/dns-query", nil
	case "cloudflare", "cf-doh":
		return "https://cloudflare-dns.com/dns-query", nil
	case "quad9":
		return "https://dns.quad9.net/dns-query", nil
	case "adguard":
		return "https://dns.adguard.com/dns-query", nil
	case "alidns", "ali":
		return "https://dns.alidns.com/dns-query", nil
	default:
		// Assume it's already a URL
		if strings.HasPrefix(provider, "https://") {
			return provider, nil
		}
		return "", fmt.Errorf("unknown DoH provider: %s", provider)
	}
}
