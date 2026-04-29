package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSOverHTTPS implements DNS-over-HTTPS (DoH)
type DNSOverHTTPS struct {
	server  string
	client  *http.Client
	enabled bool
}

// NewDoH creates a new DoH client
func NewDoH(server string) (*DNSOverHTTPS, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("DoH requires HTTPS")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
		Timeout: 10 * time.Second,
	}

	return &DNSOverHTTPS{
		server:  server,
		client:  client,
		enabled: true,
	}, nil
}

// Query performs a DNS query over HTTPS
func (d *DNSOverHTTPS) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if !d.enabled {
		return nil, fmt.Errorf("DoH is disabled")
	}

	// Serialize the request
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", d.server, strings.NewReader(string(buf)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send DoH request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Unpack DNS message
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	return dnsResp, nil
}

// QueryWithGET performs a DNS query using GET method
func (d *DNSOverHTTPS) QueryWithGET(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if !d.enabled {
		return nil, fmt.Errorf("DoH is disabled")
	}

	// Serialize the request
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Encode as base64url (without padding)
	encoded := encodeBase64URL(buf)

	// Create URL with encoded query
	reqURL := d.server
	if !strings.Contains(reqURL, "?") {
		reqURL += "?dns=" + encoded
	} else {
		reqURL += "&dns=" + encoded
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")

	// Send request
	resp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send DoH request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Unpack DNS message
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	return dnsResp, nil
}

// IsEnabled returns whether DoH is enabled
func (d *DNSOverHTTPS) IsEnabled() bool {
	return d.enabled
}

// Enable enables DoH
func (d *DNSOverHTTPS) Enable() {
	d.enabled = true
}

// Disable disables DoH
func (d *DNSOverHTTPS) Disable() {
	d.enabled = false
}

// encodeBase64URL encodes bytes to base64url without padding
func encodeBase64URL(data []byte) string {
	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	result := make([]byte, (len(data)+2)/3*4)
	for i := 0; i < len(data); i += 3 {
		var n uint32
		switch len(data) - i {
		case 1:
			n = uint32(data[i]) << 16
		case 2:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8
		default:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
		}
		result[i/3*4] = encodeStd[n>>18&0x3F]
		result[i/3*4+1] = encodeStd[n>>12&0x3F]
		result[i/3*4+2] = encodeStd[n>>6&0x3F]
		result[i/3*4+3] = encodeStd[n&0x3F]
	}

	// Remove padding and replace +/ with -_
	padLen := (4 - len(data)%3) % 4
	for i := 0; i < padLen; i++ {
		result[len(result)-1-i] = '='
	}

	out := make([]byte, len(result))
	for i, c := range result {
		switch c {
		case '+':
			out[i] = '-'
		case '/':
			out[i] = '_'
		case '=':
			out[i] = 0
		default:
			out[i] = c
		}
	}

	// Count non-zero bytes
	nonZero := 0
	for _, c := range out {
		if c != 0 {
			nonZero++
		}
	}

	return string(out[:nonZero])
}

// DNSOverTLS implements DNS-over-TLS (DoT)
type DNSOverTLS struct {
	server  string
	address string
	conn    *tls.Conn
	enabled bool
}

// NewDoT creates a new DoT client
func NewDoT(server string) (*DNSOverTLS, error) {
	// Remove scheme if present
	address := server
	if strings.HasPrefix(address, "tls://") {
		address = strings.TrimPrefix(address, "tls://")
	} else if strings.HasPrefix(address, "https://") {
		return nil, fmt.Errorf("use DoH for HTTPS")
	}

	// Remove port if present
	if strings.Contains(address, ":") {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		address = host
	}

	return &DNSOverTLS{
		server:  server,
		address: address,
		enabled: true,
	}, nil
}

// Connect establishes a TLS connection
func (d *DNSOverTLS) Connect(ctx context.Context) error {
	if !d.enabled {
		return fmt.Errorf("DoT is disabled")
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.address+":853")
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         d.address,
		InsecureSkipVerify: false,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	d.conn = tlsConn
	return nil
}

// Query performs a DNS query over TLS
func (d *DNSOverTLS) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if d.conn == nil {
		if err := d.Connect(ctx); err != nil {
			return nil, err
		}
	}

	// Serialize the request
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Send length prefix
	LenBuf := make([]byte, 2)
	LenBuf[0] = byte(len(buf) >> 8)
	LenBuf[1] = byte(len(buf))

	if _, err := d.conn.Write(LenBuf); err != nil {
		return nil, fmt.Errorf("failed to write length: %w", err)
	}

	if _, err := d.conn.Write(buf); err != nil {
		return nil, fmt.Errorf("failed to write query: %w", err)
	}

	// Read response length
	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(d.conn, respLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])

	// Read response
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(d.conn, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Unpack DNS message
	resp := new(dns.Msg)
	if err := resp.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	return resp, nil
}

// Close closes the TLS connection
func (d *DNSOverTLS) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

// IsEnabled returns whether DoT is enabled
func (d *DNSOverTLS) IsEnabled() bool {
	return d.enabled
}

// Enable enables DoT
func (d *DNSOverTLS) Enable() {
	d.enabled = true
}

// Disable disables DoT
func (d *DNSOverTLS) Disable() {
	d.enabled = false
}

// DNSResolver is a unified DNS resolver supporting multiple protocols
type DNSResolver struct {
	upstreams []Upstream
	strategy  Strategy
}

// Upstream represents a DNS upstream server
type Upstream interface {
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// Strategy defines the DNS resolution strategy
type Strategy string

const (
	StrategyPreferIPv4 Strategy = "prefer_ipv4"
	StrategyPreferIPv6 Strategy = "prefer_ipv6"
	StrategyOnlyIPv4   Strategy = "only_ipv4"
	StrategyOnlyIPv6   Strategy = "only_ipv6"
)

// NewDNSResolver creates a new DNS resolver
func NewDNSResolver(servers []string, strategy Strategy) (*DNSResolver, error) {
	r := &DNSResolver{
		strategy: strategy,
	}

	for _, server := range servers {
		upstream, err := r.createUpstream(server)
		if err != nil {
			continue // Skip invalid upstreams
		}
		r.upstreams = append(r.upstreams, upstream)
	}

	if len(r.upstreams) == 0 {
		return nil, fmt.Errorf("no valid upstream servers")
	}

	return r, nil
}

func (r *DNSResolver) createUpstream(server string) (Upstream, error) {
	// Check for DoH
	if strings.HasPrefix(server, "https://") {
		return NewDoH(server)
	}

	// Check for DoT
	if strings.HasPrefix(server, "tls://") {
		return NewDoT(server)
	}

	// Regular UDP/TCP DNS
	return &UDPDNS{server: server}, nil
}

// Query resolves a DNS query
func (r *DNSResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var lastErr error

	for _, upstream := range r.upstreams {
		resp, err := upstream.Query(ctx, req)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}

	return nil, lastErr
}

// UDPDNS is a simple UDP DNS upstream
type UDPDNS struct {
	server string
}

// Query performs a DNS query over UDP
func (u *UDPDNS) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	resp, _, err := client.ExchangeContext(ctx, req, u.server)
	return resp, err
}
