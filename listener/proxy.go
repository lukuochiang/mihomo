package listener

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lukuochiang/mihomo/core/outbound"
	"github.com/lukuochiang/mihomo/core/policy/smart"
	"github.com/lukuochiang/mihomo/core/pool"
)

// ProxyServer represents a local proxy server
type ProxyServer struct {
	config      *ProxyConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	httpServ    *http.Server
	socksServ   *socks5Server
	wg          sync.WaitGroup
	closed      bool
	mu          sync.RWMutex
}

// ProxyConfig holds proxy server configuration
type ProxyConfig struct {
	HTTPEnabled  bool
	HTTPPort     int
	HTTPBind     string
	SOCKSEnabled bool
	SOCKSPort    int
	SOCKSBind    string
	Auth         *AuthConfig
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Username string
	Password string
	Enabled  bool
}

// NewProxyServer creates a new proxy server
func NewProxyServer(cfg *ProxyConfig, dialer *outbound.Dialer, sm *smart.Smart) *ProxyServer {
	return &ProxyServer{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}
}

// Start starts the proxy server
func (p *ProxyServer) Start() error {
	if p.config.HTTPEnabled {
		if err := p.startHTTP(); err != nil {
			return fmt.Errorf("failed to start HTTP proxy: %w", err)
		}
	}

	if p.config.SOCKSEnabled {
		if err := p.startSOCKS5(); err != nil {
			return fmt.Errorf("failed to start SOCKS5 proxy: %w", err)
		}
	}

	return nil
}

// Close closes the proxy server
func (p *ProxyServer) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	p.wg.Wait()

	if p.httpServ != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.httpServ.Shutdown(ctx)
	}

	if p.socksServ != nil {
		p.socksServ.Close()
	}

	return nil
}

func (p *ProxyServer) startHTTP() error {
	bind := NormalizeBindAddress(p.config.HTTPBind)
	addr := fmt.Sprintf("%s:%d", bind, p.config.HTTPPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleHTTP)

	handler := p.wrapAuth(http.HandlerFunc(p.handleConnect), p.config.Auth)

	p.httpServ = &http.Server{
		Handler: handler,
		Addr:    addr,
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.httpServ.Serve(ln)
	}()

	return nil
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Regular HTTP request
	p.handleHTTPRequest(w, r)
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get target address
	host := r.Host
	if host == "" {
		conn.Close()
		return
	}

	// Connect to target
	targetConn, err := p.dialer.Dial(r.Context(), p.getSelectedNode(), host)
	if err != nil {
		conn.Close()
		return
	}

	// Send 200 Connection Established
	resp := "HTTP/1.1 200 Connection Established\r\n\r\n"
	conn.Write([]byte(resp))

	// Bridge connections
	p.bridge(conn, targetConn)
}

func (p *ProxyServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Select node
	nodeName := p.getSelectedNode()

	// Create proxy request
	req, err := p.createProxyRequest(r, nodeName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Send request through proxy
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return p.dialer.Dial(ctx, nodeName, addr)
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

func (p *ProxyServer) createProxyRequest(r *http.Request, nodeName string) (*http.Request, error) {
	// Build target URL
	scheme := "http"
	if r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	} else if r.TLS != nil {
		scheme = "https"
	}

	targetURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Create new request
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		return nil, err
	}

	// Copy headers
	for key, values := range r.Header {
		// Skip hop-by-hop headers
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	return req, nil
}

func (p *ProxyServer) bridge(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	done := make(chan struct{}, 2)

	go func() {
		pool.PooledCopy(left, right)
		left.Close()
		done <- struct{}{}
	}()

	go func() {
		pool.PooledCopy(right, left)
		right.Close()
		done <- struct{}{}
	}()

	<-done
}

func (p *ProxyServer) getSelectedNode() string {
	if p.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := p.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

func (p *ProxyServer) wrapAuth(handler http.Handler, auth *AuthConfig) http.Handler {
	if auth == nil || !auth.Enabled {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != auth.Username || password != auth.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Proxy"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func isHopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailers",
		"transfer-encoding", "upgrade":
		return true
	}
	return false
}

// ============ SOCKS5 Server ============

type socks5Server struct {
	config      *ProxyConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

func newSOCKS5Server(cfg *ProxyConfig, dialer *outbound.Dialer, sm *smart.Smart) *socks5Server {
	return &socks5Server{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}
}

func (s *socks5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.wg.Wait()
	return s.listener.Close()
}

func (p *ProxyServer) startSOCKS5() error {
	bind := NormalizeBindAddress(p.config.SOCKSBind)
	addr := fmt.Sprintf("%s:%d", bind, p.config.SOCKSPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	p.socksServ = newSOCKS5Server(p.config, p.dialer, p.smartEngine)
	p.socksServ.listener = ln

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.socksServ.acceptLoop()
	}()

	return nil
}

func (s *socks5Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSOCKS5(conn)
		}()
	}
}

func (s *socks5Server) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 greeting
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	// Verify version
	if buf[0] != 0x05 {
		return
	}

	// Get authentication methods
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Check for no-authentication (0x00) or username/password (0x02)
	hasNoAuth := false
	hasUserPass := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
		}
		if m == 0x02 {
			hasUserPass = true
		}
	}

	// Determine auth method
	var authMethod byte = 0xFF
	if s.config.Auth != nil && s.config.Auth.Enabled && hasUserPass {
		authMethod = 0x02
	} else if hasNoAuth {
		authMethod = 0x00
	}

	// Send method selection
	conn.Write([]byte{0x05, authMethod})
	if authMethod == 0xFF {
		return
	}

	// Authentication
	if authMethod == 0x02 {
		if !s.authenticateUserPass(conn) {
			return
		}
	}

	// SOCKS5 request
	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	if buf[0] != 0x05 {
		return
	}

	// Parse address
	var targetAddr string
	switch buf[1] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3],
			binary.BigEndian.Uint16(port))

	case 0x03: // Domain name
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("%s:%d", string(domain), binary.BigEndian.Uint16(port))

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			addr[0:2], addr[2:4], addr[4:6], addr[6:8], addr[8:10], addr[10:12], addr[12:14], addr[14:16],
			binary.BigEndian.Uint16(port))

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Get selected node
	nodeName := s.getSelectedNode()

	// Connect to target
	targetConn, err := s.dialer.Dial(context.Background(), nodeName, targetAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()

	// Send success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(reply)

	// Bridge connections
	s.bridge(conn, targetConn)
}

func (s *socks5Server) authenticateUserPass(conn net.Conn) bool {
	// Read version
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	if buf[0] != 0x01 {
		return false
	}

	// Read username
	ulen := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulen); err != nil {
		return false
	}
	username := make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		return false
	}

	// Read password
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return false
	}
	password := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return false
	}

	// Verify credentials
	if string(username) == s.config.Auth.Username &&
		string(password) == s.config.Auth.Password {
		conn.Write([]byte{0x01, 0x00})
		return true
	}

	conn.Write([]byte{0x01, 0x01})
	return false
}

func (s *socks5Server) bridge(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	done := make(chan struct{}, 2)

	go func() {
		pool.PooledCopy(left, right)
		left.Close()
		done <- struct{}{}
	}()

	go func() {
		pool.PooledCopy(right, left)
		right.Close()
		done <- struct{}{}
	}()

	<-done
}

func (s *socks5Server) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}
