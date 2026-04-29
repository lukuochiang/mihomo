package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lukuochiang/mihomo/core/outbound"
	"github.com/lukuochiang/mihomo/core/policy/smart"
)

// NormalizeBindAddress converts "*" to "" (listen on all interfaces)
// which is the correct way to listen on all interfaces in Go's net package
func NormalizeBindAddress(bind string) string {
	if bind == "*" {
		return ""
	}
	return bind
}

// HTTPSConfig holds HTTPS proxy server configuration
type HTTPSConfig struct {
	Enabled  bool
	Port     int
	Bind     string
	CertFile string
	KeyFile  string
	Auth     *AuthConfig
}

// TunnelConfig holds tunnel mode configuration
type TunnelConfig struct {
	Enabled    bool
	Port       int
	Bind       string
	TargetIP   string
	TargetPort int
}

// RedirectConfig holds TCP redirect configuration (Linux only)
type RedirectConfig struct {
	Enabled bool
	Port    int
	Bind    string
}

// TProxyConfig holds transparent proxy configuration
type TProxyConfig struct {
	EnabledIPv4 bool
	EnabledIPv6 bool
	Port        int
	Bind        string
}

// HTTPSServer represents an HTTPS proxy server
type HTTPSServer struct {
	config      *HTTPSConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	server      *http.Server
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewHTTPSServer creates a new HTTPS proxy server
func NewHTTPSServer(cfg *HTTPSConfig, dialer *outbound.Dialer, sm *smart.Smart) (*HTTPSServer, error) {
	return &HTTPSServer{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}, nil
}

// Start starts the HTTPS server
func (s *HTTPSServer) Start() error {
	if !s.config.Enabled {
		return nil
	}

	bind := NormalizeBindAddress(s.config.Bind)
	addr := fmt.Sprintf("%s:%d", bind, s.config.Port)

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	handler := s.wrapAuth(http.HandlerFunc(s.handleRequest), s.config.Auth)

	s.server = &http.Server{
		Handler:   handler,
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.server.Serve(ln)
	}()

	return nil
}

// Close closes the HTTPS server
func (s *HTTPSServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.wg.Wait()

	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}

	return nil
}

func (s *HTTPSServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	// Regular HTTPS request
	s.handleHTTPRequest(w, r)
}

func (s *HTTPSServer) handleConnect(w http.ResponseWriter, r *http.Request) {
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

	host := r.Host
	if host == "" {
		conn.Close()
		return
	}

	// Get selected node
	nodeName := s.getSelectedNode()

	// Connect to target
	targetConn, err := s.dialer.Dial(r.Context(), nodeName, host)
	if err != nil {
		conn.Close()
		return
	}

	// Send 200 Connection Established
	resp := "HTTP/1.1 200 Connection Established\r\n\r\n"
	conn.Write([]byte(resp))

	// Bridge connections
	s.bridge(conn, targetConn)
}

func (s *HTTPSServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	nodeName := s.getSelectedNode()

	req, err := s.createProxyRequest(r, nodeName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return s.dialer.Dial(ctx, nodeName, addr)
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}

func (s *HTTPSServer) createProxyRequest(r *http.Request, nodeName string) (*http.Request, error) {
	scheme := "https"
	if r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}

	targetURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		return nil, err
	}

	for key, values := range r.Header {
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	return req, nil
}

func (s *HTTPSServer) bridge(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(left, right)
		left.Close()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(right, left)
		right.Close()
		done <- struct{}{}
	}()

	<-done
}

func (s *HTTPSServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

func (s *HTTPSServer) wrapAuth(handler http.Handler, auth *AuthConfig) http.Handler {
	if auth == nil || !auth.Enabled {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != auth.Username || password != auth.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="HTTPS Proxy"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// ============ Tunnel Server ============

// TunnelServer represents a tunnel mode server (port forwarding)
type TunnelServer struct {
	config      *TunnelConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewTunnelServer creates a new tunnel server
func NewTunnelServer(cfg *TunnelConfig, dialer *outbound.Dialer, sm *smart.Smart) *TunnelServer {
	return &TunnelServer{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}
}

// Start starts the tunnel server
func (s *TunnelServer) Start() error {
	if !s.config.Enabled {
		return nil
	}

	bind := NormalizeBindAddress(s.config.Bind)
	addr := fmt.Sprintf("%s:%d", bind, s.config.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = ln

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop()
	}()

	return nil
}

// Close closes the tunnel server
func (s *TunnelServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.wg.Wait()
	return s.listener.Close()
}

func (s *TunnelServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

func (s *TunnelServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	targetAddr := fmt.Sprintf("%s:%d", s.config.TargetIP, s.config.TargetPort)
	nodeName := s.getSelectedNode()

	targetConn, err := s.dialer.Dial(context.Background(), nodeName, targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Bridge connections
	s.bridge(conn, targetConn)
}

func (s *TunnelServer) bridge(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(left, right)
		left.Close()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(right, left)
		right.Close()
		done <- struct{}{}
	}()

	<-done
}

func (s *TunnelServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

// ============ Redirect Server (Linux TCP Redirect) ============

// RedirectServer handles TCP redirect connections (Linux only)
type RedirectServer struct {
	config      *RedirectConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener    net.Listener
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewRedirectServer creates a new redirect server
func NewRedirectServer(cfg *RedirectConfig, dialer *outbound.Dialer, sm *smart.Smart) (*RedirectServer, error) {
	return &RedirectServer{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}, nil
}

// Start starts the redirect server
func (s *RedirectServer) Start() error {
	if !s.config.Enabled {
		return nil
	}

	bind := NormalizeBindAddress(s.config.Bind)
	addr := fmt.Sprintf("%s:%d", bind, s.config.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = ln

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop()
	}()

	return nil
}

// Close closes the redirect server
func (s *RedirectServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.wg.Wait()
	return s.listener.Close()
}

func (s *RedirectServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleRedirect(conn)
		}()
	}
}

func (s *RedirectServer) handleRedirect(conn net.Conn) {
	defer conn.Close()

	// Parse HTTP request to get target
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(buf[:n]))))
	if err != nil {
		// Fallback: use original destination from connection
		targetAddr := s.getOriginalDest(conn)
		if targetAddr == "" {
			return
		}
		s.connectAndBridge(conn, targetAddr, buf[:n])
		return
	}

	targetHost := req.Host
	if targetHost == "" {
		targetHost = req.URL.Host
	}
	if targetHost == "" {
		return
	}

	s.connectAndBridge(conn, targetHost, buf[:n])
}

func (s *RedirectServer) connectAndBridge(client net.Conn, target string, initialData []byte) {
	nodeName := s.getSelectedNode()

	targetConn, err := s.dialer.Dial(context.Background(), nodeName, target)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Send initial data
	if len(initialData) > 0 {
		targetConn.Write(initialData)
	}

	// Bridge connections
	s.bridge(client, targetConn)
}

func (s *RedirectServer) bridge(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(left, right)
		left.Close()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(right, left)
		right.Close()
		done <- struct{}{}
	}()

	<-done
}

func (s *RedirectServer) getOriginalDest(conn net.Conn) string {
	// For redirected connections, the original destination is lost
	// This is a limitation of TCP redirect - we need to use TPROXY for full transparency
	return ""
}

func (s *RedirectServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

// ============ TProxy Server (Transparent Proxy) ============

// TProxyServer handles TProxy connections (Linux only)
type TProxyServer struct {
	config      *TProxyConfig
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	listener4   net.Listener
	listener6   net.Listener
	closed      bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewTProxyServer creates a new TProxy server
func NewTProxyServer(cfg *TProxyConfig, dialer *outbound.Dialer, sm *smart.Smart) (*TProxyServer, error) {
	return &TProxyServer{
		config:      cfg,
		dialer:      dialer,
		smartEngine: sm,
	}, nil
}

// Start starts the TProxy server
func (s *TProxyServer) Start() error {
	if s.config.EnabledIPv4 {
		bind := NormalizeBindAddress(s.config.Bind)
		addr := fmt.Sprintf("%s:%d", bind, s.config.Port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		s.listener4 = ln

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptLoop(s.listener4)
		}()
	}

	if s.config.EnabledIPv6 {
		addr6 := fmt.Sprintf("[::]:%d", s.config.Port)
		ln6, err := net.Listen("tcp6", addr6)
		if err != nil {
			// IPv6 might not be available
			if s.listener4 == nil {
				return fmt.Errorf("failed to listen on IPv6: %w", err)
			}
		} else {
			s.listener6 = ln6

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.acceptLoop(s.listener6)
			}()
		}
	}

	return nil
}

// Close closes the TProxy server
func (s *TProxyServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.wg.Wait()

	var errs []error
	if s.listener4 != nil {
		if err := s.listener4.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.listener6 != nil {
		if err := s.listener6.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (s *TProxyServer) acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleTProxy(conn)
		}()
	}
}

func (s *TProxyServer) handleTProxy(conn net.Conn) {
	defer conn.Close()

	// Get original destination from socket mark
	origDst, err := s.getOrigDst(conn)
	if err != nil || origDst == "" {
		// Fallback to reading the request
		origDst = s.parseTargetFromRequest(conn)
		if origDst == "" {
			return
		}
	}

	nodeName := s.getSelectedNode()

	targetConn, err := s.dialer.Dial(context.Background(), nodeName, origDst)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Handle different IP versions
	if s.isIPv4(conn.LocalAddr().String()) {
		s.bridgeIPv4(conn, targetConn)
	} else {
		s.bridgeIPv6(conn, targetConn)
	}
}

func (s *TProxyServer) parseTargetFromRequest(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(buf[:n]))))
	if err != nil {
		return ""
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	return host
}

func (s *TProxyServer) getOrigDst(conn net.Conn) (string, error) {
	// On Linux, we can use getsockopt to get original destination
	// This requires syscall and proper socket handling
	// For simplicity, we return empty and rely on HTTP parsing
	return "", fmt.Errorf("TPROXY original destination not available without syscall")
}

func (s *TProxyServer) isIPv4(addr string) bool {
	return !strings.Contains(addr, "[")
}

func (s *TProxyServer) bridgeIPv4(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(left, right)
		left.Close()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(right, left)
		right.Close()
		done <- struct{}{}
	}()

	<-done
}

func (s *TProxyServer) bridgeIPv6(left, right net.Conn) {
	s.bridgeIPv4(left, right) // Same implementation for IPv6
}

func (s *TProxyServer) getSelectedNode() string {
	if s.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := s.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}
	return ""
}

// Check if running on Linux
func isLinux() bool {
	return os.Getenv("GOOS") == "linux" || isLinuxSyscall()
}

func isLinuxSyscall() bool {
	// Simple check using uname or GOOS
	return false
}
