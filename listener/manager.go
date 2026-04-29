package listener

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lukuochiang/mihomo/config"
	"github.com/lukuochiang/mihomo/core/outbound"
	"github.com/lukuochiang/mihomo/core/policy/smart"
)

// Manager manages all listeners
type Manager struct {
	listeners   map[string]*Listener
	dialer      *outbound.Dialer
	smartEngine *smart.Smart
	mu          sync.RWMutex
}

// Listener represents a single listener
type Listener struct {
	Name    string
	Type    string
	ln      net.Listener
	udpConn *net.UDPConn
	proxy   string // Bound proxy group name
	server  interface{}
	closed  bool
	mu      sync.RWMutex
}

// NewManager creates a new listener manager
func NewManager(dialer *outbound.Dialer, sm *smart.Smart) *Manager {
	return &Manager{
		listeners:   make(map[string]*Listener),
		dialer:      dialer,
		smartEngine: sm,
	}
}

// StartListeners starts all configured listeners
func (m *Manager) StartListeners(listeners []config.ListenerConfig) error {
	for _, l := range listeners {
		if err := m.startListener(&l); err != nil {
			return fmt.Errorf("failed to start listener %s: %w", l.Name, err)
		}
	}
	return nil
}

// startListener starts a single listener
func (m *Manager) startListener(cfg *config.ListenerConfig) error {
	// Normalize listen address
	listen := cfg.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", listen, cfg.Port)

	var ln net.Listener
	var err error

	// Create listener based on type
	switch cfg.Type {
	case "mixed":
		ln, err = m.startMixedListener(addr, cfg)
	case "http":
		ln, err = m.startHTTPListener(addr, cfg)
	case "socks":
		ln, err = m.startSOCKSListener(addr, cfg)
	case "shadowsocks":
		ln, err = m.startShadowsocksListener(addr, cfg)
	default:
		// Default to mixed
		ln, err = m.startMixedListener(addr, cfg)
	}

	if err != nil {
		return err
	}

	m.mu.Lock()
	m.listeners[cfg.Name] = &Listener{
		Name:   cfg.Name,
		Type:   cfg.Type,
		ln:     ln,
		proxy:  cfg.Proxy,
		closed: false,
	}
	m.mu.Unlock()

	return nil
}

// startMixedListener starts a mixed HTTP+SOCKS5 listener
func (m *Manager) startMixedListener(addr string, cfg *config.ListenerConfig) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	// Start accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.handleMixedConn(conn, cfg)
		}
	}()

	return ln, nil
}

// handleMixedConn handles a mixed protocol connection
func (m *Manager) handleMixedConn(conn net.Conn, cfg *config.ListenerConfig) {
	defer conn.Close()

	// Read first byte to determine protocol
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return
	}

	// SOCKS5 starts with 0x05
	if buf[0] == 0x05 {
		// Handle as SOCKS5
		m.handleSOCKS5Conn(conn, cfg)
	} else {
		// Handle as HTTP
		m.handleHTTPConn(conn, cfg, buf[0])
	}
}

// handleHTTPConn handles HTTP proxy connection
func (m *Manager) handleHTTPConn(conn net.Conn, cfg *config.ListenerConfig, firstByte byte) {
	// Read the rest of HTTP request
	// For simplicity, we'll implement basic CONNECT handling
	buf := []byte{firstByte}

	// Read until \r\n\r\n or connection close
	tmp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			return
		}
		buf = append(buf, tmp[:n]...)
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			break
		}
		if n == 0 || len(buf) > 65536 {
			break
		}
	}

	// Get proxy target
	node := m.getSelectedNode(cfg.Proxy)
	if node == "" {
		node = "DIRECT"
	}

	// Parse request to get target host
	host := m.parseHTTPHost(string(buf))
	if host == "" {
		return
	}

	// Connect to target
	target, err := m.dialer.Dial(context.Background(), node, host)
	if err != nil {
		return
	}
	defer target.Close()

	// Send 200 Connection Established for CONNECT
	if strings.HasPrefix(string(buf), "CONNECT") {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		// Forward the HTTP request
		target.Write(buf)
	}

	// Bridge connections
	bridgeConns(conn, target)
}

// parseHTTPHost extracts host:port from HTTP request
func (m *Manager) parseHTTPHost(req string) string {
	lines := strings.Split(req, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 2 {
				host := strings.TrimSpace(parts[1])
				if len(parts) == 3 {
					host += ":" + strings.TrimSpace(parts[2])
				} else {
					host += ":80"
				}
				return host
			}
		}
	}
	return ""
}

// handleSOCKS5Conn handles SOCKS5 connection
func (m *Manager) handleSOCKS5Conn(conn net.Conn, cfg *config.ListenerConfig) {
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	// Get auth methods
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := conn.Read(methods); err != nil {
		return
	}

	// Send no-auth response
	conn.Write([]byte{0x05, 0x00})

	// Read request
	buf = make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 { // CMD_CONNECT only
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Parse target address
	var targetAddr string
	switch buf[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := conn.Read(addr); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := conn.Read(port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3],
			int(port[0])<<8|int(port[1]))

	case 0x03: // Domain
		domainLen := make([]byte, 1)
		if _, err := conn.Read(domainLen); err != nil {
			return
		}
		domain := make([]byte, domainLen[0])
		if _, err := conn.Read(domain); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := conn.Read(port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("%s:%d", string(domain), int(port[0])<<8|int(port[1]))

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := conn.Read(addr); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := conn.Read(port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			addr[0]<<8|addr[1], addr[2]<<8|addr[3], addr[4]<<8|addr[5], addr[6]<<8|addr[7],
			addr[8]<<8|addr[9], addr[10]<<8|addr[11], addr[12]<<8|addr[13], addr[14]<<8|addr[15],
			int(port[0])<<8|int(port[1]))
	}

	// Get selected node
	node := m.getSelectedNode(cfg.Proxy)
	if node == "" {
		node = "DIRECT"
	}

	// Connect to target
	target, err := m.dialer.Dial(context.Background(), node, targetAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer target.Close()

	// Send success reply
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Bridge connections
	bridgeConns(conn, target)
}

// startHTTPListener starts HTTP proxy listener
func (m *Manager) startHTTPListener(addr string, cfg *config.ListenerConfig) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.handleHTTPOnlyConn(conn, cfg)
		}
	}()

	return ln, nil
}

// handleHTTPOnlyConn handles HTTP-only connection
func (m *Manager) handleHTTPOnlyConn(conn net.Conn, cfg *config.ListenerConfig) {
	defer conn.Close()

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return
	}

	m.handleHTTPConn(conn, cfg, buf[0])
}

// startSOCKSListener starts SOCKS5 proxy listener
func (m *Manager) startSOCKSListener(addr string, cfg *config.ListenerConfig) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.handleSOCKS5Conn(conn, cfg)
		}
	}()

	return ln, nil
}

// startShadowsocksListener starts Shadowsocks listener
func (m *Manager) startShadowsocksListener(addr string, cfg *config.ListenerConfig) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	// For Shadowsocks, we need to handle the protocol
	// This is a simplified implementation
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.handleShadowsocksConn(conn, cfg)
		}
	}()

	return ln, nil
}

// handleShadowsocksConn handles Shadowsocks connection
func (m *Manager) handleShadowsocksConn(conn net.Conn, cfg *config.ListenerConfig) {
	defer conn.Close()

	// Shadowsocks protocol handling
	// Read header: method specific encryption info + target address
	// This is a simplified placeholder

	// Read first byte to determine address type
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return
	}

	var targetAddr string

	switch buf[0] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := conn.Read(addr); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := conn.Read(port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3],
			int(port[0])<<8|int(port[1]))

	case 0x03: // Domain
		domainLen := make([]byte, 1)
		if _, err := conn.Read(domainLen); err != nil {
			return
		}
		domain := make([]byte, domainLen[0])
		if _, err := conn.Read(domain); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := conn.Read(port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("%s:%d", string(domain), int(port[0])<<8|int(port[1]))

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := conn.Read(addr); err != nil {
			return
		}
		port := make([]byte, 2)
		if _, err := conn.Read(port); err != nil {
			return
		}
		targetAddr = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			addr[0]<<8|addr[1], addr[2]<<8|addr[3], addr[4]<<8|addr[5], addr[6]<<8|addr[7],
			addr[8]<<8|addr[9], addr[10]<<8|addr[11], addr[12]<<8|addr[13], addr[14]<<8|addr[15],
			int(port[0])<<8|int(port[1]))
	}

	// Get selected node
	node := m.getSelectedNode(cfg.Proxy)
	if node == "" {
		node = "DIRECT"
	}

	// Connect to target
	target, err := m.dialer.Dial(context.Background(), node, targetAddr)
	if err != nil {
		return
	}
	defer target.Close()

	// Bridge connections
	bridgeConns(conn, target)
}

// getSelectedNode gets selected node from proxy group or uses default
func (m *Manager) getSelectedNode(proxy string) string {
	if proxy != "" && m.smartEngine != nil {
		// Try to get specific proxy group selection
		// For now, use Smart selection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := m.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}

	// Default: use Smart selection
	if m.smartEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if node, err := m.smartEngine.SelectNode(ctx); err == nil {
			return node
		}
	}

	return ""
}

// Close closes all listeners
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, l := range m.listeners {
		if l.ln != nil {
			l.ln.Close()
		}
		if l.udpConn != nil {
			l.udpConn.Close()
		}
		delete(m.listeners, name)
	}

	return nil
}

// GetListener returns a listener by name
func (m *Manager) GetListener(name string) *Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listeners[name]
}

// ListListeners returns all listener names
func (m *Manager) ListListeners() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.listeners))
	for name := range m.listeners {
		names = append(names, name)
	}
	return names
}
