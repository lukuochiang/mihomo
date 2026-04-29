package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// StackType defines the type of network stack
type StackType string

const (
	StackTypeSystem    StackType = "system"
	StackTypeGVisor    StackType = "gvisor"
	StackTypeWireGuard StackType = "wireguard"
)

// GVisorConfig holds gVisor stack configuration
type GVisorConfig struct {
	// Network configuration
	MTU        int
	Addresses  []net.IPNet
	Routes     []Route
	DNSServers []net.IP

	// TCP/IP stack settings
	TCPRxBufSize int
	TCPTxBufSize int
	UDPRxBufSize int
	UDPTxBufSize int

	// Connection settings
	MaxConnections    int
	ConnectionTimeout time.Duration
}

// Route represents a network route
type Route struct {
	Destination *net.IPNet
	Gateway     net.IP
	Interface   string
}

// DefaultGVisorConfig returns default gVisor configuration
func DefaultGVisorConfig() *GVisorConfig {
	return &GVisorConfig{
		MTU:               1500,
		Addresses:         []net.IPNet{},
		Routes:            []Route{},
		DNSServers:        []net.IP{net.ParseIP("8.8.8.8")},
		TCPRxBufSize:      16 * 1024,
		TCPTxBufSize:      16 * 1024,
		UDPRxBufSize:      16 * 1024,
		UDPTxBufSize:      16 * 1024,
		MaxConnections:    4096,
		ConnectionTimeout: 30 * time.Second,
	}
}

// GVisorStack implements gVisor-style TUN stack
// This is a simplified implementation that provides TCP/IP stack functionality
type GVisorStack struct {
	config  *GVisorConfig
	tun     Device
	handler PacketHandler
	running bool
	mu      sync.RWMutex
	wg      sync.WaitGroup

	// Connection tracking
	connections *ConnectionMap
	endpoints   *EndpointMap

	// Protocol handlers
	tcpHandler  *TCPHandler
	udpHandler  *UDPHandler
	icmpHandler *ICMPHandler
}

// NewGVisorStack creates a new gVisor-style stack
func NewGVisorStack(config *GVisorConfig, tun Device, handler PacketHandler) *GVisorStack {
	if config == nil {
		config = DefaultGVisorConfig()
	}

	stack := &GVisorStack{
		config:      config,
		tun:         tun,
		handler:     handler,
		connections: NewConnectionMap(config.MaxConnections),
		endpoints:   NewEndpointMap(),
		tcpHandler:  NewTCPHandler(config),
		udpHandler:  NewUDPHandler(config),
		icmpHandler: NewICMPHandler(),
	}

	return stack
}

// Start starts the gVisor stack
func (s *GVisorStack) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("stack already running")
	}
	s.running = true
	s.mu.Unlock()

	// Start packet processing loop
	s.wg.Add(1)
	go s.packetLoop(ctx)

	// Start connection cleanup
	s.wg.Add(1)
	go s.cleanupLoop(ctx)

	return nil
}

// Stop stops the gVisor stack
func (s *GVisorStack) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	s.wg.Wait()
	return s.tun.Close()
}

func (s *GVisorStack) packetLoop(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, s.config.MTU+64)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline
		// In practice, we would set a deadline on the TUN device

		n, err := s.tun.Read(buf)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			// Check for timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		if n == 0 {
			continue
		}

		// Parse and handle packet
		go s.handlePacket(buf[:n])
	}
}

func (s *GVisorStack) handlePacket(data []byte) {
	packet, err := ParsePacket(data)
	if err != nil {
		return
	}

	switch packet.Protocol {
	case ProtocolTCP:
		s.tcpHandler.Handle(s, packet)
	case ProtocolUDP:
		s.udpHandler.Handle(s, packet)
	case ProtocolICMP:
		s.icmpHandler.Handle(s, packet)
	}
}

func (s *GVisorStack) cleanupLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.connections.Cleanup()
		}
	}
}

// WritePacket writes a packet to the TUN device
func (s *GVisorStack) WritePacket(packet []byte) error {
	_, err := s.tun.Write(packet)
	return err
}

// ============ TCP Handler ============

// TCPHandler handles TCP packets
type TCPHandler struct {
	config *GVisorConfig
}

// NewTCPHandler creates a new TCP handler
func NewTCPHandler(config *GVisorConfig) *TCPHandler {
	return &TCPHandler{config: config}
}

// Handle handles a TCP packet
func (h *TCPHandler) Handle(stack *GVisorStack, packet *Packet) {
	tcpPkt, err := ParseTCPPacket(packet.Payload)
	if err != nil {
		return
	}

	// Look up or create connection
	key := ConnectionKey{
		SrcIP:   packet.SrcIP.String(),
		DstIP:   packet.DstIP.String(),
		SrcPort: tcpPkt.SrcPort,
		DstPort: tcpPkt.DstPort,
	}

	conn := stack.connections.Get(key)
	if conn == nil {
		// Create new connection
		conn = NewTCPConnection(key, stack)
		stack.connections.Add(key, conn)
	}

	conn.Handle(tcpPkt)
}

// TCPConnection represents a TCP connection
type TCPConnection struct {
	Key        ConnectionKey
	State      TCPState
	stack      *GVisorStack
	mu         sync.RWMutex
	lastActive time.Time
}

// TCPState represents TCP connection state
type TCPState int

const (
	TCPStateClosed TCPState = iota
	TCPStateListen
	TCPStateSynSent
	TCPStateSynReceived
	TCPStateEstablished
	TCPStateFinWait1
	TCPStateFinWait2
	TCPStateCloseWait
	TCPStateClosing
	TCPStateLastAck
	TCPStateTimeWait
)

// NewTCPConnection creates a new TCP connection
func NewTCPConnection(key ConnectionKey, stack *GVisorStack) *TCPConnection {
	return &TCPConnection{
		Key:        key,
		State:      TCPStateClosed,
		stack:      stack,
		lastActive: time.Now(),
	}
}

// Handle handles a TCP packet
func (c *TCPConnection) Handle(pkt *TCPPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.State {
	case TCPStateClosed:
		// Handle incoming SYN
		if pkt.Flags&TCPFlagSYN != 0 {
			c.State = TCPStateSynReceived
			// Send SYN-ACK
			c.sendPacket(pkt, TCPFlagSYN|TCPFlagACK)
		}
	case TCPStateSynReceived:
		// Handle ACK
		if pkt.Flags&TCPFlagACK != 0 {
			c.State = TCPStateEstablished
		}
	case TCPStateEstablished:
		// Handle data or FIN
		if pkt.Flags&TCPFlagFIN != 0 {
			c.State = TCPStateCloseWait
			c.sendPacket(pkt, TCPFlagACK)
			c.State = TCPStateLastAck
			c.sendPacket(pkt, TCPFlagFIN|TCPFlagACK)
		}
	case TCPStateFinWait1:
		if pkt.Flags&TCPFlagACK != 0 {
			c.State = TCPStateFinWait2
		}
	case TCPStateFinWait2:
		if pkt.Flags&TCPFlagFIN != 0 {
			c.sendPacket(pkt, TCPFlagACK)
			c.State = TCPStateTimeWait
		}
	}

	c.lastActive = time.Now()
}

func (c *TCPConnection) sendPacket(inPkt *TCPPacket, flags uint8) {
	// Build response packet
	// In practice, this would construct a proper TCP packet
	_ = inPkt
	_ = flags
}

// ============ UDP Handler ============

// UDPHandler handles UDP packets
type UDPHandler struct {
	config *GVisorConfig
}

// NewUDPHandler creates a new UDP handler
func NewUDPHandler(config *GVisorConfig) *UDPHandler {
	return &UDPHandler{config: config}
}

// Handle handles a UDP packet
func (h *UDPHandler) Handle(stack *GVisorStack, packet *Packet) {
	udpPkt, err := ParseUDPPacket(packet.Payload)
	if err != nil {
		return
	}

	// Check if this is a DNS query
	if udpPkt.DstPort == 53 {
		h.handleDNS(stack, packet, udpPkt)
		return
	}

	// Forward UDP packet through the proxy
	// In practice, this would route the packet through the outbound
}

// handleDNS handles DNS queries
func (h *UDPHandler) handleDNS(stack *GVisorStack, packet *Packet, udp *UDPPacket) {
	// Forward DNS query to configured DNS servers
	// This is a simplified implementation
}

// ============ ICMP Handler ============

// ICMPHandler handles ICMP packets
type ICMPHandler struct{}

// NewICMPHandler creates a new ICMP handler
func NewICMPHandler() *ICMPHandler {
	return &ICMPHandler{}
}

// Handle handles an ICMP packet
func (h *ICMPHandler) Handle(stack *GVisorStack, packet *Packet) {
	// Handle ICMP echo requests
	// In practice, we would respond to ping requests
}

// ============ Connection Management ============

// ConnectionKey identifies a connection
type ConnectionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

// ConnectionMap manages TCP connections
type ConnectionMap struct {
	connections map[ConnectionKey]*TCPConnection
	maxSize     int
	mu          sync.RWMutex
}

// NewConnectionMap creates a new connection map
func NewConnectionMap(maxSize int) *ConnectionMap {
	if maxSize <= 0 {
		maxSize = 4096
	}
	return &ConnectionMap{
		connections: make(map[ConnectionKey]*TCPConnection),
		maxSize:     maxSize,
	}
}

// Get retrieves a connection
func (m *ConnectionMap) Get(key ConnectionKey) *TCPConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connections[key]
}

// Add adds a connection
func (m *ConnectionMap) Add(key ConnectionKey, conn *TCPConnection) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cleanup if full
	if len(m.connections) >= m.maxSize {
		m.cleanupLocked()
	}

	m.connections[key] = conn
}

// Remove removes a connection
func (m *ConnectionMap) Remove(key ConnectionKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.connections, key)
}

// Cleanup removes old connections
func (m *ConnectionMap) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()
}

func (m *ConnectionMap) cleanupLocked() {
	now := time.Now()
	for key, conn := range m.connections {
		if now.Sub(conn.lastActive) > 5*time.Minute {
			delete(m.connections, key)
		}
	}
}

// EndpointMap manages network endpoints
type EndpointMap struct {
	endpoints map[string]*Endpoint
	mu        sync.RWMutex
}

// Endpoint represents a network endpoint
type Endpoint struct {
	IP   net.IP
	Port uint16
}

// NewEndpointMap creates a new endpoint map
func NewEndpointMap() *EndpointMap {
	return &EndpointMap{
		endpoints: make(map[string]*Endpoint),
	}
}

// Add adds an endpoint
func (m *EndpointMap) Add(addr string, ep *Endpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoints[addr] = ep
}

// Get retrieves an endpoint
func (m *EndpointMap) Get(addr string) *Endpoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.endpoints[addr]
}

// ============ DNS Hijack ============

// DNSHijack implements DNS hijacking for TUN mode
type DNSHijack struct {
	stack    *GVisorStack
	fakeIP   string // Fake IP prefix
	upstream []string
}

// NewDNSHijack creates a new DNS hijacker
func NewDNSHijack(stack *GVisorStack, fakeIP, upstream string) *DNSHijack {
	return &DNSHijack{
		stack:    stack,
		fakeIP:   fakeIP,
		upstream: strings.Split(upstream, ","),
	}
}

// HandleDNS handles a DNS query
func (h *DNSHijack) HandleDNS(packet *Packet) (*Packet, error) {
	// Parse DNS query from UDP payload
	// Return fake IP for the queried domain
	return nil, nil
}
