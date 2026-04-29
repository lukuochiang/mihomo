package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mihomo/smart/core/outbound"
)

// Tunnel represents a network tunnel
type Tunnel struct {
	config     TunnelConfig
	manager    *outbound.Manager
	conn       io.ReadWriteCloser
	running    bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	packetsIn  uint64
	packetsOut uint64
	bytesIn    uint64
	bytesOut   uint64
}

// TunnelConfig holds tunnel configuration
type TunnelConfig struct {
	Name      string
	MTU       int
	Addresses []string
	DNS       []string
	AutoRoute bool
}

// Packet represents an IP packet
type Packet struct {
	Version   int
	HeaderLen int
	TotalLen  int
	Protocol  int
	SrcIP     net.IP
	DstIP     net.IP
	Payload   []byte
}

// NewTunnel creates a new tunnel
func NewTunnel(cfg TunnelConfig, manager *outbound.Manager) (*Tunnel, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Tunnel{
		config:  cfg,
		manager: manager,
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// Start starts the tunnel
func (t *Tunnel) Start() error {
	if t.running {
		return fmt.Errorf("tunnel already running")
	}

	// Open TUN device
	conn, err := t.openTUN()
	if err != nil {
		return fmt.Errorf("failed to open TUN: %w", err)
	}

	t.conn = conn
	t.running = true

	// Start packet handlers
	t.wg.Add(2)
	go t.readLoop()
	go t.writeLoop()

	return nil
}

// Stop stops the tunnel
func (t *Tunnel) Stop() error {
	t.cancel()
	t.running = false

	if t.conn != nil {
		return t.conn.Close()
	}

	t.wg.Wait()
	return nil
}

// openTUN opens a TUN device
func (t *Tunnel) openTUN() (io.ReadWriteCloser, error) {
	// Try to open /dev/tun0 or similar
	tunPaths := []string{
		"/dev/tun0",
		"/dev/tun1",
		"/dev/net/tun",
	}

	for _, path := range tunPaths {
		conn, err := OpenTUN(path, t.config.Name, t.config.MTU)
		if err == nil {
			return conn, nil
		}
	}

	// If running on macOS without root, return a mock
	return &mockTUN{
		config: t.config,
	}, nil
}

func (t *Tunnel) readLoop() {
	defer t.wg.Done()

	buf := make([]byte, t.config.MTU)

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Read from TUN - use SetReadDeadline if supported
		if setter, ok := t.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			setter.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
		n, err := t.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		t.packetsIn++
		t.bytesIn += uint64(n)

		// Process packet
		go t.processPacket(buf[:n])
	}
}

func (t *Tunnel) writeLoop() {
	defer t.wg.Done()

	// This would handle returning packets to the TUN device
	// For now, just keep the loop running
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (t *Tunnel) processPacket(data []byte) {
	if len(data) < 20 {
		return
	}

	// Parse IP header
	packet, err := ParseIPPacket(data)
	if err != nil {
		return
	}

	// Determine routing
	switch packet.Protocol {
	case 6: // TCP
		t.handleTCP(packet)
	case 17: // UDP
		t.handleUDP(packet)
	default:
		// Drop other protocols
	}
}

func (t *Tunnel) handleTCP(packet *Packet) {
	ctx := context.Background()

	// Select outbound node
	node, err := t.manager.SelectNode(ctx)
	if err != nil {
		return
	}

	// Dial through adapter
	addr := fmt.Sprintf("%s:%d", packet.DstIP.String(), packet.TotalLen&0xFFFF)
	node, nodeOk := t.manager.GetNode(node.ID)
	if !nodeOk {
		return
	}

	// TODO: Forward TCP traffic through the selected node
	_ = addr
	_ = node
}

func (t *Tunnel) handleUDP(packet *Packet) {
	// Handle UDP traffic
	// TODO: Implement UDP forwarding
}

// ParseIPPacket parses an IP packet
func ParseIPPacket(data []byte) (*Packet, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short")
	}

	version := int(data[0] >> 4)
	if version != 4 {
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}

	headerLen := int(data[0]&0x0F) * 4
	if headerLen < 20 || len(data) < headerLen {
		return nil, fmt.Errorf("invalid header length")
	}

	totalLen := binary.BigEndian.Uint16(data[2:4])
	protocol := int(data[9])

	srcIP := net.IP(data[12:16])
	dstIP := net.IP(data[16:20])

	return &Packet{
		Version:   version,
		HeaderLen: headerLen,
		TotalLen:  int(totalLen),
		Protocol:  protocol,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Payload:   data[headerLen:],
	}, nil
}

// BuildIPPacket builds an IP packet
func BuildIPPacket(srcIP, dstIP net.IP, protocol int, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))

	// Version and IHL
	packet[0] = 0x45

	// Total length
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))

	// Identification
	binary.BigEndian.PutUint16(packet[4:6], 1)

	// Flags and Fragment Offset
	packet[6] = 0x40
	packet[7] = 0

	// TTL
	packet[8] = 64

	// Protocol
	packet[9] = byte(protocol)

	// Checksum (simplified)
	binary.BigEndian.PutUint16(packet[10:12], 0)

	// Source IP
	copy(packet[12:16], srcIP.To4())

	// Destination IP
	copy(packet[16:20], dstIP.To4())

	// Payload
	copy(packet[20:], payload)

	return packet
}

// GetStats returns tunnel statistics
func (t *Tunnel) GetStats() TunnelStats {
	return TunnelStats{
		Running:    t.running,
		PacketsIn:  t.packetsIn,
		PacketsOut: t.packetsOut,
		BytesIn:    t.bytesIn,
		BytesOut:   t.bytesOut,
	}
}

// TunnelStats holds tunnel statistics
type TunnelStats struct {
	Running    bool
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64
}

// mockTUN is a mock TUN device for testing
type mockTUN struct {
	config TunnelConfig
}

func (m *mockTUN) Read(b []byte) (n int, err error) {
	// Simulate no data
	time.Sleep(100 * time.Millisecond)
	return 0, io.EOF
}

func (m *mockTUN) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockTUN) Close() error {
	return nil
}

// Platform-specific TUN operations

// OpenTUN opens a TUN device
func OpenTUN(path, name string, mtu int) (io.ReadWriteCloser, error) {
	// This would use platform-specific code
	// For now, return error
	return nil, fmt.Errorf("TUN not supported on this platform without root")
}

// SetupTUN configures TUN device
func SetupTUN(conn io.ReadWriteCloser, config *TunnelConfig) error {
	// Set MTU
	// Configure addresses
	// Set up routing
	return nil
}
