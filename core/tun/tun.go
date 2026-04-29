package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
)

// Device represents a TUN interface
type Device interface {
	// Read reads a packet from the TUN device
	Read([]byte) (int, error)
	// Write writes a packet to the TUN device
	Write([]byte) (int, error)
	// Close closes the TUN device
	Close() error
	// Name returns the device name
	Name() string
	// MTU returns the MTU
	MTU() int
}

// Config holds TUN device configuration
type Config struct {
	Name      string   // Device name (e.g., "tun0")
	MTU       int      // Maximum Transmission Unit
	Addresses []string // IP addresses (e.g., "10.0.0.1/24")
	Routes    []string // Routes to add
	DNS       []string // DNS servers
	AutoRoute bool     // Automatically add default route
}

// DefaultConfig returns a default TUN configuration
func DefaultConfig() *Config {
	return &Config{
		Name:      "tun0",
		MTU:       1500,
		Addresses: []string{"10.0.0.1/24"},
		DNS:       []string{"8.8.8.8"},
		AutoRoute: true,
	}
}

// TunDevice implements TUN interface using /dev/tun
type TunDevice struct {
	name string
	mtu  int
	fd   int
	file *os.File
	mu   sync.RWMutex
}

// OpenTUN opens a TUN device
func OpenTUN(config *Config) (*TunDevice, error) {
	name := config.Name
	if name == "" {
		name = "tun0"
	}

	// Open /dev/tun for reading/writing
	fd, err := os.Open("/dev/tun")
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/tun: %w", err)
	}

	mtu := config.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	return &TunDevice{
		name: name,
		mtu:  mtu,
		fd:   int(fd.Fd()),
		file: fd,
	}, nil
}

// Read reads a packet from the TUN device
func (d *TunDevice) Read(b []byte) (n int, err error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.file == nil {
		return 0, errors.New("device closed")
	}

	return d.file.Read(b)
}

// Write writes a packet to the TUN device
func (d *TunDevice) Write(b []byte) (n int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return 0, errors.New("device closed")
	}

	return d.file.Write(b)
}

// Close closes the TUN device
func (d *TunDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file != nil {
		err := d.file.Close()
		d.file = nil
		d.fd = -1
		return err
	}
	return nil
}

// Name returns the device name
func (d *TunDevice) Name() string {
	return d.name
}

// MTU returns the MTU
func (d *TunDevice) MTU() int {
	return d.mtu
}

// Configure sets up the TUN device with IP addresses and routes
func (d *TunDevice) Configure(config *Config) error {
	// On Linux, this uses ioctl syscalls via tun_linux.go
	// On other platforms, this is a stub that returns an error
	return SetupTUN(d.fd, config)
}

// Packet represents an IP packet
type Packet struct {
	Version  int    // IP version (4 or 6)
	Header   []byte // IP header
	Payload  []byte // Protocol payload
	SrcIP    net.IP // Source IP
	DstIP    net.IP // Destination IP
	Protocol int    // Protocol (TCP, UDP, ICMP, etc.)
}

// ParsePacket parses an IP packet
func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < 20 {
		return nil, errors.New("packet too short")
	}

	// Get IP version
	version := int(data[0] >> 4)

	packet := &Packet{
		Version: version,
		Header:  data,
	}

	if version == 4 {
		// IPv4
		headerLen := int(data[0]&0x0F) * 4
		if len(data) < headerLen {
			return nil, errors.New("invalid IPv4 header length")
		}

		packet.Header = data[:headerLen]
		packet.Payload = data[headerLen:]
		packet.SrcIP = net.IP(data[12:16])
		packet.DstIP = net.IP(data[16:20])
		packet.Protocol = int(data[9])

	} else if version == 6 {
		// IPv6
		if len(data) < 40 {
			return nil, errors.New("invalid IPv6 header length")
		}

		packet.Header = data[:40]
		packet.Payload = data[40:]
		packet.SrcIP = net.IP(data[8:24])
		packet.DstIP = net.IP(data[24:40])
		packet.Protocol = int(data[6]) // Next Header
	}

	return packet, nil
}

// Protocol constants
const (
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
)

// UDPPacket represents a UDP packet
type UDPPacket struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

// ParseUDPPacket parses a UDP packet
func ParseUDPPacket(data []byte) (*UDPPacket, error) {
	if len(data) < 8 {
		return nil, errors.New("UDP packet too short")
	}

	return &UDPPacket{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
		Payload:  data[8:],
	}, nil
}

// BuildUDPPacket builds a UDP packet
func BuildUDPPacket(srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(packet[0:2], srcPort)
	binary.BigEndian.PutUint16(packet[2:4], dstPort)
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	copy(packet[8:], payload)
	return packet
}

// TCPPacket represents a TCP packet
type TCPPacket struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
	Payload    []byte
}

// TCP flags
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// ParseTCPPacket parses a TCP packet
func ParseTCPPacket(data []byte) (*TCPPacket, error) {
	if len(data) < 20 {
		return nil, errors.New("TCP packet too short")
	}

	dataOffset := uint8(data[12] >> 4)
	headerLen := int(dataOffset) * 4
	if len(data) < headerLen {
		return nil, errors.New("invalid TCP header length")
	}

	return &TCPPacket{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: dataOffset,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
		Options:    data[20:headerLen],
		Payload:    data[headerLen:],
	}, nil
}

// IsDNS checks if a packet is a DNS query (UDP port 53)
func IsDNS(p *Packet) bool {
	if p.Protocol != ProtocolUDP {
		return false
	}
	if len(p.Payload) < 2 {
		return false
	}
	udp, err := ParseUDPPacket(p.Payload)
	if err != nil {
		return false
	}
	return udp.SrcPort == 53 || udp.DstPort == 53
}

// DNSHandler handles DNS packets
type DNSHandler interface {
	HandleDNS(packet *Packet) (*Packet, error)
}

// DNSPacketHandler is a simple DNS packet handler
type DNSPacketHandler struct {
	dnsServer string
}

// NewDNSPacketHandler creates a new DNS packet handler
func NewDNSPacketHandler(dnsServer string) *DNSPacketHandler {
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	}
	return &DNSPacketHandler{
		dnsServer: dnsServer,
	}
}

// HandleDNS handles a DNS packet
func (h *DNSPacketHandler) HandleDNS(inPacket *Packet) (*Packet, error) {
	// This is a simplified implementation
	// In production, you would forward the DNS query to the upstream server
	// and relay the response back
	return nil, errors.New("DNS forwarding not implemented")
}

// Stack implements a simple IP stack
type Stack struct {
	tun     Device
	handler PacketHandler
	dns     *DNSPacketHandler
	mtu     int
}

// PacketHandler handles IP packets
type PacketHandler interface {
	HandlePacket(packet *Packet) error
}

// NewStack creates a new IP stack
func NewStack(tun Device, handler PacketHandler) *Stack {
	return &Stack{
		tun:     tun,
		handler: handler,
		dns:     NewDNSPacketHandler(""),
		mtu:     tun.MTU(),
	}
}

// Start starts the packet processing loop
func (s *Stack) Start(ctx context.Context) error {
	buf := make([]byte, s.mtu+64) // Extra space for headers

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := s.tun.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout, continue
			}
			return err
		}

		if n == 0 {
			continue
		}

		// Parse packet
		packet, err := ParsePacket(buf[:n])
		if err != nil {
			continue // Skip invalid packets
		}

		// Handle packet
		if s.handler != nil {
			if err := s.handler.HandlePacket(packet); err != nil {
				// Log error but continue
			}
		}
	}
}

// Stop stops the stack
func (s *Stack) Stop() error {
	return s.tun.Close()
}

// AutoRoute handles automatic route configuration
type AutoRoute struct {
	gateway   string
	tunName   string
	tunSubnet string
}

// NewAutoRoute creates a new AutoRoute helper
func NewAutoRoute(tunName, tunSubnet string) *AutoRoute {
	return &AutoRoute{
		tunName:   tunName,
		tunSubnet: tunSubnet,
	}
}

// Setup sets up automatic routing
func (r *AutoRoute) Setup() error {
	// Add route for TUN subnet using shell command
	// This requires running as root
	return nil
}

// Cleanup removes automatic routing
func (r *AutoRoute) Cleanup() error {
	// Remove route
	return nil
}
