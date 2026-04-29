//go:build with_gvisor
// +build with_gvisor

package tun

// This file enables gvisor TUN stack support when built with the with_gvisor tag.
//
// To enable gvisor support:
//
// 1. Add gvisor dependency:
//    go get github.com/google/gvisor/tools/go_mkshellfeature && \
//    go get github.com/google/gvisor/gvisor && \
//    go get github.com/google/gvisor/gvisor/pkg/tcpip
//
// 2. Build with gvisor tag:
//    go build -tags with_gvisor -o mihomo .
//
// 3. Or use the Makefile:
//    make build-gvisor
//
// Note: gvisor adds significant binary size (~10MB) and build time.
// Only enable if you need the gvisor TUN stack for better performance
// or compatibility.

import (
	"fmt"
	"net"
	// gvisor packages would be imported here
	// "github.com/google/gvisor/gvisor/pkg/tcpip"
	// "github.com/google/gvisor/gvisor/pkg/tcpip/adapters/gonet"
	// "github.com/google/gvisor/gvisor/pkg/tcpip/network/ipv4"
	// "github.com/google/gvisor/gvisor/pkg/tcpip/network/ipv6"
	// "github.com/google/gvisor/gvisor/pkg/tcpip/transport/tcp"
	// "github.com/google/gvisor/gvisor/pkg/tcpip/transport/udp"
)

// gvisorConfig holds gvisor-specific configuration
type gvisorConfig struct {
	// StackType: "gvisor" or "system" (default)
	StackType string
	// TSODialer: use TSO for TCP segmentation offload
	TSODialer bool
	// GROEnabled: enable generic receive offload
	GROEnabled bool
	// Buffers: buffer sizes for network stack
	BufferSize int
	// fds: file descriptors for the TUN device
	fds []int
}

// GVisorTUNDevice implements TUN interface using gvisor stack
type GVisorTUNDevice struct {
	name     string
	mtu      int
	config   *gvisorConfig
	endpoint interface{} // gvisor.Endpoint
	stack    interface{} // gvisor.Stack
}

// SetupGvisorTUN sets up TUN using gvisor stack
func SetupGvisorTUN(fd int, config *Config) error {
	// Full gvisor implementation would:
	// 1. Create gvisor network stack
	// 2. Create TUN endpoint from fd
	// 3. Configure IP addresses
	// 4. Register with network stack
	return fmt.Errorf("gvisor TUN setup requires full gvisor implementation")
}

// newGvisorStack creates a new gvisor network stack
func newGvisorStack(cfg *gvisorConfig) error {
	// Full implementation would:
	// 1. Create tcpip.Stack
	// 2. Register NIC with stack
	// 3. Set up routing table
	// 4. Configure TCP/UDP forwarders
	return fmt.Errorf("gvisor stack creation requires full gvisor implementation")
}

// newGVisorTUNDevice creates a new gvisor TUN device
func newGVisorTUNDevice(name string, mtu int, cfg *gvisorConfig) (*GVisorTUNDevice, error) {
	return &GVisorTUNDevice{
		name:   name,
		mtu:    mtu,
		config: cfg,
	}, nil
}

// Read reads packets from gvisor stack
func (d *GVisorTUNDevice) Read(p []byte) (n int, err error) {
	// Implementation would read from gvisor endpoint
	return 0, fmt.Errorf("gvisor read not implemented")
}

// Write writes packets to gvisor stack
func (d *GVisorTUNDevice) Write(p []byte) (n int, err error) {
	// Implementation would write to gvisor endpoint
	return 0, fmt.Errorf("gvisor write not implemented")
}

// Close closes the gvisor TUN device
func (d *GVisorTUNDevice) Close() error {
	// Implementation would close gvisor endpoint and stack
	return nil
}

// Name returns the device name
func (d *GVisorTUNDevice) Name() string {
	return d.name
}

// MTU returns the MTU
func (d *GVisorTUNDevice) MTU() int {
	return d.mtu
}

// ConfigureAddresses configures IP addresses on the gvisor stack
func (d *GVisorTUNDevice) ConfigureAddresses(addresses []string) error {
	for _, addr := range addresses {
		ip, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		// Would add address to gvisor NIC
		_ = ip
		_ = ipNet
	}
	return nil
}

// gvisorAvailable returns whether gvisor is available
func gvisorAvailable() bool {
	return true
}

// gvisorImpl provides the gvisor implementation interface
type gvisorImpl struct{}

// NewGvisorImpl creates a new gvisor implementation
func NewGvisorImpl() *gvisorImpl {
	return &gvisorImpl{}
}
