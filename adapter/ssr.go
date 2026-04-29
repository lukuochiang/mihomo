package adapter

import (
	"context"
	"fmt"
	"net"

	"github.com/lukuochiang/mihomo/protocol"
)

// SSRAdapter implements ShadowsocksR outbound adapter
type SSRAdapter struct {
	config *protocol.SSRConfig
	proxy  *protocol.SSRProxy
}

// NewSSRAdapter creates a new ShadowsocksR adapter
func NewSSRAdapter(cfg *protocol.SSRConfig) (*SSRAdapter, error) {
	return &SSRAdapter{
		config: cfg,
		proxy:  protocol.NewSSRProxy(cfg),
	}, nil
}

// Name returns the adapter name
func (a *SSRAdapter) Name() string {
	return "shadowsocksr"
}

// Type returns the adapter type
func (a *SSRAdapter) Type() string {
	return "shadowsocksr"
}

// Dial connects to target through SSR proxy
func (a *SSRAdapter) Dial(ctx context.Context, network, target string) (net.Conn, error) {
	return a.proxy.Connect(target)
}

// Close closes the adapter
func (a *SSRAdapter) Close() error {
	return nil
}

// Config returns the adapter configuration
func (a *SSRAdapter) Config() *protocol.SSRConfig {
	return a.config
}

// SupportedProtocols returns supported protocols
func (a *SSRAdapter) SupportedProtocols() []string {
	return []string{
		"origin",
		"auth_sha1_v4",
		"auth_sha256_v4",
		"auth_chain_a",
		"auth_chain_b",
		"auth_chain_c",
		"auth_chain_d",
		"auth_chain_e",
	}
}

// SupportedObfuscators returns supported obfuscators
func (a *SSRAdapter) SupportedObfuscators() []string {
	return []string{
		"plain",
		"random_len",
		"random_pktsize",
	}
}

// ParseSSRLink parses ssr:// link and creates adapter
func ParseSSRLink(link string) (*SSRAdapter, error) {
	cfg, err := protocol.ParseSSRLink(link)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSR link: %w", err)
	}

	return NewSSRAdapter(cfg)
}

// BuildSSRLink builds ssr:// link from adapter config
func (a *SSRAdapter) BuildSSRLink() string {
	return protocol.BuildSSRLink(a.config)
}
