package adapter

import (
	"context"
	"fmt"
	"net"

	"github.com/mihomo/smart/transport"
)

// SSHAdapter implements SSH outbound adapter
type SSHAdapter struct {
	config *transport.SSHConfig
	proxy  *transport.SSHProxy
}

// NewSSHAdapter creates a new SSH adapter
func NewSSHAdapter(cfg *transport.SSHConfig) (*SSHAdapter, error) {
	proxy, err := transport.NewSSHProxy(cfg)
	if err != nil {
		return nil, err
	}

	return &SSHAdapter{
		config: cfg,
		proxy:  proxy,
	}, nil
}

// Name returns the adapter name
func (a *SSHAdapter) Name() string {
	return "ssh"
}

// Type returns the adapter type
func (a *SSHAdapter) Type() string {
	return "ssh"
}

// Dial connects to target through SSH proxy
func (a *SSHAdapter) Dial(ctx context.Context, network, target string) (net.Conn, error) {
	return a.proxy.Dial(ctx, target)
}

// Connect establishes connection to SSH server
func (a *SSHAdapter) Connect(ctx context.Context) error {
	return a.proxy.Connect(ctx)
}

// Close closes the adapter
func (a *SSHAdapter) Close() error {
	return a.proxy.Close()
}

// Config returns the adapter configuration
func (a *SSHAdapter) Config() *transport.SSHConfig {
	return a.config
}

// SupportedAuthMethods returns supported authentication methods
func (a *SSHAdapter) SupportedAuthMethods() []string {
	return []string{"password", "publickey"}
}

// ParseSSHLink parses SSH link (simplified format)
// Format: ssh://user:password@host:port
func ParseSSHLink(link string) (*SSHAdapter, error) {
	cfg, err := parseSSHURL(link)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH link: %w", err)
	}

	return NewSSHAdapter(cfg)
}

// parseSSHURL parses SSH URL
func parseSSHURL(link string) (*transport.SSHConfig, error) {
	// Simple SSH URL parser
	// Format: ssh://[user[:password]@]host[:port]

	cfg := &transport.SSHConfig{
		Port: 22, // Default SSH port
	}

	// Remove ssh:// prefix
	if len(link) > 6 && link[:6] == "ssh://" {
		link = link[6:]
	}

	// Find @ to separate user info
	atIdx := -1
	for i := len(link) - 1; i >= 0; i-- {
		if link[i] == '@' {
			atIdx = i
			break
		}
	}

	if atIdx > 0 {
		// Has user info
		userInfo := link[:atIdx]
		link = link[atIdx+1:]

		// Find : to separate password
		colonIdx := -1
		for i := 0; i < len(userInfo); i++ {
			if userInfo[i] == ':' {
				colonIdx = i
				break
			}
		}

		if colonIdx > 0 {
			cfg.User = userInfo[:colonIdx]
			cfg.Password = userInfo[colonIdx+1:]
		} else {
			cfg.User = userInfo
		}
	}

	// Find : to separate port
	colonIdx := -1
	for i := len(link) - 1; i >= 0; i-- {
		if link[i] == ':' {
			colonIdx = i
			break
		}
	}

	if colonIdx > 0 {
		cfg.Server = link[:colonIdx]
		fmt.Sscanf(link[colonIdx+1:], "%d", &cfg.Port)
	} else {
		cfg.Server = link
	}

	if cfg.Server == "" {
		return nil, fmt.Errorf("invalid SSH URL: missing host")
	}

	if cfg.User == "" {
		cfg.User = "root" // Default user
	}

	return cfg, nil
}

// WithPrivateKey sets private key for authentication
func (a *SSHAdapter) WithPrivateKey(key []byte, passphrase string) *SSHAdapter {
	a.config.PrivateKey = key
	a.config.Passphrase = passphrase
	return a
}
