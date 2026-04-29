package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig holds SSH proxy configuration
type SSHConfig struct {
	Server     string
	Port       int
	User       string
	Password   string
	PrivateKey []byte
	Passphrase string
}

// SSHProxy represents an SSH proxy connection
type SSHProxy struct {
	config     *SSHConfig
	client     *ssh.Client
	clientConn net.Conn
	mu         sync.Mutex
}

// NewSSHProxy creates a new SSH proxy
func NewSSHProxy(config *SSHConfig) (*SSHProxy, error) {
	return &SSHProxy{config: config}, nil
}

// Connect establishes connection to SSH server
func (s *SSHProxy) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil {
		return nil
	}

	serverAddr := fmt.Sprintf("%s:%d", s.config.Server, s.config.Port)

	conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to dial SSH server: %w", err)
	}

	clientConfig, err := s.buildClientConfig()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to build SSH client config: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, serverAddr, clientConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SSH handshake failed: %w", err)
	}

	s.client = ssh.NewClient(sshConn, chans, reqs)
	s.clientConn = conn

	return nil
}

// Dial creates a new SSH channel for proxy forwarding
func (s *SSHProxy) Dial(ctx context.Context, target string) (net.Conn, error) {
	s.mu.Lock()
	if s.client == nil {
		s.mu.Unlock()
		if err := s.Connect(ctx); err != nil {
			return nil, err
		}
		s.mu.Lock()
	}
	s.mu.Unlock()

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	port := parsePort(portStr)

	channel, requests, err := s.client.OpenChannel("forwarded-tcpip", marshalSSHAddr(host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to open SSH channel: %w", err)
	}

	go ssh.DiscardRequests(requests)

	return &sshChannelConn{
		Channel:    channel,
		localAddr:  s.clientConn.LocalAddr(),
		remoteAddr: s.clientConn.RemoteAddr(),
	}, nil
}

// Close closes the SSH connection
func (s *SSHProxy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
	if s.clientConn != nil {
		s.clientConn.Close()
		s.clientConn = nil
	}
	return nil
}

func (s *SSHProxy) buildClientConfig() (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            s.config.User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	var authMethods []ssh.AuthMethod

	if s.config.Password != "" {
		authMethods = append(authMethods, ssh.Password(s.config.Password))
	}

	if len(s.config.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(s.config.PrivateKey, []byte(s.config.Passphrase))
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method available")
	}

	config.Auth = authMethods
	return config, nil
}

// sshChannelConn wraps ssh.Channel as net.Conn
type sshChannelConn struct {
	ssh.Channel
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *sshChannelConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *sshChannelConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *sshChannelConn) SetDeadline(t time.Time) error      { return nil }
func (c *sshChannelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sshChannelConn) SetWriteDeadline(t time.Time) error { return nil }

// DirectTCPIPConfig holds direct TCP/IP channel configuration
type DirectTCPIPConfig struct {
	TargetHost string
	TargetPort uint32
	OriginHost string
	OriginPort uint32
}

// marshalSSHAddr marshals address for SSH channel request
func marshalSSHAddr(host string, port int) []byte {
	var buf bytes.Buffer
	buf.WriteString(host)
	buf.WriteByte(0)
	buf.Write([]byte{byte(port >> 24), byte(port >> 16), byte(port >> 8), byte(port)})
	buf.WriteString("127.0.0.1")
	buf.WriteByte(0)
	buf.Write([]byte{0, 0, 0, 0})
	return buf.Bytes()
}

// parsePort parses port string to int
func parsePort(portStr string) int {
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// Unused imports
var _ = io.Discard
