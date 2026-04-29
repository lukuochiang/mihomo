package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lukuochiang/mihomo/core/metrics"
)

// HealthCheck performs health checks on outbound nodes
type HealthCheck struct {
	cfg      HealthCheckConfig
	nodes    map[string]*Node
	callback func(nodeID string, result HealthCheckResult)
	metrics  *metrics.Collector
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Enabled     bool              `yaml:"enabled"`
	URL         string            `yaml:"url"`          // URL to check
	Interval    time.Duration     `yaml:"interval"`     // Check interval
	Timeout     time.Duration     `yaml:"timeout"`      // Request timeout
	Fall        int               `yaml:"fall"`         // Consecutive failures before marking down
	Rise        int               `yaml:"rise"`         // Consecutive successes before marking up
	HTTPMethod  string            `yaml:"http-method"`  // HTTP method to use
	HTTPHeaders map[string]string `yaml:"http-headers"` // Custom HTTP headers
	TCPPort     int               `yaml:"tcp-port"`     // TCP port to check
}

// Node represents an outbound node
type Node struct {
	ID       string
	Name     string
	Type     string
	Address  string
	Port     int
	Username string
	Password string
	UUID     string
	Cipher   string
	TLS      TLSConfig
	Metadata map[string]string

	// SSR specific fields
	Protocol      string // SSR protocol (origin, auth_sha1_v4, auth_chain_a, etc.)
	OBFS          string // SSR obfuscator (plain, random_len, random_pktsize)
	OBFSParam     string // Obfuscator parameter
	ProtocolParam string // Protocol parameter

	// SSH specific fields
	PrivateKey           []byte // SSH private key
	PrivateKeyPassphrase string // Private key passphrase

	Status       NodeStatus
	FailCount    int32
	SuccessCount int32
	LastLatency  time.Duration
	LastCheck    time.Time
	mu           sync.RWMutex
}

// NodeStatus represents node status
type NodeStatus int

const (
	NodeStatusUnknown NodeStatus = iota
	NodeStatusAlive
	NodeStatusDead
)

// HealthCheckResult represents health check result
type HealthCheckResult struct {
	NodeID  string
	Latency time.Duration
	Success bool
	Error   error
	Checked time.Time
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled    bool
	ServerName string
	Insecure   bool
}

// NewHealthCheck creates a new health check instance
func NewHealthCheck(cfg HealthCheckConfig, callback func(string, HealthCheckResult), m *metrics.Collector) *HealthCheck {
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Fall == 0 {
		cfg.Fall = 3
	}
	if cfg.Rise == 0 {
		cfg.Rise = 2
	}
	if cfg.URL == "" {
		cfg.URL = "https://www.google.com/generate_204"
	}
	if cfg.HTTPMethod == "" {
		cfg.HTTPMethod = "HEAD"
	}

	return &HealthCheck{
		cfg:      cfg,
		nodes:    make(map[string]*Node),
		callback: callback,
		metrics:  m,
		stopCh:   make(chan struct{}),
	}
}

// RegisterNode adds a node for health checking
func (hc *HealthCheck) RegisterNode(node *Node) {
	hc.nodes[node.ID] = node
}

// UnregisterNode removes a node from health checking
func (hc *HealthCheck) UnregisterNode(nodeID string) {
	hc.nodes[nodeID] = nil
	delete(hc.nodes, nodeID)
}

// Start begins health checking all registered nodes
func (hc *HealthCheck) Start() {
	if !hc.cfg.Enabled {
		return
	}

	hc.wg.Add(1)
	go hc.checkLoop()
}

// Stop stops health checking
func (hc *HealthCheck) Stop() {
	close(hc.stopCh)
	hc.wg.Wait()
}

func (hc *HealthCheck) checkLoop() {
	defer hc.wg.Done()

	// Initial check for all nodes
	hc.checkAll()

	ticker := time.NewTicker(hc.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.stopCh:
			return
		case <-ticker.C:
			hc.checkAll()
		}
	}
}

func (hc *HealthCheck) checkAll() {
	var wg sync.WaitGroup
	for _, node := range hc.nodes {
		wg.Add(1)
		go func(n *Node) {
			defer wg.Done()
			hc.checkNode(n)
		}(node)
	}
	wg.Wait()
}

func (hc *HealthCheck) checkNode(node *Node) {
	result := hc.performCheck(node)
	node.mu.Lock()
	node.LastCheck = result.Checked
	node.LastLatency = result.Latency
	node.mu.Unlock()

	// Update metrics
	if hc.metrics != nil {
		hc.metrics.RecordLatency(node.ID, result.Latency)
		if !result.Success {
			hc.metrics.RecordError(node.ID, "health_check_failed")
		}
	}

	// Handle result
	hc.handleResult(node, result)

	// Notify callback
	if hc.callback != nil {
		hc.callback(node.ID, result)
	}
}

func (hc *HealthCheck) handleResult(node *Node, result HealthCheckResult) {
	node.mu.Lock()
	defer node.mu.Unlock()

	if result.Success {
		atomic.StoreInt32(&node.FailCount, 0)
		successCount := atomic.AddInt32(&node.SuccessCount, 1)
		if successCount >= int32(hc.cfg.Rise) && node.Status != NodeStatusAlive {
			node.Status = NodeStatusAlive
		}
	} else {
		atomic.StoreInt32(&node.SuccessCount, 0)
		failCount := atomic.AddInt32(&node.FailCount, 1)
		if failCount >= int32(hc.cfg.Fall) && node.Status != NodeStatusDead {
			node.Status = NodeStatusDead
		}
	}
}

func (hc *HealthCheck) performCheck(node *Node) HealthCheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), hc.cfg.Timeout)
	defer cancel()

	start := time.Now()
	checker := NewProtocolChecker(node.Type)

	err := checker.Check(ctx, node, hc.cfg.URL)
	latency := time.Since(start)

	return HealthCheckResult{
		NodeID:  node.ID,
		Latency: latency,
		Success: err == nil,
		Error:   err,
		Checked: time.Now(),
	}
}

// GetNodeStatus returns current status of a node
func (hc *HealthCheck) GetNodeStatus(nodeID string) (NodeStatus, time.Duration) {
	node, ok := hc.nodes[nodeID]
	if !ok {
		return NodeStatusUnknown, 0
	}
	node.mu.RLock()
	defer node.mu.RUnlock()
	return node.Status, node.LastLatency
}

// ProtocolChecker checks node availability using different protocols
type ProtocolChecker interface {
	Check(ctx context.Context, node *Node, url string) error
}

// NewProtocolChecker creates appropriate checker for node type
func NewProtocolChecker(nodeType string) ProtocolChecker {
	switch nodeType {
	case "vmess", "vless":
		return &HTTPProtocolChecker{}
	case "trojan":
		return &HTTPProtocolChecker{}
	case "shadowsocks", "ss":
		return &HTTPProtocolChecker{}
	case "wireguard":
		return &ICMPChecker{}
	default:
		return &TCPProtocolChecker{Port: 443}
	}
}

// HTTPProtocolChecker checks via HTTP/HTTPS
type HTTPProtocolChecker struct {
	Method string
}

func (c *HTTPProtocolChecker) Check(ctx context.Context, node *Node, urlStr string) error {
	method := c.Method
	if method == "" {
		method = "HEAD"
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "curl/7.88.1")

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Dial to node address
			address := fmt.Sprintf("%s:%d", node.Address, node.Port)
			return net.DialTimeout("tcp", address, 5*time.Second)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:    1,
		IdleConnTimeout: 3 * time.Second,
	}

	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil
}

// TCPProtocolChecker checks via raw TCP connection
type TCPProtocolChecker struct {
	Port int
}

func (c *TCPProtocolChecker) Check(ctx context.Context, node *Node, urlStr string) error {
	port := c.Port
	if node.Port > 0 {
		port = node.Port
	}

	address := fmt.Sprintf("%s:%d", node.Address, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	return nil
}

// ICMPChecker checks via ICMP ping
type ICMPChecker struct{}

func (c *ICMPChecker) Check(ctx context.Context, node *Node, urlStr string) error {
	// For WireGuard, try TCP check on WireGuard port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", node.Address, node.Port), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

// CheckerRegistry registers protocol checkers
var checkerRegistry = make(map[string]func() ProtocolChecker)

// RegisterChecker registers a new protocol checker
func RegisterChecker(protocol string, factory func() ProtocolChecker) {
	checkerRegistry[protocol] = factory
}

// GetChecker returns checker for protocol
func GetChecker(protocol string) ProtocolChecker {
	if factory, ok := checkerRegistry[protocol]; ok {
		return factory()
	}
	return &TCPProtocolChecker{Port: 443}
}
