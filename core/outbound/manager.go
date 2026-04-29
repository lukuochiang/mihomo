package outbound

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lukuochiang/mihomo/adapter"
	"github.com/lukuochiang/mihomo/core/metrics"
	"github.com/lukuochiang/mihomo/core/policy/smart"
	"github.com/lukuochiang/mihomo/protocol"
	"github.com/lukuochiang/mihomo/transport"
)

// Manager manages outbound nodes
type Manager struct {
	nodes       map[string]*Node
	groups      map[string]*Group
	policy      *smart.Smart
	healthCheck *HealthCheck
	metrics     *metrics.Collector
	mu          sync.RWMutex
}

// Group represents a node group
type Group struct {
	Name       string
	Type       string // selector, url-test, fallback, load-balance
	Nodes      []string
	PolicyName string
}

// NewManager creates a new outbound manager
func NewManager(policy *smart.Smart, m *metrics.Collector) *Manager {
	cfg := HealthCheckConfig{
		Enabled:  true,
		URL:      "https://www.google.com/generate_204",
		Interval: 5 * time.Minute,
		Timeout:  5 * time.Second,
		Fall:     3,
		Rise:     2,
	}

	return &Manager{
		nodes:       make(map[string]*Node),
		groups:      make(map[string]*Group),
		policy:      policy,
		healthCheck: NewHealthCheck(cfg, nil, m),
		metrics:     m,
	}
}

// AddNode adds a new node
func (m *Manager) AddNode(node *Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.nodes[node.ID]; exists {
		return fmt.Errorf("node %s already exists", node.ID)
	}

	m.nodes[node.ID] = node
	m.healthCheck.RegisterNode(node)
	m.policy.RegisterNode(node.ID, node.Name, node.Address)

	return nil
}

// RemoveNode removes a node
func (m *Manager) RemoveNode(nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.nodes[nodeID]; !exists {
		return fmt.Errorf("node %s not found", nodeID)
	}

	delete(m.nodes, nodeID)
	m.healthCheck.UnregisterNode(nodeID)
	m.policy.UnregisterNode(nodeID)

	return nil
}

// GetNode returns a node by ID
func (m *Manager) GetNode(nodeID string) (*Node, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	node, ok := m.nodes[nodeID]
	return node, ok
}

// GetAllNodes returns all nodes
func (m *Manager) GetAllNodes() []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]*Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// GetLiveNodes returns only live nodes
func (m *Manager) GetLiveNodes() []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var nodes []*Node
	for _, n := range m.nodes {
		status, _ := m.healthCheck.GetNodeStatus(n.ID)
		if status == NodeStatusAlive {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// SelectNode selects best node using policy
func (m *Manager) SelectNode(ctx context.Context) (*Node, error) {
	nodeID, err := m.policy.SelectNode(ctx)
	if err != nil {
		return nil, err
	}

	node, ok := m.GetNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %s not found", nodeID)
	}

	return node, nil
}

// SelectNodeForGroup selects best node for a specific group
func (m *Manager) SelectNodeForGroup(ctx context.Context, groupName string) (*Node, error) {
	group, ok := m.GetGroup(groupName)
	if !ok {
		return nil, fmt.Errorf("group %s not found", groupName)
	}

	// Filter nodes in group
	var groupNodes []*Node
	for _, nodeID := range group.Nodes {
		if node, ok := m.GetNode(nodeID); ok {
			groupNodes = append(groupNodes, node)
		}
	}

	if len(groupNodes) == 0 {
		return nil, fmt.Errorf("no nodes available in group %s", groupName)
	}

	// Use strategy based on group type
	switch group.Type {
	case "url-test":
		return m.selectURLTest(ctx, groupNodes)
	case "fallback":
		return m.selectFallback(ctx, groupNodes)
	case "load-balance":
		return m.selectLoadBalance(ctx, groupNodes)
	default: // selector
		return m.selectByPolicy(ctx, groupNodes)
	}
}

func (m *Manager) selectURLTest(ctx context.Context, nodes []*Node) (*Node, error) {
	// Find node with lowest latency
	var best *Node
	var bestLatency time.Duration

	for _, n := range nodes {
		status, latency := m.healthCheck.GetNodeStatus(n.ID)
		if status == NodeStatusAlive {
			if best == nil || latency < bestLatency {
				best = n
				bestLatency = latency
			}
		}
	}

	return best, nil
}

func (m *Manager) selectFallback(ctx context.Context, nodes []*Node) (*Node, error) {
	// Return first available node
	for _, n := range nodes {
		status, _ := m.healthCheck.GetNodeStatus(n.ID)
		if status == NodeStatusAlive {
			return n, nil
		}
	}
	return nil, fmt.Errorf("no live nodes in fallback group")
}

func (m *Manager) selectLoadBalance(ctx context.Context, nodes []*Node) (*Node, error) {
	// Simple round-robin with health awareness
	// TODO: Implement more sophisticated load balancing
	var liveNodes []*Node
	for _, n := range nodes {
		status, _ := m.healthCheck.GetNodeStatus(n.ID)
		if status == NodeStatusAlive {
			liveNodes = append(liveNodes, n)
		}
	}

	if len(liveNodes) == 0 {
		return nil, fmt.Errorf("no live nodes for load balancing")
	}

	// Pick node with best score (based on latency)
	var best *Node
	var bestLatency time.Duration = -1
	for _, n := range liveNodes {
		n.mu.RLock()
		latency := n.LastLatency
		n.mu.RUnlock()
		if bestLatency < 0 || (latency > 0 && latency < bestLatency) {
			best = n
			bestLatency = latency
		}
	}

	return best, nil
}

func (m *Manager) selectByPolicy(ctx context.Context, nodes []*Node) (*Node, error) {
	// Use Smart policy
	for _, n := range nodes {
		m.policy.RegisterNode(n.ID, n.Name, n.Address)
	}

	nodeID, err := m.policy.SelectNode(ctx)
	if err != nil {
		return nil, err
	}

	node, ok := m.GetNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %s not found after selection", nodeID)
	}
	return node, nil
}

// AddGroup adds a node group
func (m *Manager) AddGroup(group *Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.groups[group.Name]; exists {
		return fmt.Errorf("group %s already exists", group.Name)
	}

	m.groups[group.Name] = group
	return nil
}

// GetGroup returns a group by name
func (m *Manager) GetGroup(name string) (*Group, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	group, ok := m.groups[name]
	return group, ok
}

// UpdateNodeMetrics updates node metrics from actual usage
func (m *Manager) UpdateNodeMetrics(nodeID string, latency time.Duration, success bool) {
	m.policy.UpdateMetrics(nodeID, latency, success)

	// Update health check result
	node, ok := m.GetNode(nodeID)
	if !ok {
		return
	}

	node.mu.Lock()
	node.LastLatency = latency
	node.mu.Unlock()
}

// Start starts the manager
func (m *Manager) Start() {
	m.healthCheck.Start()
}

// Stop stops the manager
func (m *Manager) Stop() {
	m.healthCheck.Stop()
}

// GetStats returns manager statistics
func (m *Manager) GetStats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	totalNodes := len(m.nodes)
	liveNodes := 0

	for _, n := range m.nodes {
		status, _ := m.healthCheck.GetNodeStatus(n.ID)
		if status == NodeStatusAlive {
			liveNodes++
		}
	}

	return ManagerStats{
		TotalNodes: totalNodes,
		LiveNodes:  liveNodes,
		Groups:     len(m.groups),
	}
}

// ManagerStats holds manager statistics
type ManagerStats struct {
	TotalNodes int
	LiveNodes  int
	Groups     int
}

// Dialer creates connections to nodes
type Dialer struct {
	manager *Manager
}

// NewDialer creates a new dialer
func NewDialer(manager *Manager) *Dialer {
	return &Dialer{manager: manager}
}

// Dial connects to a node using the appropriate protocol
func (d *Dialer) Dial(ctx context.Context, nodeID string, target string) (net.Conn, error) {
	node, ok := d.manager.GetNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("node not found: %s", nodeID)
	}

	// If no target specified, use a placeholder
	if target == "" {
		target = "example.com:443"
	}

	switch node.Type {
	case "shadowsocks", "ss":
		return d.dialSS(ctx, node, target)
	case "shadowsocksr", "ssr":
		return d.dialSSR(ctx, node, target)
	case "ssh":
		return d.dialSSH(ctx, node, target)
	case "vmess":
		return d.dialVMess(ctx, node, target)
	case "vless":
		return d.dialVLESS(ctx, node, target)
	case "trojan":
		return d.dialTrojan(ctx, node, target)
	case "snell":
		return d.dialSnell(ctx, node, target)
	case "hysteria", "hysteria2":
		return d.dialHysteria(ctx, node, target)
	case "tuic":
		return d.dialTUIC(ctx, node, target)
	default:
		// Fallback to direct TCP connection
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, "tcp", target)
	}
}

// DialSimple connects to a node without specifying a target
func (d *Dialer) DialSimple(ctx context.Context, nodeID string) (net.Conn, error) {
	return d.Dial(ctx, nodeID, "")
}

// dialSS creates a Shadowsocks connection
func (d *Dialer) dialSS(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &adapter.Config{
		Type:     "shadowsocks",
		Address:  node.Address,
		Port:     node.Port,
		Cipher:   node.Cipher,
		Password: node.Password,
	}

	ssAdapter := adapter.NewShadowsocksAdapter(cfg)
	return ssAdapter.Dial(ctx, "tcp", target)
}

// dialVMess creates a VMess connection
func (d *Dialer) dialVMess(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &adapter.Config{
		Type:    "vmess",
		Address: node.Address,
		Port:    node.Port,
		UUID:    node.UUID,
		TLS: adapter.TLSConfig{
			Enabled:    node.TLS.Enabled,
			ServerName: node.TLS.ServerName,
			Insecure:   node.TLS.Insecure,
		},
	}

	vmessAdapter := adapter.NewVMessAdapter(cfg)
	return vmessAdapter.Dial(ctx, "tcp", target)
}

// dialVLESS creates a VLESS connection
func (d *Dialer) dialVLESS(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &adapter.Config{
		Type:    "vless",
		Address: node.Address,
		Port:    node.Port,
		UUID:    node.UUID,
		TLS: adapter.TLSConfig{
			Enabled:    node.TLS.Enabled,
			ServerName: node.TLS.ServerName,
			Insecure:   node.TLS.Insecure,
		},
	}

	vlessAdapter := adapter.NewVLESSAdapter(cfg)
	return vlessAdapter.Dial(ctx, "tcp", target)
}

// dialTrojan creates a Trojan connection
func (d *Dialer) dialTrojan(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &adapter.Config{
		Type:     "trojan",
		Address:  node.Address,
		Port:     node.Port,
		Password: node.Password,
		TLS: adapter.TLSConfig{
			Enabled:    node.TLS.Enabled,
			ServerName: node.TLS.ServerName,
			Insecure:   node.TLS.Insecure,
		},
	}

	trojanAdapter := adapter.NewTrojanAdapter(cfg)
	return trojanAdapter.Dial(ctx, "tcp", target)
}

// dialSnell creates a Snell connection
func (d *Dialer) dialSnell(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &adapter.Config{
		Type:     "snell",
		Address:  node.Address,
		Port:     node.Port,
		Password: node.Password,
	}

	snellAdapter := adapter.NewSnellAdapter(cfg)
	return snellAdapter.Dial(ctx, "tcp", target)
}

// dialHysteria creates a Hysteria connection
func (d *Dialer) dialHysteria(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &adapter.Config{
		Type:     "hysteria",
		Address:  node.Address,
		Port:     node.Port,
		Password: node.Password,
		TLS: adapter.TLSConfig{
			Enabled:    node.TLS.Enabled,
			ServerName: node.TLS.ServerName,
			Insecure:   node.TLS.Insecure,
		},
	}

	hysteriaAdapter := adapter.NewHysteriaAdapter(cfg)
	return hysteriaAdapter.Dial(ctx, "tcp", target)
}

// dialTUIC creates a TUIC connection
func (d *Dialer) dialTUIC(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &adapter.Config{
		Type:     "tuic",
		Address:  node.Address,
		Port:     node.Port,
		UUID:     node.UUID,
		Password: node.Password,
		TLS: adapter.TLSConfig{
			Enabled:    node.TLS.Enabled,
			ServerName: node.TLS.ServerName,
			Insecure:   node.TLS.Insecure,
		},
	}

	tuicAdapter := adapter.NewTUICAdapter(cfg)
	return tuicAdapter.Dial(ctx, "tcp", target)
}

// dialSSR creates a ShadowsocksR connection
func (d *Dialer) dialSSR(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &protocol.SSRConfig{
		Server:   node.Address,
		Port:     node.Port,
		Password: node.Password,
		Method:   node.Cipher,
	}

	// Parse SSR protocol and obfuscator from node options
	if node.Protocol != "" {
		cfg.Protocol = protocol.SSRProtocol(node.Protocol)
	}
	if node.OBFS != "" {
		cfg.Obfuscator = protocol.SSRObfuscator(node.OBFS)
	}
	if node.OBFSParam != "" {
		cfg.OBFSParam = node.OBFSParam
	}
	if node.ProtocolParam != "" {
		cfg.ProtocolParam = node.ProtocolParam
	}

	ssrAdapter, err := adapter.NewSSRAdapter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSR adapter: %w", err)
	}
	return ssrAdapter.Dial(ctx, "tcp", target)
}

// dialSSH creates an SSH connection
func (d *Dialer) dialSSH(ctx context.Context, node *Node, target string) (net.Conn, error) {
	cfg := &transport.SSHConfig{
		Server:   node.Address,
		Port:     node.Port,
		User:     node.Username,
		Password: node.Password,
	}

	// Parse private key if provided
	if node.PrivateKey != nil {
		cfg.PrivateKey = node.PrivateKey
		cfg.Passphrase = node.PrivateKeyPassphrase
	}

	sshAdapter, err := adapter.NewSSHAdapter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH adapter: %w", err)
	}

	return sshAdapter.Dial(ctx, "tcp", target)
}
