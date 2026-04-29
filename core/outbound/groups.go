package outbound

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/lukuochiang/mihomo/config"
	"github.com/lukuochiang/mihomo/core/policy/smart"
)

// GroupType defines the type of a group
type GroupType string

const (
	GroupTypeSelector    GroupType = "selector"     // Manual selection
	GroupTypeURLTest     GroupType = "url-test"     // Test URL and use fastest
	GroupTypeFallback    GroupType = "fallback"     // Use first available, fallback
	GroupTypeLoadBalance GroupType = "load-balance" // Distribute traffic
	GroupTypeSmart       GroupType = "smart"        // Smart selection
)

// GroupHealthCheck holds health check configuration for a group
type GroupHealthCheck struct {
	Enable   bool
	URL      string
	Interval time.Duration
	Timeout  time.Duration
	Lazy     bool
	Fall     int
	Rise     int
}

// SelectorGroup is a group that requires manual node selection
type SelectorGroup struct {
	Name        string
	Type        GroupType
	Nodes       []string // Node IDs
	Selected    string   // Currently selected node ID
	HealthCheck *GroupHealthCheck
	mu          sync.RWMutex
	selectorIdx int
}

// NewSelectorGroup creates a new selector group
func NewSelectorGroup(name string, nodes []string) *SelectorGroup {
	selected := ""
	if len(nodes) > 0 {
		selected = nodes[0]
	}
	return &SelectorGroup{
		Name:        name,
		Type:        GroupTypeSelector,
		Nodes:       nodes,
		Selected:    selected,
		selectorIdx: 0,
	}
}

// Select selects a node by ID
func (g *SelectorGroup) Select(nodeID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Verify node exists
	for _, id := range g.Nodes {
		if id == nodeID {
			g.Selected = nodeID
			return nil
		}
	}
	return fmt.Errorf("node %s not found in group", nodeID)
}

// SelectByIndex selects a node by index
func (g *SelectorGroup) SelectByIndex(idx int) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if idx < 0 || idx >= len(g.Nodes) {
		return fmt.Errorf("index out of range")
	}
	g.Selected = g.Nodes[idx]
	return nil
}

// GetSelected returns the currently selected node
func (g *SelectorGroup) GetSelected() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Selected
}

// URLTestGroup tests URLs and selects the fastest node
type URLTestGroup struct {
	Name        string
	Nodes       []string
	NodesMap    map[string]*Node // Reference to actual nodes
	TestURL     string
	TestTimeout time.Duration
	lastTest    time.Time
	HealthCheck *GroupHealthCheck
	mu          sync.RWMutex
}

// NewURLTestGroup creates a new URL test group
func NewURLTestGroup(name string, nodes []string, testURL string) *URLTestGroup {
	return &URLTestGroup{
		Name:        name,
		Nodes:       nodes,
		NodesMap:    make(map[string]*Node),
		TestURL:     testURL,
		TestTimeout: 5 * time.Second,
	}
}

// ShouldTest returns true if a new test should be performed
func (g *URLTestGroup) ShouldTest() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.HealthCheck == nil || !g.HealthCheck.Enable {
		return false
	}

	interval := 5 * time.Minute
	if g.HealthCheck.Interval > 0 {
		interval = g.HealthCheck.Interval
	}

	return time.Since(g.lastTest) >= interval
}

// UpdateTestTime updates the last test time
func (g *URLTestGroup) UpdateTestTime() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastTest = time.Now()
}

// SelectBest selects the node with lowest latency
func (g *URLTestGroup) SelectBest() (string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Nodes) == 0 {
		return "", fmt.Errorf("no nodes in group")
	}

	var bestID string
	var bestLatency time.Duration = -1

	for _, id := range g.Nodes {
		node, ok := g.NodesMap[id]
		if !ok {
			continue
		}
		node.mu.RLock()
		latency := node.LastLatency
		node.mu.RUnlock()

		if bestLatency < 0 || (latency > 0 && latency < bestLatency) {
			bestID = id
			bestLatency = latency
		}
	}

	if bestID == "" && len(g.Nodes) > 0 {
		bestID = g.Nodes[0]
	}

	return bestID, nil
}

// FallbackGroup uses the first available node
type FallbackGroup struct {
	Name         string
	Nodes        []string
	NodesMap     map[string]*Node
	CurrentIndex int
	HealthCheck  *GroupHealthCheck
	mu           sync.RWMutex
}

// NewFallbackGroup creates a new fallback group
func NewFallbackGroup(name string, nodes []string) *FallbackGroup {
	return &FallbackGroup{
		Name:         name,
		Nodes:        nodes,
		NodesMap:     make(map[string]*Node),
		CurrentIndex: 0,
	}
}

// GetCurrent returns the current active node
func (g *FallbackGroup) GetCurrent() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Nodes) == 0 {
		return ""
	}
	return g.Nodes[g.CurrentIndex]
}

// SetCurrent sets the current active node
func (g *FallbackGroup) SetCurrent(nodeID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for i, id := range g.Nodes {
		if id == nodeID {
			g.CurrentIndex = i
			return
		}
	}
}

// LoadBalanceGroup distributes traffic across nodes
type LoadBalanceGroup struct {
	Name     string
	Nodes    []string
	Strategy LoadBalanceStrategy
	mu       sync.RWMutex
	idx      int
}

// LoadBalanceStrategy defines how to distribute traffic
type LoadBalanceStrategy string

const (
	LBLRoundRobin   LoadBalanceStrategy = "round-robin"
	LBLLeastConn    LoadBalanceStrategy = "least-connections"
	LBLLeastLatency LoadBalanceStrategy = "least-latency"
	LBLWeighted     LoadBalanceStrategy = "weighted"
	LBLConsistent   LoadBalanceStrategy = "consistent-hash"
)

// NewLoadBalanceGroup creates a new load balance group
func NewLoadBalanceGroup(name string, nodes []string, strategy LoadBalanceStrategy) *LoadBalanceGroup {
	return &LoadBalanceGroup{
		Name:     name,
		Nodes:    nodes,
		Strategy: strategy,
		idx:      0,
	}
}

// Next returns the next node based on strategy
func (g *LoadBalanceGroup) Next() string {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.Nodes) == 0 {
		return ""
	}

	var selected string
	switch g.Strategy {
	case LBLRoundRobin:
		selected = g.Nodes[g.idx]
		g.idx = (g.idx + 1) % len(g.Nodes)
	default:
		selected = g.Nodes[rand.Intn(len(g.Nodes))]
	}

	return selected
}

// SelectByHash selects a node based on a hash value (for consistent hashing)
func (g *LoadBalanceGroup) SelectByHash(hash uint64) string {
	if len(g.Nodes) == 0 {
		return ""
	}
	idx := int(hash % uint64(len(g.Nodes)))
	return g.Nodes[idx]
}

// SelectLeastLatency selects the node with the lowest latency
func (g *LoadBalanceGroup) SelectLeastLatency() string {
	if len(g.Nodes) == 0 {
		return ""
	}

	var bestID string
	var bestLatency int64 = -1

	for _, id := range g.Nodes {
		// In a real implementation, we would get latency from node stats
		// For now, we use a simple hash-based selection as fallback
		latency := int64(hashString(id) % 1000) // Simulated latency
		if bestLatency < 0 || latency < bestLatency {
			bestID = id
			bestLatency = latency
		}
	}

	return bestID
}

// SelectLeastConnections selects the node with fewest active connections
func (g *LoadBalanceGroup) SelectLeastConnections() string {
	if len(g.Nodes) == 0 {
		return ""
	}

	var bestID string
	var minConns int64 = -1

	for _, id := range g.Nodes {
		// In a real implementation, we would get connection count from node stats
		conns := int64(hashString(id) % 100) // Simulated connection count
		if minConns < 0 || conns < minConns {
			bestID = id
			minConns = conns
		}
	}

	return bestID
}

// hashString computes a simple hash of a string
func hashString(s string) int64 {
	var h int64
	for _, c := range s {
		h = h*31 + int64(c)
	}
	return h
}

// ============ Relay Group ============

// RelayGroup chains multiple proxies together
type RelayGroup struct {
	Name     string
	Type     GroupType
	Nodes    []string // Chain: [node1, node2, node3] = node1 -> node2 -> node3
	Selected string   // Currently selected final target
	mu       sync.RWMutex
}

// NewRelayGroup creates a new relay group
func NewRelayGroup(name string, nodes []string) *RelayGroup {
	selected := ""
	if len(nodes) > 0 {
		selected = nodes[len(nodes)-1]
	}
	return &RelayGroup{
		Name:     name,
		Type:     GroupType("relay"),
		Nodes:    nodes,
		Selected: selected,
	}
}

// GetChain returns the proxy chain
func (g *RelayGroup) GetChain() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Nodes
}

// SetChain sets a new proxy chain
func (g *RelayGroup) SetChain(nodes []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Nodes = nodes
	if len(nodes) > 0 {
		g.Selected = nodes[len(nodes)-1]
	}
}

// GetSelected returns the final target in the chain
func (g *RelayGroup) GetSelected() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Selected
}

// DialChain establishes connections through the entire chain
func (g *RelayGroup) DialChain(ctx interface{}) ([]interface{}, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.Nodes) == 0 {
		return nil, fmt.Errorf("no nodes in relay chain")
	}

	// In a real implementation, this would create connections through each node
	// The connection chain would be: conn1 -> conn2 -> ... -> connN
	var chain []interface{}
	for _, nodeID := range g.Nodes {
		// In practice, this would dial through the previous connection
		chain = append(chain, nodeID)
	}

	return chain, nil
}

// ============ Interface Group ============

// InterfaceGroup selects outbound based on network interface
type InterfaceGroup struct {
	Name        string
	Type        GroupType
	Interfaces  []string            // Available interface names
	Selected    string              // Currently selected interface
	Nodes       map[string][]string // interface -> nodes mapping
	HealthCheck *GroupHealthCheck
	mu          sync.RWMutex
}

// NewInterfaceGroup creates a new interface group
func NewInterfaceGroup(name string, interfaces []string) *InterfaceGroup {
	selected := ""
	if len(interfaces) > 0 {
		selected = interfaces[0]
	}
	return &InterfaceGroup{
		Name:       name,
		Type:       GroupType("interface"),
		Interfaces: interfaces,
		Selected:   selected,
		Nodes:      make(map[string][]string),
	}
}

// AddInterface adds a network interface with associated nodes
func (g *InterfaceGroup) AddInterface(iface string, nodes []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Interfaces = append(g.Interfaces, iface)
	g.Nodes[iface] = nodes
}

// SelectInterface selects an interface by name
func (g *InterfaceGroup) SelectInterface(iface string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, i := range g.Interfaces {
		if i == iface {
			g.Selected = iface
			return nil
		}
	}
	return fmt.Errorf("interface %s not found", iface)
}

// GetSelected returns the currently selected interface
func (g *InterfaceGroup) GetSelected() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Selected
}

// GetNodesForInterface returns nodes associated with an interface
func (g *InterfaceGroup) GetNodesForInterface(iface string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Nodes[iface]
}

// GetCurrentNodes returns nodes for the selected interface
func (g *InterfaceGroup) GetCurrentNodes() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Nodes[g.Selected]
}

// ============ NTP Group ============

// NTPGroup syncs time with specified servers
type NTPGroup struct {
	Name     string
	Type     GroupType
	Servers  []string
	Selected string
	mu       sync.RWMutex
}

// NewNTPGroup creates a new NTP group
func NewNTPGroup(name string, servers []string) *NTPGroup {
	selected := ""
	if len(servers) > 0 {
		selected = servers[0]
	}
	return &NTPGroup{
		Name:     name,
		Type:     GroupType("ntp"),
		Servers:  servers,
		Selected: selected,
	}
}

// GetCurrentServer returns the current NTP server
func (g *NTPGroup) GetCurrentServer() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Selected
}

// SyncTime synchronizes time with NTP server
func (g *NTPGroup) SyncTime() (time.Time, error) {
	g.mu.RLock()
	_ = g.Selected // Currently selected server
	g.mu.RUnlock()

	// In a real implementation, this would sync with NTP server
	// For now, return current time
	return time.Now(), nil
}

// ============ Smart Group ============

// SmartGroup uses Smart policy engine for intelligent node selection
type SmartGroup struct {
	Name         string
	Type         GroupType
	Nodes        []string
	NodesMap     map[string]*Node
	SmartEngine  *smart.Smart
	Selector     *smart.Selector
	SmartMode    smart.SelectionMode
	TargetRegion string
	mu           sync.RWMutex
}

// NewSmartGroup creates a new Smart group
// If globalCfg is provided, it inherits global Smart settings
func NewSmartGroup(name string, nodes []string, mode smart.SelectionMode, globalCfg ...smart.Config) *SmartGroup {
	var cfg smart.Config

	if len(globalCfg) > 0 {
		cfg = globalCfg[0]
	} else {
		cfg = smart.Config{
			SelectionMode:   mode,
			LearningEnabled: false,
			UpdateInterval:  5 * time.Second,
		}
	}

	// Override mode if specified in group config
	if mode != "" {
		cfg.SelectionMode = mode
	}

	return &SmartGroup{
		Name:        name,
		Type:        GroupTypeSmart,
		Nodes:       nodes,
		NodesMap:    make(map[string]*Node),
		SmartEngine: smart.NewSmart(cfg),
		Selector:    smart.NewSelector(),
		SmartMode:   cfg.SelectionMode,
	}
}

// RegisterNode registers a node with the Smart engine
func (g *SmartGroup) RegisterNode(nodeID, nodeName, address string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.SmartEngine.RegisterNode(nodeID, nodeName, address)

	// Also set region from node name if available
	if region := extractRegionFromName(nodeName); region != "" {
		g.Selector.SetNodeRegion(nodeID, region)
	}
}

// UpdateMetrics updates node metrics for Smart selection
func (g *SmartGroup) UpdateMetrics(nodeID string, latency time.Duration, success bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.SmartEngine.UpdateMetrics(nodeID, latency, success)
}

// Select selects the best node using Smart policy
func (g *SmartGroup) Select(ctx context.Context) (string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// If target region is set, use SelectNodeForTarget
	if g.TargetRegion != "" {
		return g.SmartEngine.SelectNodeForTarget(ctx, g.TargetRegion)
	}

	return g.SmartEngine.SelectNode(ctx)
}

// GetStats returns Smart engine statistics
func (g *SmartGroup) GetStats() smart.Stats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.SmartEngine.GetStats()
}

// SetMode changes the Smart selection mode
func (g *SmartGroup) SetMode(mode smart.SelectionMode) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.SmartMode = mode
}

// SetTargetRegion sets the preferred region for this group
func (g *SmartGroup) SetTargetRegion(region string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.TargetRegion = region
}

// GetTopN returns the top N nodes by score
func (g *SmartGroup) GetTopN(n int) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Get all node metrics
	var nodeMetrics []*smart.NodeMetrics
	for _, id := range g.Nodes {
		if node, ok := g.NodesMap[id]; ok {
			node.mu.RLock()
			metrics := &smart.NodeMetrics{
				ID:          node.ID,
				Name:        node.Name,
				Address:     node.Address,
				LastLatency: node.LastLatency,
				SuccessRate: float64(node.SuccessCount) / float64(node.SuccessCount+node.FailCount+1),
			}
			node.mu.RUnlock()
			nodeMetrics = append(nodeMetrics, metrics)
		}
	}

	topNodes := g.Selector.GetTopN(nodeMetrics, n)
	result := make([]string, len(topNodes))
	for i, n := range topNodes {
		result[i] = n.ID
	}
	return result
}

// extractRegionFromName extracts region code from node name
func extractRegionFromName(name string) string {
	regions := []string{"JP", "US", "HK", "SG", "KR", "UK", "DE", "AU", "TW", "CN"}
	nameUpper := strings.ToUpper(name)

	for _, region := range regions {
		if strings.Contains(nameUpper, region) {
			return strings.ToLower(region)
		}
	}
	return ""
}

// GroupFactory creates groups from configuration
// Smart is built-in - no global config needed
type GroupFactory struct{}

// NewGroupFactory creates a new GroupFactory
func NewGroupFactory() *GroupFactory {
	return &GroupFactory{}
}

// CreateGroup creates a group from configuration
func (f *GroupFactory) CreateGroup(cfg *config.GroupConfig) *Group {
	g := &Group{
		Name:  cfg.Name,
		Type:  cfg.Type,
		Nodes: cfg.Proxies,
	}

	// For Smart groups, set the policy mode
	if cfg.Type == "smart" {
		mode := smart.SelectionMode(cfg.SmartMode)
		if mode == "" {
			mode = smart.ModeAuto // Default to auto
		}
		g.PolicyName = string(mode)
	}

	return g
}
