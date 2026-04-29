package policy

import (
	"context"
	"time"
)

// Policy defines the interface for routing policies
type Policy interface {
	// SelectNode selects a node for the given context
	SelectNode(ctx context.Context) (string, error)

	// SelectNodeForTarget selects a node for a specific target
	SelectNodeForTarget(ctx context.Context, target string) (string, error)

	// RegisterNode registers a node for policy consideration
	RegisterNode(id, name, address string)

	// UnregisterNode removes a node from policy consideration
	UnregisterNode(id string)

	// UpdateMetrics updates metrics for a node
	UpdateMetrics(id string, latency time.Duration, success bool)

	// GetStats returns policy statistics
	GetStats() PolicyStats

	// Close closes the policy
	Close() error
}

// PolicyStats holds policy statistics
type PolicyStats struct {
	Name       string
	Mode       string
	TotalNodes int
	AvgScore   float64
	BestNode   string
}

// PolicyType defines the type of policy
type PolicyType string

const (
	PolicyTypeDirect   PolicyType = "direct"
	PolicyTypeSelector PolicyType = "selector"
	PolicyTypeFallback PolicyType = "fallback"
	PolicyTypeURLTest  PolicyType = "url-test"
	PolicyTypeSmart    PolicyType = "smart"
)

// Config holds policy configuration
type Config struct {
	Type PolicyType `yaml:"type"`

	// Common options
	Disabled bool `yaml:"disabled"`

	// URLTest options
	URL         string        `yaml:"url"`
	Interval    time.Duration `yaml:"interval"`
	Tolerance   time.Duration `yaml:"tolerance"`
	StartProbes int           `yaml:"start-probes"`
	MinProbes   int           `yaml:"min-probes"`

	// Smart options
	LearningEnabled bool          `yaml:"learning-enabled"`
	UpdateInterval  time.Duration `yaml:"update-interval"`
}

// NewPolicy creates a new policy instance
func NewPolicy(cfg Config) (Policy, error) {
	switch cfg.Type {
	case PolicyTypeSmart:
		// This will be set up by the controller
		return nil, nil
	case PolicyTypeURLTest:
		return newURLTestPolicy(cfg), nil
	case PolicyTypeFallback:
		return newFallbackPolicy(cfg), nil
	case PolicyTypeSelector:
		return newSelectorPolicy(cfg), nil
	default:
		return newDirectPolicy(cfg), nil
	}
}

// URLTestPolicy implements URL test policy
type URLTestPolicy struct {
	cfg   Config
	nodes map[string]*NodeInfo
}

// NodeInfo holds node information
type NodeInfo struct {
	ID      string
	Name    string
	Address string
	URL     string
}

// FallbackPolicy implements fallback policy
type FallbackPolicy struct {
	cfg     Config
	nodes   []string
	current int
}

// SelectorPolicy implements selector policy
type SelectorPolicy struct {
	cfg     Config
	nodes   []string
	current string
}

// DirectPolicy implements direct policy
type DirectPolicy struct {
	cfg Config
}

func newDirectPolicy(cfg Config) *DirectPolicy {
	return &DirectPolicy{cfg: cfg}
}

func newURLTestPolicy(cfg Config) *URLTestPolicy {
	return &URLTestPolicy{
		cfg:   cfg,
		nodes: make(map[string]*NodeInfo),
	}
}

func newFallbackPolicy(cfg Config) *FallbackPolicy {
	return &FallbackPolicy{
		cfg:   cfg,
		nodes: make([]string, 0),
	}
}

func newSelectorPolicy(cfg Config) *SelectorPolicy {
	return &SelectorPolicy{
		cfg:     cfg,
		nodes:   make([]string, 0),
		current: "",
	}
}

// Implement Policy interface for DirectPolicy
func (p *DirectPolicy) SelectNode(ctx context.Context) (string, error) {
	return "", nil
}

func (p *DirectPolicy) SelectNodeForTarget(ctx context.Context, target string) (string, error) {
	return "", nil
}

func (p *DirectPolicy) RegisterNode(id, name, address string)                        {}
func (p *DirectPolicy) UnregisterNode(id string)                                     {}
func (p *DirectPolicy) UpdateMetrics(id string, latency time.Duration, success bool) {}

func (p *DirectPolicy) GetStats() PolicyStats {
	return PolicyStats{
		Name:       "direct",
		Mode:       string(PolicyTypeDirect),
		TotalNodes: 0,
	}
}

func (p *DirectPolicy) Close() error { return nil }

// Implement Policy interface for URLTestPolicy
func (p *URLTestPolicy) SelectNode(ctx context.Context) (string, error) {
	// TODO: Implement URL test logic
	return "", nil
}

func (p *URLTestPolicy) SelectNodeForTarget(ctx context.Context, target string) (string, error) {
	return p.SelectNode(ctx)
}

func (p *URLTestPolicy) RegisterNode(id, name, address string) {
	p.nodes[id] = &NodeInfo{ID: id, Name: name, Address: address}
}

func (p *URLTestPolicy) UnregisterNode(id string) {
	delete(p.nodes, id)
}

func (p *URLTestPolicy) UpdateMetrics(id string, latency time.Duration, success bool) {}

func (p *URLTestPolicy) GetStats() PolicyStats {
	return PolicyStats{
		Name:       "url-test",
		Mode:       string(PolicyTypeURLTest),
		TotalNodes: len(p.nodes),
	}
}

func (p *URLTestPolicy) Close() error { return nil }

// Implement Policy interface for FallbackPolicy
func (p *FallbackPolicy) SelectNode(ctx context.Context) (string, error) {
	if len(p.nodes) == 0 {
		return "", nil
	}
	idx := p.current % len(p.nodes)
	return p.nodes[idx], nil
}

func (p *FallbackPolicy) SelectNodeForTarget(ctx context.Context, target string) (string, error) {
	return p.SelectNode(ctx)
}

func (p *FallbackPolicy) RegisterNode(id, name, address string) {
	p.nodes = append(p.nodes, id)
}

func (p *FallbackPolicy) UnregisterNode(id string) {
	for i, n := range p.nodes {
		if n == id {
			p.nodes = append(p.nodes[:i], p.nodes[i+1:]...)
			break
		}
	}
}

func (p *FallbackPolicy) UpdateMetrics(id string, latency time.Duration, success bool) {
	if success {
		// Move to next node if current fails
		for i, n := range p.nodes {
			if n == id {
				p.current = i
				break
			}
		}
	}
}

func (p *FallbackPolicy) GetStats() PolicyStats {
	return PolicyStats{
		Name:       "fallback",
		Mode:       string(PolicyTypeFallback),
		TotalNodes: len(p.nodes),
	}
}

func (p *FallbackPolicy) Close() error { return nil }

// Implement Policy interface for SelectorPolicy
func (p *SelectorPolicy) SelectNode(ctx context.Context) (string, error) {
	if p.current == "" && len(p.nodes) > 0 {
		p.current = p.nodes[0]
	}
	return p.current, nil
}

func (p *SelectorPolicy) SelectNodeForTarget(ctx context.Context, target string) (string, error) {
	return p.SelectNode(ctx)
}

func (p *SelectorPolicy) RegisterNode(id, name, address string) {
	p.nodes = append(p.nodes, id)
}

func (p *SelectorPolicy) UnregisterNode(id string) {
	for i, n := range p.nodes {
		if n == id {
			p.nodes = append(p.nodes[:i], p.nodes[i+1:]...)
			if p.current == id {
				if len(p.nodes) > 0 {
					p.current = p.nodes[0]
				} else {
					p.current = ""
				}
			}
			break
		}
	}
}

func (p *SelectorPolicy) UpdateMetrics(id string, latency time.Duration, success bool) {}

func (p *SelectorPolicy) GetStats() PolicyStats {
	return PolicyStats{
		Name:       "selector",
		Mode:       string(PolicyTypeSelector),
		TotalNodes: len(p.nodes),
		BestNode:   p.current,
	}
}

func (p *SelectorPolicy) Close() error { return nil }
