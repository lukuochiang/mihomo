package smart

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Selector handles node selection based on different modes
type Selector struct {
	mu      sync.RWMutex
	targets map[string]string // target -> preferred region
	regions map[string]string // nodeID -> region mapping
}

// NewSelector creates a new Selector
func NewSelector() *Selector {
	return &Selector{
		targets: make(map[string]string),
		regions: make(map[string]string),
	}
}

// SetTargetRegion sets preferred region for a target
func (s *Selector) SetTargetRegion(target, region string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets[target] = region
}

// SetNodeRegion sets region for a node (e.g., "jp", "us", "hk", "sg")
func (s *Selector) SetNodeRegion(nodeID, region string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.regions[nodeID] = strings.ToLower(region)
}

// Select selects a node based on mode
func (s *Selector) Select(ctx interface{}, nodes []*NodeMetrics, mode SelectionMode) (string, error) {
	if len(nodes) == 0 {
		return "", ErrNoNodesAvailable
	}

	switch mode {
	case ModeFast:
		return s.selectFast(nodes)
	case ModeStable:
		return s.selectStable(nodes)
	case ModeBalanced:
		return s.selectBalanced(nodes)
	case ModeLearning:
		return s.selectLearning(nodes)
	default: // ModeAuto
		return s.selectAuto(nodes)
	}
}

// SelectForTarget selects best node for specific target
func (s *Selector) SelectForTarget(ctx interface{}, nodes []*NodeMetrics, targetRegion string) (string, error) {
	if len(nodes) == 0 {
		return "", ErrNoNodesAvailable
	}

	// Filter nodes by region if possible
	var regionMatch []*NodeMetrics
	var others []*NodeMetrics

	for _, n := range nodes {
		if s.regionMatches(n, targetRegion) {
			regionMatch = append(regionMatch, n)
		} else {
			others = append(others, n)
		}
	}

	// Prefer region match, fallback to others
	pool := regionMatch
	if len(pool) == 0 {
		pool = others
	}

	return s.selectAuto(pool)
}

// selectFast selects node with lowest latency
func (s *Selector) selectFast(nodes []*NodeMetrics) (string, error) {
	sorted := make([]*NodeMetrics, len(nodes))
	copy(sorted, nodes)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].AvgLatency < sorted[j].AvgLatency
	})

	// Return best node with acceptable latency
	for _, n := range sorted {
		if n.AvgLatency < 500*time.Millisecond && n.SuccessRate > 0.9 {
			return n.ID, nil
		}
	}

	// Fallback to best available
	return sorted[0].ID, nil
}

// selectStable selects node with highest stability
func (s *Selector) selectStable(nodes []*NodeMetrics) (string, error) {
	sorted := make([]*NodeMetrics, len(nodes))
	copy(sorted, nodes)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].SuccessRate > sorted[j].SuccessRate
	})

	return sorted[0].ID, nil
}

// selectBalanced selects node with best overall score
func (s *Selector) selectBalanced(nodes []*NodeMetrics) (string, error) {
	sorted := make([]*NodeMetrics, len(nodes))
	copy(sorted, nodes)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score > sorted[j].Score
	})

	return sorted[0].ID, nil
}

// selectLearning selects using ML prediction
// It uses the learner's recommendations combined with current metrics
func (s *Selector) selectLearning(nodes []*NodeMetrics) (string, error) {
	if len(nodes) == 0 {
		return "", ErrNoNodesAvailable
	}

	// Get candidate node IDs
	nodeIDs := make([]string, len(nodes))
	for i, n := range nodes {
		nodeIDs[i] = n.ID
	}

	// Try to get recommendation from learner (if available in smart.go)
	// For now, use predictor-based selection
	return s.selectByPrediction(nodes)
}

// selectByPrediction selects node based on predicted future performance
func (s *Selector) selectByPrediction(nodes []*NodeMetrics) (string, error) {
	if len(nodes) == 0 {
		return "", ErrNoNodesAvailable
	}

	// Simple weighted selection based on score and predicted trend
	// Nodes with improving performance (lower latency trend) get priority
	var bestNode *NodeMetrics
	var bestScore float64

	for _, n := range nodes {
		// Base score from current metrics
		baseScore := n.Score

		// Bonus for good success rate (stability indicator)
		successBonus := n.SuccessRate * 20

		// Slight penalty for high jitter (unstable connection)
		jitterPenalty := float64(n.Jitter.Milliseconds()) * 0.1

		// Calculate combined score
		combinedScore := baseScore + successBonus - jitterPenalty

		if bestNode == nil || combinedScore > bestScore {
			bestScore = combinedScore
			bestNode = n
		}
	}

	if bestNode == nil {
		return s.selectBalanced(nodes)
	}

	return bestNode.ID, nil
}

// selectAuto automatically chooses best strategy
func (s *Selector) selectAuto(nodes []*NodeMetrics) (string, error) {
	// Analyze nodes
	var lowLatencyCount, stableCount, goodScoreCount int

	for _, n := range nodes {
		if n.AvgLatency < 100*time.Millisecond {
			lowLatencyCount++
		}
		if n.SuccessRate > 0.95 {
			stableCount++
		}
		if n.Score > 80 {
			goodScoreCount++
		}
	}

	total := len(nodes)
	lowLatencyRatio := float64(lowLatencyCount) / float64(total)
	stableRatio := float64(stableCount) / float64(total)

	// Decision logic
	if lowLatencyRatio > 0.5 {
		return s.selectFast(nodes)
	}
	if stableRatio < 0.3 {
		// Network seems unstable, prefer stability
		return s.selectStable(nodes)
	}

	return s.selectBalanced(nodes)
}

// regionMatches checks if node region matches target
// It supports:
// - Exact match: "jp" matches node with region "jp"
// - Prefix match: "us" matches "us-west", "us-east"
// - Target domain hint: "netflix" hints to use region from domain
func (s *Selector) regionMatches(node *NodeMetrics, targetRegion string) bool {
	if targetRegion == "" {
		return true
	}

	targetRegion = strings.ToLower(targetRegion)
	nodeRegion := strings.ToLower(s.getNodeRegion(node))

	// Direct match
	if nodeRegion == targetRegion {
		return true
	}

	// Partial match (target is prefix of node region or vice versa)
	if strings.HasPrefix(nodeRegion, targetRegion) || strings.HasPrefix(targetRegion, nodeRegion) {
		return true
	}

	// Check if targetRegion is a domain hint (contains dot or known service names)
	if strings.Contains(targetRegion, ".") || s.isServiceDomain(targetRegion) {
		// For domain hints, prefer region-coded nodes
		return s.regionFromDomain(targetRegion) == nodeRegion
	}

	// Fallback: check name and address
	return strings.Contains(strings.ToLower(node.Name), targetRegion) ||
		strings.Contains(strings.ToLower(node.Address), targetRegion)
}

// getNodeRegion gets region from node's stored region or name
func (s *Selector) getNodeRegion(node *NodeMetrics) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if region, ok := s.regions[node.ID]; ok && region != "" {
		return region
	}

	// Extract region from node name (e.g., "JP-01", "US-West")
	return extractRegion(node.Name)
}

// isServiceDomain checks if target looks like a service domain
func (s *Selector) isServiceDomain(target string) bool {
	services := []string{
		"netflix", "youtube", "google", "twitter", "facebook",
		"github", "openai", "claude", "spotify", "discord",
	}
	target = strings.ToLower(target)
	for _, svc := range services {
		if strings.Contains(target, svc) {
			return true
		}
	}
	return false
}

// regionFromDomain extracts region hint from domain
func (s *Selector) regionFromDomain(domain string) string {
	domain = strings.ToLower(domain)
	regionHints := map[string]string{
		"netflix": "us", "youtube": "us", "google": "us",
		"github": "us", "spotify": "us",
		"baidu": "cn", "aliyun": "cn", "tencent": "hk",
	}
	for svc, region := range regionHints {
		if strings.Contains(domain, svc) {
			return region
		}
	}
	return ""
}

// extractRegion extracts region code from node name
func extractRegion(name string) string {
	name = strings.ToUpper(name)
	regions := []string{"JP", "US", "HK", "SG", "KR", "UK", "DE", "AU", "TW", "CN"}

	for _, region := range regions {
		if strings.Contains(name, region) {
			return strings.ToLower(region)
		}
	}
	return ""
}

// GetTopN returns top N nodes by score
func (s *Selector) GetTopN(nodes []*NodeMetrics, n int) []*NodeMetrics {
	sorted := make([]*NodeMetrics, len(nodes))
	copy(sorted, nodes)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score > sorted[j].Score
	})

	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}

// CalculateVariance calculates score variance
func (s *Selector) CalculateVariance(nodes []*NodeMetrics) float64 {
	if len(nodes) < 2 {
		return 0
	}

	var sum, sumSq float64
	for _, n := range nodes {
		sum += n.Score
		sumSq += n.Score * n.Score
	}

	n := float64(len(nodes))
	mean := sum / n
	return (sumSq / n) - (mean * mean)
}

// CalculateEntropy calculates score entropy
func (s *Selector) CalculateEntropy(nodes []*NodeMetrics) float64 {
	if len(nodes) < 2 {
		return 0
	}

	var sum float64
	for _, n := range nodes {
		sum += n.Score
	}

	if sum == 0 {
		return 0
	}

	var entropy float64
	for _, n := range nodes {
		p := n.Score / sum
		if p > 0 {
			entropy -= p * math.Log(p)
		}
	}

	return entropy
}
