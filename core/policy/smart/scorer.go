package smart

import (
	"math"
	"sync"
	"time"
)

// Scorer calculates scores for nodes
type Scorer struct {
	weights Weights
	mu      sync.RWMutex
}

// Weights defines scoring weights
type Weights struct {
	Latency   float64 // Weight for latency (lower is better)
	Jitter    float64 // Weight for jitter (lower is better)
	Stability float64 // Weight for stability (higher is better)
	Bandwidth float64 // Weight for bandwidth (higher is better)
	Region    float64 // Weight for region match (higher is better)
}

// DefaultWeights returns default scoring weights
func DefaultWeights() Weights {
	return Weights{
		Latency:   0.35,
		Jitter:    0.20,
		Stability: 0.25,
		Bandwidth: 0.10,
		Region:    0.10,
	}
}

// NewScorer creates a new Scorer
func NewScorer() *Scorer {
	return &Scorer{
		weights: DefaultWeights(),
	}
}

// SetWeights updates scoring weights
func (s *Scorer) SetWeights(w Weights) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.weights = w
}

// CalcScore calculates the overall score for a node (0-100)
func (s *Scorer) CalcScore(node *NodeMetrics) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Latency score (0-100, lower latency = higher score)
	latencyScore := s.calcLatencyScore(node.AvgLatency)

	// Jitter score (0-100, lower jitter = higher score)
	jitterScore := s.calcJitterScore(node.Jitter)

	// Stability score (0-100, based on success rate)
	stabilityScore := node.SuccessRate * 100

	// Bandwidth score (0-100)
	bandwidthScore := s.calcBandwidthScore(node.Bandwidth)

	// Calculate weighted sum
	total := s.weights.Latency*latencyScore +
		s.weights.Jitter*jitterScore +
		s.weights.Stability*stabilityScore +
		s.weights.Bandwidth*bandwidthScore

	return math.Round(total*100) / 100
}

// calcLatencyScore converts latency to score
// 0ms = 100, 500ms+ = 0
func (s *Scorer) calcLatencyScore(latency time.Duration) float64 {
	ms := latency.Milliseconds()
	if ms <= 0 {
		return 100
	}
	if ms >= 500 {
		return 0
	}
	return 100 - (float64(ms) / 500 * 100)
}

// calcJitterScore converts jitter to score
// 0ms = 100, 100ms+ = 0
func (s *Scorer) calcJitterScore(jitter time.Duration) float64 {
	ms := jitter.Milliseconds()
	if ms <= 0 {
		return 100
	}
	if ms >= 100 {
		return 0
	}
	return 100 - (float64(ms) / 100 * 100)
}

// calcBandwidthScore converts bandwidth to score
// 1Gbps+ = 100, 0 = 0
func (s *Scorer) calcBandwidthScore(bandwidth int64) float64 {
	if bandwidth <= 0 {
		return 0
	}
	mbps := float64(bandwidth) / 1_000_000
	if mbps >= 1000 {
		return 100
	}
	return mbps / 10 // 100Mbps = 10, 500Mbps = 50, 1000Mbps = 100
}

// ScoreBreakdown returns detailed score breakdown
type ScoreBreakdown struct {
	LatencyScore   float64
	JitterScore    float64
	StabilityScore float64
	BandwidthScore float64
	TotalScore     float64
}

// GetBreakdown returns detailed score breakdown
func (s *Scorer) GetBreakdown(node *NodeMetrics) ScoreBreakdown {
	return ScoreBreakdown{
		LatencyScore:   s.calcLatencyScore(node.AvgLatency),
		JitterScore:    s.calcJitterScore(node.Jitter),
		StabilityScore: node.SuccessRate * 100,
		BandwidthScore: s.calcBandwidthScore(node.Bandwidth),
		TotalScore:     s.CalcScore(node),
	}
}
