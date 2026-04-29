package smart

import (
	"context"
	"sync"
	"time"

	"github.com/mihomo/smart/core/metrics"
)

// SelectionMode defines the node selection strategy
type SelectionMode string

const (
	ModeAuto     SelectionMode = "auto"
	ModeFast     SelectionMode = "fast"
	ModeStable   SelectionMode = "stable"
	ModeBalanced SelectionMode = "balanced"
	ModeLearning SelectionMode = "learning"
)

// Config holds Smart configuration
type Config struct {
	MetricsCollector *metrics.Collector
	LearningEnabled  bool
	SelectionMode    SelectionMode
	UpdateInterval   time.Duration
}

// Smart is the main Smart policy engine
type Smart struct {
	config    Config
	scorer    *Scorer
	selector  *Selector
	metrics   *metrics.Collector
	predictor *Predictor
	learning  *Learner
	nodes     map[string]*NodeMetrics
	nodesMu   sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NodeMetrics holds metrics for a single node
type NodeMetrics struct {
	ID          string
	Name        string
	Address     string
	LastLatency time.Duration
	AvgLatency  time.Duration
	Jitter      time.Duration
	PacketLoss  float64
	SuccessRate float64
	Bandwidth   int64
	LastCheck   time.Time
	Score       float64
	History     *LatencyHistory
}

// NewSmart creates a new Smart instance
func NewSmart(cfg Config) *Smart {
	if cfg.UpdateInterval == 0 {
		cfg.UpdateInterval = 5 * time.Second
	}
	if cfg.SelectionMode == "" {
		cfg.SelectionMode = ModeAuto
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm := &Smart{
		config:    cfg,
		scorer:    NewScorer(),
		selector:  NewSelector(),
		predictor: NewPredictor(),
		nodes:     make(map[string]*NodeMetrics),
		ctx:       ctx,
		cancel:    cancel,
	}

	if cfg.LearningEnabled {
		sm.learning = NewLearner()
	}

	// Start background tasks
	sm.wg.Add(1)
	go sm.updateLoop()

	return sm
}

// RegisterNode adds a new node to the pool
func (sm *Smart) RegisterNode(id, name, address string) {
	sm.nodesMu.Lock()
	defer sm.nodesMu.Unlock()

	if _, exists := sm.nodes[id]; !exists {
		sm.nodes[id] = &NodeMetrics{
			ID:      id,
			Name:    name,
			Address: address,
			History: &LatencyHistory{
				Data:    make([]time.Duration, 100),
				MaxSize: 100,
			},
		}
	}
}

// UnregisterNode removes a node from the pool
func (sm *Smart) UnregisterNode(id string) {
	sm.nodesMu.Lock()
	defer sm.nodesMu.Unlock()
	delete(sm.nodes, id)
}

// UpdateMetrics updates node metrics
func (sm *Smart) UpdateMetrics(id string, latency time.Duration, success bool) {
	sm.nodesMu.Lock()
	defer sm.nodesMu.Unlock()

	node, exists := sm.nodes[id]
	if !exists {
		return
	}

	node.LastCheck = time.Now()
	node.LastLatency = latency

	// Update history
	node.History.add(latency)

	// Calculate averages
	node.AvgLatency = node.History.avg()
	node.Jitter = node.History.jitter()

	// Update success rate (exponential moving average)
	if success {
		node.SuccessRate = node.SuccessRate*0.9 + 0.1
	} else {
		node.SuccessRate = node.SuccessRate * 0.9
	}

	// Calculate score
	node.Score = sm.scorer.CalcScore(node)
}

// SelectNode selects the best node based on current mode
func (sm *Smart) SelectNode(ctx context.Context) (string, error) {
	sm.nodesMu.RLock()
	defer sm.nodesMu.RUnlock()

	if len(sm.nodes) == 0 {
		return "", ErrNoNodesAvailable
	}

	nodes := make([]*NodeMetrics, 0, len(sm.nodes))
	for _, n := range sm.nodes {
		nodes = append(nodes, n)
	}

	return sm.selector.Select(ctx, nodes, sm.config.SelectionMode)
}

// SelectNodeForTarget selects the best node for a specific target
func (sm *Smart) SelectNodeForTarget(ctx context.Context, targetRegion string) (string, error) {
	sm.nodesMu.RLock()
	defer sm.nodesMu.RUnlock()

	if len(sm.nodes) == 0 {
		return "", ErrNoNodesAvailable
	}

	nodes := make([]*NodeMetrics, 0, len(sm.nodes))
	for _, n := range sm.nodes {
		nodes = append(nodes, n)
	}

	return sm.selector.SelectForTarget(ctx, nodes, targetRegion)
}

// PredictLatency predicts future latency for a node
func (sm *Smart) PredictLatency(nodeID string) (time.Duration, bool) {
	sm.nodesMu.RLock()
	node, exists := sm.nodes[nodeID]
	sm.nodesMu.RUnlock()

	if !exists || node.History.Len() < 10 {
		return 0, false
	}

	return sm.predictor.Predict(node.History)
}

// GetStats returns current statistics
func (sm *Smart) GetStats() Stats {
	sm.nodesMu.RLock()
	defer sm.nodesMu.RUnlock()

	var totalNodes = len(sm.nodes)
	var avgScore float64
	var bestScore float64
	var bestNode string

	for id, node := range sm.nodes {
		avgScore += node.Score
		if node.Score > bestScore {
			bestScore = node.Score
			bestNode = id
		}
	}

	if totalNodes > 0 {
		avgScore /= float64(totalNodes)
	}

	return Stats{
		TotalNodes: totalNodes,
		AvgScore:   avgScore,
		BestScore:  bestScore,
		BestNode:   bestNode,
		Mode:       sm.config.SelectionMode,
	}
}

// Stats holds statistics
type Stats struct {
	TotalNodes int
	AvgScore   float64
	BestScore  float64
	BestNode   string
	Mode       SelectionMode
}

// Close stops the Smart engine
func (sm *Smart) Close() error {
	sm.cancel()
	sm.wg.Wait()
	return nil
}

func (sm *Smart) updateLoop() {
	defer sm.wg.Done()

	ticker := time.NewTicker(sm.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.refreshScores()
		}
	}
}

func (sm *Smart) refreshScores() {
	sm.nodesMu.Lock()
	defer sm.nodesMu.Unlock()

	for _, node := range sm.nodes {
		node.Score = sm.scorer.CalcScore(node)
	}
}

// Error definitions
var (
	ErrNoNodesAvailable = &SmartError{Code: "NO_NODES", Message: "no nodes available"}
)

// SmartError represents an error in Smart
type SmartError struct {
	Code    string
	Message string
}

func (e *SmartError) Error() string {
	return e.Code + ": " + e.Message
}
