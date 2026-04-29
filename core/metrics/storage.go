package metrics

import (
	"encoding/json"
	"sync"
	"time"
)

// Storage stores historical metrics data
type Storage struct {
	mu     sync.RWMutex
	window time.Duration
	data   map[string]*NodeMetricsData
	dataMu sync.RWMutex
}

// NodeMetricsData holds time-series data for a node
type NodeMetricsData struct {
	NodeID      string
	Latencies   []TimedValue
	Scores      []TimedValue
	SuccessRate []TimedValue
	PacketsIn   []TimedValue
	PacketsOut  []TimedValue
	BytesIn     []TimedValue
	BytesOut    []TimedValue
	LastUpdate  time.Time
}

// TimedValue is a timestamped value
type TimedValue struct {
	Timestamp time.Time
	Value     float64
}

// NewStorage creates a new metrics storage
func NewStorage(window time.Duration) *Storage {
	if window == 0 {
		window = 24 * time.Hour
	}

	return &Storage{
		window: window,
		data:   make(map[string]*NodeMetricsData),
	}
}

// AddLatency adds a latency measurement
func (s *Storage) AddLatency(nodeID string, latency time.Duration) {
	s.addValue(nodeID, "latency", latency.Seconds()*1000) // Store in ms
}

// AddScore adds a score measurement
func (s *Storage) AddScore(nodeID string, score float64) {
	s.addValue(nodeID, "score", score)
}

// AddSuccessRate adds a success rate measurement
func (s *Storage) AddSuccessRate(nodeID string, rate float64) {
	s.addValue(nodeID, "success", rate*100)
}

// AddBytes adds bytes measurement
func (s *Storage) AddBytes(nodeID string, direction string, bytes uint64) {
	field := "bytes_in"
	if direction == "out" {
		field = "bytes_out"
	}
	s.addValue(nodeID, field, float64(bytes))
}

func (s *Storage) addValue(nodeID, field string, value float64) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()

	node, exists := s.data[nodeID]
	if !exists {
		node = &NodeMetricsData{
			NodeID:      nodeID,
			Latencies:   make([]TimedValue, 0, 1000),
			Scores:      make([]TimedValue, 0, 1000),
			SuccessRate: make([]TimedValue, 0, 1000),
			PacketsIn:   make([]TimedValue, 0, 1000),
			PacketsOut:  make([]TimedValue, 0, 1000),
			BytesIn:     make([]TimedValue, 0, 1000),
			BytesOut:    make([]TimedValue, 0, 1000),
		}
		s.data[nodeID] = node
	}

	now := time.Now()
	node.LastUpdate = now

	switch field {
	case "latency":
		node.Latencies = append(node.Latencies, TimedValue{Timestamp: now, Value: value})
	case "score":
		node.Scores = append(node.Scores, TimedValue{Timestamp: now, Value: value})
	case "success":
		node.SuccessRate = append(node.SuccessRate, TimedValue{Timestamp: now, Value: value})
	case "bytes_in":
		node.BytesIn = append(node.BytesIn, TimedValue{Timestamp: now, Value: value})
	case "bytes_out":
		node.BytesOut = append(node.BytesOut, TimedValue{Timestamp: now, Value: value})
	}

	// Trim old data
	s.trimOldData(node, now)
}

func (s *Storage) trimOldData(node *NodeMetricsData, now time.Time) {
	cutoff := now.Add(-s.window)

	trim := func(data []TimedValue) []TimedValue {
		i := 0
		for i < len(data) && data[i].Timestamp.Before(cutoff) {
			i++
		}
		if i > 0 {
			return data[i:]
		}
		return data
	}

	node.Latencies = trim(node.Latencies)
	node.Scores = trim(node.Scores)
	node.SuccessRate = trim(node.SuccessRate)
	node.PacketsIn = trim(node.PacketsIn)
	node.PacketsOut = trim(node.PacketsOut)
	node.BytesIn = trim(node.BytesIn)
	node.BytesOut = trim(node.BytesOut)
}

// GetLatencies returns latency history for a node
func (s *Storage) GetLatencies(nodeID string) []TimedValue {
	s.dataMu.RLock()
	defer s.dataMu.RUnlock()

	if node, ok := s.data[nodeID]; ok {
		result := make([]TimedValue, len(node.Latencies))
		copy(result, node.Latencies)
		return result
	}
	return nil
}

// GetScores returns score history for a node
func (s *Storage) GetScores(nodeID string) []TimedValue {
	s.dataMu.RLock()
	defer s.dataMu.RUnlock()

	if node, ok := s.data[nodeID]; ok {
		result := make([]TimedValue, len(node.Scores))
		copy(result, node.Scores)
		return result
	}
	return nil
}

// GetSummary returns a summary for a node
func (s *Storage) GetSummary(nodeID string) *Summary {
	s.dataMu.RLock()
	defer s.dataMu.RUnlock()

	if node, ok := s.data[nodeID]; ok {
		return &Summary{
			NodeID:      nodeID,
			SampleCount: len(node.Latencies),
			LastUpdate:  node.LastUpdate,
			AvgLatency:  avg(node.Latencies),
			MinLatency:  min(node.Latencies),
			MaxLatency:  max(node.Latencies),
			AvgScore:    avg(node.Scores),
			AvgSuccess:  avg(node.SuccessRate),
		}
	}
	return nil
}

// Summary holds a metrics summary
type Summary struct {
	NodeID      string
	SampleCount int
	LastUpdate  time.Time
	AvgLatency  float64
	MinLatency  float64
	MaxLatency  float64
	AvgScore    float64
	AvgSuccess  float64
}

func avg(values []TimedValue) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v.Value
	}
	return sum / float64(len(values))
}

func min(values []TimedValue) float64 {
	if len(values) == 0 {
		return 0
	}
	m := values[0].Value
	for _, v := range values {
		if v.Value < m {
			m = v.Value
		}
	}
	return m
}

func max(values []TimedValue) float64 {
	if len(values) == 0 {
		return 0
	}
	m := values[0].Value
	for _, v := range values {
		if v.Value > m {
			m = v.Value
		}
	}
	return m
}

// Export exports all data as JSON
func (s *Storage) Export() ([]byte, error) {
	s.dataMu.RLock()
	defer s.dataMu.RUnlock()

	type exportData struct {
		Window time.Duration               `json:"window"`
		Data   map[string]*NodeMetricsData `json:"data"`
	}

	return json.MarshalIndent(exportData{
		Window: s.window,
		Data:   s.data,
	}, "", "  ")
}

// GetAllSummaries returns summaries for all nodes
func (s *Storage) GetAllSummaries() map[string]*Summary {
	s.dataMu.RLock()
	defer s.dataMu.RUnlock()

	result := make(map[string]*Summary)
	for nodeID := range s.data {
		result[nodeID] = s.GetSummary(nodeID)
	}
	return result
}

// Clear clears all data for a node
func (s *Storage) Clear(nodeID string) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	delete(s.data, nodeID)
}

// ClearAll clears all data
func (s *Storage) ClearAll() {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	s.data = make(map[string]*NodeMetricsData)
}
