package smart

import (
	"math"
	"sync"
	"time"
)

// Learner implements simple machine learning for node selection
type Learner struct {
	mu           sync.RWMutex
	patterns     map[string]*Pattern
	feedbackChan chan Feedback
	stopChan     chan struct{}
}

// Pattern represents learned pattern
type Pattern struct {
	Target      string
	BestNode    string
	TimeOfDay   int // Hour of day (0-23)
	DayOfWeek   int // Day of week (0-6)
	SuccessRate float64
	SampleCount int
}

// Feedback represents selection feedback
type Feedback struct {
	NodeID    string
	Target    string
	Latency   time.Duration
	Success   bool
	Timestamp time.Time
}

// NewLearner creates a new Learner
func NewLearner() *Learner {
	l := &Learner{
		patterns:     make(map[string]*Pattern),
		feedbackChan: make(chan Feedback, 1000),
		stopChan:     make(chan struct{}),
	}

	// Start feedback processor
	go l.processFeedback()

	return l
}

// processFeedback processes feedback in background
func (l *Learner) processFeedback() {
	for {
		select {
		case <-l.stopChan:
			return
		case fb := <-l.feedbackChan:
			l.learn(fb)
		}
	}
}

// learn learns from feedback
func (l *Learner) learn(fb Feedback) {
	l.mu.Lock()
	defer l.mu.Unlock()

	pattern := l.makeKey(fb.Target, fb.Timestamp)
	p, exists := l.patterns[pattern]

	if !exists {
		p = &Pattern{
			Target:      fb.Target,
			TimeOfDay:   fb.Timestamp.Hour(),
			DayOfWeek:   int(fb.Timestamp.Weekday()),
			SampleCount: 0,
		}
		l.patterns[pattern] = p
	}

	// Update success rate with exponential moving average
	if fb.Success {
		if p.SampleCount == 0 {
			p.SuccessRate = 1.0
		} else {
			p.SuccessRate = p.SuccessRate*0.9 + 0.1
		}
	} else {
		if p.SampleCount == 0 {
			p.SuccessRate = 0.0
		} else {
			p.SuccessRate = p.SuccessRate * 0.9
		}
	}

	// If this node is best for this pattern, record it
	if fb.Success && (p.BestNode == "" || p.BestNode == fb.NodeID) {
		p.BestNode = fb.NodeID
	}

	p.SampleCount++
}

// makeKey generates pattern key based on target and time
func (l *Learner) makeKey(target string, t time.Time) string {
	return target + "_" +
		t.Format("1504") + "_" + // Hour in 24h format (e.g., "1430")
		t.Weekday().String() // Day of week (e.g., "Monday")
}

// Recommend recommends best node for target based on learned patterns
func (l *Learner) Recommend(target string, candidateNodes []string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	now := time.Now()
	hour := now.Hour()
	day := int(now.Weekday())

	// Find best matching pattern
	var bestPattern *Pattern
	var bestScore float64

	for _, p := range l.patterns {
		if p.Target != target {
			continue
		}

		// Score based on time match
		timeScore := 1.0
		if p.TimeOfDay == hour {
			timeScore = 2.0
		}
		if p.DayOfWeek == day {
			timeScore *= 1.5
		}

		combinedScore := p.SuccessRate * timeScore * math.Sqrt(float64(p.SampleCount))
		if combinedScore > bestScore {
			bestScore = combinedScore
			bestPattern = p
		}
	}

	if bestPattern != nil && bestPattern.BestNode != "" {
		// Verify node is still available
		for _, n := range candidateNodes {
			if n == bestPattern.BestNode {
				return n
			}
		}
	}

	// Fallback: return most successful node overall
	var bestNode string
	var bestSuccess float64

	for _, p := range l.patterns {
		if p.SuccessRate > bestSuccess {
			bestSuccess = p.SuccessRate
			bestNode = p.BestNode
		}
	}

	return bestNode
}

// RecordFeedback records feedback for learning
func (l *Learner) RecordFeedback(fb Feedback) {
	select {
	case l.feedbackChan <- fb:
	default:
		// Channel full, skip
	}
}

// GetStats returns learning statistics
func (l *Learner) GetStats() LearnerStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var totalPatterns int
	var avgSuccessRate float64
	var bestPattern *Pattern

	for _, p := range l.patterns {
		totalPatterns++
		avgSuccessRate += p.SuccessRate
		if bestPattern == nil || p.SampleCount > bestPattern.SampleCount {
			bestPattern = p
		}
	}

	if totalPatterns > 0 {
		avgSuccessRate /= float64(totalPatterns)
	}

	return LearnerStats{
		TotalPatterns:  totalPatterns,
		AvgSuccessRate: avgSuccessRate,
		BestPattern:    bestPattern,
	}
}

// LearnerStats holds learner statistics
type LearnerStats struct {
	TotalPatterns  int
	AvgSuccessRate float64
	BestPattern    *Pattern
}

// Clear clears all learned patterns
func (l *Learner) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k := range l.patterns {
		delete(l.patterns, k)
	}
}

// Close stops the learner
func (l *Learner) Close() error {
	close(l.stopChan)
	return nil
}

// Export exports patterns
func (l *Learner) Export() map[string]Pattern {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make(map[string]Pattern)
	for k, p := range l.patterns {
		result[k] = *p
	}
	return result
}

// Import imports patterns
func (l *Learner) Import(patterns map[string]Pattern) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, p := range patterns {
		l.patterns[k] = &p
	}
}
