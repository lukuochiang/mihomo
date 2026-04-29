package smart

import (
	"sync"
	"time"
)

// LatencyHistory stores historical latency data with fixed-size circular buffer
type LatencyHistory struct {
	Data     []time.Duration
	MaxSize  int
	InsertAt int
	mu       sync.Mutex
}

// NewLatencyHistory creates a new LatencyHistory
func NewLatencyHistory(maxSize int) *LatencyHistory {
	if maxSize <= 0 {
		maxSize = 100
	}
	return &LatencyHistory{
		Data:    make([]time.Duration, maxSize),
		MaxSize: maxSize,
	}
}

// add adds a new latency value
func (h *LatencyHistory) add(latency time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Data[h.InsertAt] = latency
	h.InsertAt = (h.InsertAt + 1) % h.MaxSize
}

// Len returns number of data points
func (h *LatencyHistory) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	count := 0
	for i := 0; i < h.MaxSize; i++ {
		if h.Data[i] > 0 {
			count++
		}
	}
	return count
}

// avg calculates average latency
func (h *LatencyHistory) avg() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	var sum int64
	var count int
	for _, d := range h.Data {
		if d > 0 {
			sum += d.Nanoseconds()
			count++
		}
	}

	if count == 0 {
		return 0
	}
	return time.Duration(sum / int64(count))
}

// jitter calculates latency jitter (standard deviation)
func (h *LatencyHistory) jitter() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	var values []int64
	for _, d := range h.Data {
		if d > 0 {
			values = append(values, d.Nanoseconds())
		}
	}

	if len(values) < 2 {
		return 0
	}

	// Calculate mean
	var sum int64
	for _, v := range values {
		sum += v
	}
	mean := float64(sum) / float64(len(values))

	// Calculate variance
	var varianceSum float64
	for _, v := range values {
		diff := float64(v) - mean
		varianceSum += diff * diff
	}
	variance := varianceSum / float64(len(values))

	return time.Duration(variancesqrt(variance))
}

// variancesqrt is math.Sqrt for float64
func variancesqrt(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v == 0 {
		return 0
	}

	// Newton's method
	x := v
	for i := 0; i < 20; i++ {
		x = (x + v/x) / 2
	}
	return x
}

// percentile calculates percentile (0-100)
func (h *LatencyHistory) percentile(p float64) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	var values []int64
	for _, d := range h.Data {
		if d > 0 {
			values = append(values, d.Nanoseconds())
		}
	}

	if len(values) == 0 {
		return 0
	}

	// Sort
	for i := 0; i < len(values)-1; i++ {
		for j := i + 1; j < len(values); j++ {
			if values[i] > values[j] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}

	idx := int(float64(len(values)-1) * p / 100)
	if idx >= len(values) {
		idx = len(values) - 1
	}

	return time.Duration(values[idx])
}

// min returns minimum latency
func (h *LatencyHistory) min() time.Duration {
	return h.percentile(0)
}

// max returns maximum latency
func (h *LatencyHistory) max() time.Duration {
	return h.percentile(100)
}

// median returns median latency
func (h *LatencyHistory) median() time.Duration {
	return h.percentile(50)
}

// p95 returns 95th percentile latency
func (h *LatencyHistory) p95() time.Duration {
	return h.percentile(95)
}

// p99 returns 99th percentile latency
func (h *LatencyHistory) p99() time.Duration {
	return h.percentile(99)
}

// GetAll returns all values as slice
func (h *LatencyHistory) GetAll() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	var result []time.Duration
	for _, d := range h.Data {
		if d > 0 {
			result = append(result, d)
		}
	}
	return result
}

// Reset clears all data
func (h *LatencyHistory) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i := range h.Data {
		h.Data[i] = 0
	}
	h.InsertAt = 0
}
