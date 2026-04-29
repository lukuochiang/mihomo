package smart

import (
	"sync"
	"time"
)

// Predictor predicts future latency using simple exponential smoothing
type Predictor struct {
	mu        sync.RWMutex
	alpha     float64 // Smoothing factor (0-1)
	beta      float64 // Trend factor
	forecasts map[string]*Forecast
}

// Forecast holds prediction state for a node
type Forecast struct {
	Value        float64   // Current predicted value
	Trend        float64   // Current trend
	Season       []float64 // Seasonality (optional)
	SeasonPeriod int
}

// NewPredictor creates a new Predictor
func NewPredictor() *Predictor {
	return &Predictor{
		alpha:     0.3,
		beta:      0.1,
		forecasts: make(map[string]*Forecast),
	}
}

// Predict predicts future latency based on historical data
func (p *Predictor) Predict(history *LatencyHistory) (time.Duration, bool) {
	if history.Len() < 5 {
		return 0, false
	}

	values := history.GetAll()
	if len(values) < 5 {
		return 0, false
	}

	// Use Holt's linear exponential smoothing
	forecast := p.holtForecast(values)

	return time.Duration(forecast) * time.Millisecond, true
}

// holtForecast implements Holt's linear exponential smoothing
func (p *Predictor) holtForecast(values []time.Duration) float64 {
	p.mu.RLock()
	alpha := p.alpha
	beta := p.beta
	p.mu.RUnlock()

	if len(values) < 2 {
		return float64(values[0].Milliseconds())
	}

	// Initialize
	s := float64(values[0].Milliseconds())
	t := float64(values[1].Milliseconds()) - float64(values[0].Milliseconds())

	// Apply smoothing
	for i := 1; i < len(values); i++ {
		v := float64(values[i].Milliseconds())
		newS := alpha*v + (1-alpha)*(s+t)
		newT := beta*(newS-s) + (1-beta)*t
		s = newS
		t = newT
	}

	// Forecast next value
	return s + t
}

// GetForecast returns forecast for a node
func (p *Predictor) GetForecast(nodeID string) (value, trend float64, ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	f, exists := p.forecasts[nodeID]
	if !exists {
		return 0, 0, false
	}
	return f.Value, f.Trend, true
}

// UpdateForecast updates forecast with new data point
func (p *Predictor) UpdateForecast(nodeID string, latency time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	f, exists := p.forecasts[nodeID]
	if !exists {
		f = &Forecast{}
		p.forecasts[nodeID] = f
	}

	alpha := p.alpha
	beta := p.beta

	v := float64(latency.Milliseconds())
	if f.Value == 0 {
		f.Value = v
	} else {
		newS := alpha*v + (1-alpha)*(f.Value+f.Trend)
		newT := beta*(newS-f.Value) + (1-beta)*f.Trend
		f.Value = newS
		f.Trend = newT
	}
}

// RemoveForecast removes forecast for a node
func (p *Predictor) RemoveForecast(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.forecasts, nodeID)
}

// SetAlpha sets smoothing factor
func (p *Predictor) SetAlpha(alpha float64) {
	if alpha < 0 || alpha > 1 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.alpha = alpha
}

// SetBeta sets trend factor
func (p *Predictor) SetBeta(beta float64) {
	if beta < 0 || beta > 1 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beta = beta
}

// ConfidenceInterval calculates confidence interval for forecast
func (p *Predictor) ConfidenceInterval(history *LatencyHistory, confidence float64) (lower, upper time.Duration, ok bool) {
	if history.Len() < 10 {
		return 0, 0, false
	}

	values := history.GetAll()

	// Calculate standard deviation
	var sum, sumSq float64
	for _, v := range values {
		ms := float64(v.Milliseconds())
		sum += ms
		sumSq += ms * ms
	}

	n := float64(len(values))
	mean := sum / n
	variance := (sumSq / n) - (mean * mean)
	stdDev := variancesqrt(variance)

	// Get forecast
	forecast, ok := p.Predict(history)
	if !ok {
		return 0, 0, false
	}

	// Calculate margin
	margin := stdDev * confidence

	return forecast - time.Duration(margin)*time.Millisecond, forecast + time.Duration(margin)*time.Millisecond, true
}

// SeasonalityDetector detects periodic patterns
type SeasonalityDetector struct {
	period int
	data   []float64
}

// NewSeasonalityDetector creates a new detector
func NewSeasonalityDetector(period int) *SeasonalityDetector {
	return &SeasonalityDetector{
		period: period,
		data:   make([]float64, 0),
	}
}

// Add adds a data point
func (s *SeasonalityDetector) Add(value float64) {
	s.data = append(s.data, value)
	if len(s.data) > s.period*10 {
		s.data = s.data[len(s.data)-s.period*10:]
	}
}

// Detect returns true if periodicity is detected
func (s *SeasonalityDetector) Detect() bool {
	if len(s.data) < s.period*2 {
		return false
	}

	// Simple autocorrelation check
	lag := s.period
	mean := 0.0
	for _, v := range s.data {
		mean += v
	}
	mean /= float64(len(s.data))

	n := len(s.data) - lag
	if n <= 0 {
		return false
	}

	var correlation float64
	for i := 0; i < n; i++ {
		correlation += (s.data[i] - mean) * (s.data[i+lag] - mean)
	}

	var variance float64
	for _, v := range s.data {
		variance += (v - mean) * (v - mean)
	}

	if variance == 0 {
		return false
	}

	correlation /= variance
	return correlation > 0.7 // Strong correlation threshold
}
