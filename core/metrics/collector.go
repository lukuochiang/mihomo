package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Collector collects and exports metrics
type Collector struct {
	mu sync.RWMutex

	// Counters
	requestsTotal *prometheus.CounterVec
	bytesTotal    *prometheus.CounterVec
	errorsTotal   *prometheus.CounterVec

	// Gauges
	activeConnections prometheus.Gauge
	nodeScore         *prometheus.GaugeVec
	nodeLatency       *prometheus.GaugeVec

	// Histograms
	requestDuration *prometheus.HistogramVec
	nodeHealthScore *prometheus.HistogramVec

	// Summary
	upstreamLatency *prometheus.SummaryVec

	// Internal metrics
	internal struct {
		requestsTotal uint64
		bytesTotal    uint64
		errorsTotal   uint64
		activeConns   int64
	}
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	c := &Collector{
		requestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mihomo_requests_total",
				Help: "Total number of requests",
			},
			[]string{"node", "status"},
		),
		bytesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mihomo_bytes_total",
				Help: "Total bytes transferred",
			},
			[]string{"node", "direction"}, // direction: in/out
		),
		errorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mihomo_errors_total",
				Help: "Total number of errors",
			},
			[]string{"node", "type"},
		),
		activeConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "mihomo_active_connections",
				Help: "Number of active connections",
			},
		),
		nodeScore: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mihomo_node_score",
				Help: "Node score from smart policy",
			},
			[]string{"node"},
		),
		nodeLatency: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mihomo_node_latency_ms",
				Help: "Node latency in milliseconds",
			},
			[]string{"node"},
		),
		requestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "mihomo_request_duration_seconds",
				Help:    "Request duration in seconds",
				Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
			},
			[]string{"node"},
		),
		nodeHealthScore: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "mihomo_node_health_score",
				Help:    "Node health score distribution",
				Buckets: []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
			},
			[]string{"node"},
		),
		upstreamLatency: promauto.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "mihomo_upstream_latency_seconds",
				Help: "Upstream latency in seconds",
			},
			[]string{"node"},
		),
	}

	return c
}

// RecordRequest records a request
func (c *Collector) RecordRequest(node string, status string) {
	c.requestsTotal.WithLabelValues(node, status).Inc()
	atomic.AddUint64(&c.internal.requestsTotal, 1)
}

// RecordBytes records bytes transferred
func (c *Collector) RecordBytes(node string, direction string, bytes uint64) {
	c.bytesTotal.WithLabelValues(node, direction).Add(float64(bytes))
	atomic.AddUint64(&c.internal.bytesTotal, bytes)
}

// RecordError records an error
func (c *Collector) RecordError(node string, errorType string) {
	c.errorsTotal.WithLabelValues(node, errorType).Inc()
	atomic.AddUint64(&c.internal.errorsTotal, 1)
}

// RecordConnectionChange records connection count change
func (c *Collector) RecordConnectionChange(delta int64) {
	c.activeConnections.Add(float64(delta))
	atomic.AddInt64(&c.internal.activeConns, delta)
}

// SetNodeScore sets node score
func (c *Collector) SetNodeScore(node string, score float64) {
	c.nodeScore.WithLabelValues(node).Set(score)
}

// SetNodeLatency sets node latency
func (c *Collector) SetNodeLatency(node string, latencyMs float64) {
	c.nodeLatency.WithLabelValues(node).Set(latencyMs)
}

// RecordLatency records request latency
func (c *Collector) RecordLatency(node string, duration time.Duration) {
	c.requestDuration.WithLabelValues(node).Observe(duration.Seconds())
	c.upstreamLatency.WithLabelValues(node).Observe(duration.Seconds())
}

// RecordHealthScore records node health score
func (c *Collector) RecordHealthScore(node string, score float64) {
	c.nodeHealthScore.WithLabelValues(node).Observe(score)
}

// GetStats returns internal statistics
func (c *Collector) GetStats() Stats {
	return Stats{
		RequestsTotal: atomic.LoadUint64(&c.internal.requestsTotal),
		BytesTotal:    atomic.LoadUint64(&c.internal.bytesTotal),
		ErrorsTotal:   atomic.LoadUint64(&c.internal.errorsTotal),
		ActiveConns:   int(atomic.LoadInt64(&c.internal.activeConns)),
	}
}

// Stats holds internal statistics
type Stats struct {
	RequestsTotal uint64
	BytesTotal    uint64
	ErrorsTotal   uint64
	ActiveConns   int
}

// Reset resets all internal counters
func (c *Collector) Reset() {
	atomic.StoreUint64(&c.internal.requestsTotal, 0)
	atomic.StoreUint64(&c.internal.bytesTotal, 0)
	atomic.StoreUint64(&c.internal.errorsTotal, 0)
	atomic.StoreInt64(&c.internal.activeConns, 0)
}
