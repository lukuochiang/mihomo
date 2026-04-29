package ntp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// NTP configuration and constants
const (
	// NTP epoch offset (seconds from 1900-01-01 to 1970-01-01)
	ntpEpochOffset = 2208988800

	// NTP port
	ntpPort = 123

	// Default NTP servers
	DefaultServer1 = "pool.ntp.org"
	DefaultServer2 = "time.google.com"

	// Mode constants
	NTPModeClient    = 3
	NTPModeServer    = 4
	NTPModeSymmetric = 1
	NTPModeBroadcast = 5

	// NTP version
	NTPVersion = 4

	// NTP packet size
	ntpPacketSize = 48
)

// NTPConfig holds NTP client configuration
type NTPConfig struct {
	Servers          []string      `yaml:"servers"`
	Interval         time.Duration `yaml:"interval"`           // Sync interval
	Timeout          time.Duration `yaml:"timeout"`            // Request timeout
	MaxRetries       int           `yaml:"max-retries"`        // Max retries on failure
	RetryInterval    time.Duration `yaml:"retry-interval"`     // Interval between retries
	ForceSync        bool          `yaml:"force-sync"`         // Force sync even if offset is small
	MinSyncThreshold time.Duration `yaml:"min-sync-threshold"` // Minimum offset to trigger sync
}

// NTPClient provides NTP time synchronization
type NTPClient struct {
	config   *NTPConfig
	servers  []string
	offset   time.Duration // Clock offset
	latency  time.Duration // Round trip latency
	mu       sync.RWMutex
	synced   atomic.Bool
	stopChan chan struct{}
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
	syncedAt time.Time
}

// NTPPacket represents an NTP packet
type NTPPacket struct {
	Settings       uint8  // LI, Version, Mode
	Stratum        uint8  // Clock stratum
	Poll           int8   // Poll interval
	Precision      int8   // Precision
	RootDelay      uint32 // Root delay
	RootDispersion uint32 // Root dispersion
	ReferenceID    uint32 // Reference ID
	RefTimeSec     uint32 // Reference timestamp (seconds)
	RefTimeFrac    uint32 // Reference timestamp (fractional)
	OrigTimeSec    uint32 // Origin timestamp (seconds)
	OrigTimeFrac   uint32 // Origin timestamp (fractional)
	RecvTimeSec    uint32 // Receive timestamp (seconds)
	RecvTimeFrac   uint32 // Receive timestamp (fractional)
	TransTimeSec   uint32 // Transmit timestamp (seconds)
	TransTimeFrac  uint32 // Transmit timestamp (fractional)
}

// NewNTPClient creates a new NTP client
func NewNTPClient(cfg *NTPConfig) *NTPClient {
	if cfg == nil {
		cfg = &NTPConfig{
			Servers:          []string{DefaultServer1, DefaultServer2},
			Interval:         1 * time.Hour,
			Timeout:          5 * time.Second,
			MaxRetries:       3,
			RetryInterval:    5 * time.Second,
			ForceSync:        false,
			MinSyncThreshold: 100 * time.Millisecond,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &NTPClient{
		config:   cfg,
		servers:  cfg.Servers,
		stopChan: make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start starts the NTP client background sync
func (c *NTPClient) Start() error {
	// Initial sync
	if err := c.Sync(); err != nil {
		slog.Warn("initial NTP sync failed", "error", err)
	}

	// Start background sync
	c.wg.Add(1)
	go c.syncLoop()

	slog.Info("NTP client started", "servers", c.servers, "interval", c.config.Interval)
	return nil
}

// Stop stops the NTP client
func (c *NTPClient) Stop() {
	close(c.stopChan)
	c.cancel()
	c.wg.Wait()
	slog.Info("NTP client stopped")
}

// syncLoop runs periodic synchronization
func (c *NTPClient) syncLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.Sync(); err != nil {
				slog.Warn("NTP sync failed", "error", err)
			}
		case <-c.stopChan:
			return
		}
	}
}

// Sync performs immediate time synchronization
func (c *NTPClient) Sync() error {
	var lastErr error

	for i := 0; i < c.config.MaxRetries; i++ {
		for _, server := range c.servers {
			offset, latency, err := c.queryServer(server)
			if err != nil {
				lastErr = err
				slog.Debug("NTP query failed", "server", server, "error", err)
				continue
			}

			// Check if offset is significant enough to sync
			if !c.config.ForceSync && offset < c.config.MinSyncThreshold && offset > -c.config.MinSyncThreshold {
				slog.Debug("NTP offset too small, skipping sync", "offset", offset, "threshold", c.config.MinSyncThreshold)
				c.mu.Lock()
				c.syncedAt = time.Now()
				c.mu.Unlock()
				return nil
			}

			// Apply offset
			if err := c.applyOffset(offset); err != nil {
				return err
			}

			c.mu.Lock()
			c.offset = offset
			c.latency = latency
			c.synced.Store(true)
			c.syncedAt = time.Now()
			c.mu.Unlock()

			slog.Info("NTP sync completed", "server", server, "offset", offset, "latency", latency)
			return nil
		}

		// Wait before retry
		select {
		case <-time.After(c.config.RetryInterval):
		case <-c.stopChan:
			return nil
		}
	}

	return fmt.Errorf("all NTP servers failed, last error: %w", lastErr)
}

// queryServer queries a single NTP server
func (c *NTPClient) queryServer(server string) (offset, latency time.Duration, err error) {
	// Resolve server address
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", server, ntpPort))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to resolve server: %w", err)
	}

	// Create connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Set deadline
	deadline := time.Now().Add(c.config.Timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, 0, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Send request
	sendTime := time.Now()
	packet := c.createPacket()
	packetBytes := c.encodePacket(packet)

	if _, err := conn.Write(packetBytes); err != nil {
		return 0, 0, fmt.Errorf("failed to send packet: %w", err)
	}

	// Receive response
	response := make([]byte, ntpPacketSize+8)
	n, _, err := conn.ReadFromUDP(response)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to receive response: %w", err)
	}

	recvTime := time.Now()

	if n < ntpPacketSize {
		return 0, 0, fmt.Errorf("response too short: %d bytes", n)
	}

	// Parse response
	recvPacket := c.parsePacket(response[:ntpPacketSize])

	// Calculate offset and latency
	origTime := c.decodeTimestamp(recvPacket.OrigTimeSec, recvPacket.OrigTimeFrac)
	xmitTime := c.decodeTimestamp(recvPacket.TransTimeSec, recvPacket.TransTimeFrac)

	// NTP offset = ((t1 - t0) + (t3 - t2)) / 2
	// where t0 = orig, t1 = recv, t2 = xmit, t3 = recvTime
	offset = ((recvTime.Sub(origTime)) + (xmitTime.Sub(sendTime))) / 2
	latency = sendTime.Sub(origTime) + recvTime.Sub(xmitTime)

	return offset, latency, nil
} // createPacket creates an NTP request packet
func (c *NTPClient) createPacket() NTPPacket {
	var packet NTPPacket

	// Settings: LI (0) + Version (4) + Mode (3 = client)
	packet.Settings = (NTPVersion << 3) | NTPModeClient

	// Stratum (0 = unspecified)
	packet.Stratum = 0

	// Poll interval (0)
	packet.Poll = 0

	// Precision (0 = 1 second)
	packet.Precision = 0

	// Set originate timestamp
	now := time.Now()
	sec, frac := c.encodeTimestamp(now)
	packet.OrigTimeSec = sec
	packet.OrigTimeFrac = frac

	return packet
}

// encodePacket encodes NTPPacket to bytes for sending
func (c *NTPClient) encodePacket(p NTPPacket) []byte {
	buf := make([]byte, ntpPacketSize)
	buf[0] = p.Settings
	buf[1] = p.Stratum
	buf[2] = byte(p.Poll)
	buf[3] = byte(p.Precision)
	binary.BigEndian.PutUint32(buf[4:8], p.RootDelay)
	binary.BigEndian.PutUint32(buf[8:12], p.RootDispersion)
	binary.BigEndian.PutUint32(buf[12:16], p.ReferenceID)
	binary.BigEndian.PutUint32(buf[16:20], p.RefTimeSec)
	binary.BigEndian.PutUint32(buf[20:24], p.RefTimeFrac)
	binary.BigEndian.PutUint32(buf[24:28], p.OrigTimeSec)
	binary.BigEndian.PutUint32(buf[28:32], p.OrigTimeFrac)
	binary.BigEndian.PutUint32(buf[32:36], p.RecvTimeSec)
	binary.BigEndian.PutUint32(buf[36:40], p.RecvTimeFrac)
	binary.BigEndian.PutUint32(buf[40:44], p.TransTimeSec)
	binary.BigEndian.PutUint32(buf[44:48], p.TransTimeFrac)
	return buf
}

// parsePacket parses an NTP response packet
func (c *NTPClient) parsePacket(data []byte) NTPPacket {
	var packet NTPPacket

	packet.Settings = data[0]
	packet.Stratum = data[1]
	packet.Poll = int8(data[2])
	packet.Precision = int8(data[3])
	packet.RootDelay = binary.BigEndian.Uint32(data[4:8])
	packet.RootDispersion = binary.BigEndian.Uint32(data[8:12])
	packet.ReferenceID = binary.BigEndian.Uint32(data[12:16])
	packet.RefTimeSec = binary.BigEndian.Uint32(data[16:20])
	packet.RefTimeFrac = binary.BigEndian.Uint32(data[20:24])
	packet.OrigTimeSec = binary.BigEndian.Uint32(data[24:28])
	packet.OrigTimeFrac = binary.BigEndian.Uint32(data[28:32])
	packet.RecvTimeSec = binary.BigEndian.Uint32(data[32:36])
	packet.RecvTimeFrac = binary.BigEndian.Uint32(data[36:40])
	packet.TransTimeSec = binary.BigEndian.Uint32(data[40:44])
	packet.TransTimeFrac = binary.BigEndian.Uint32(data[44:48])

	return packet
}

// encodeTimestamp encodes time.Time to NTP timestamp
func (c *NTPClient) encodeTimestamp(t time.Time) (sec, frac uint32) {
	nsec := t.UnixNano()
	sec = uint32(nsec/1e9 + ntpEpochOffset)
	frac = uint32((uint64(nsec%1e9) << 32) / 1e9)
	return sec, frac
}

// decodeTimestamp decodes NTP timestamp to time.Time
func (c *NTPClient) decodeTimestamp(sec, frac uint32) time.Time {
	// Convert seconds since 1900 to seconds since 1970
	sec -= ntpEpochOffset

	// Convert fractional part to nanoseconds
	nsec := int64(uint64(frac) * 1e9 / (1 << 32))

	return time.Unix(int64(sec), nsec)
}

// applyOffset applies the clock offset
func (c *NTPClient) applyOffset(offset time.Duration) error {
	// Note: Actually setting system time requires elevated privileges
	// For most use cases, we just store the offset and apply it virtually

	slog.Debug("would apply clock offset", "offset", offset)
	return nil
}

// GetOffset returns the current clock offset
func (c *NTPClient) GetOffset() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.offset
}

// GetLatency returns the last measured latency
func (c *NTPClient) GetLatency() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latency
}

// IsSynced returns whether the client has successfully synced
func (c *NTPClient) IsSynced() bool {
	return c.synced.Load()
}

// GetSyncedAt returns the time of last successful sync
func (c *NTPClient) GetSyncedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.syncedAt
}

// AdjustTime returns a time adjusted by the NTP offset
func (c *NTPClient) AdjustTime(t time.Time) time.Time {
	c.mu.RLock()
	offset := c.offset
	c.mu.RUnlock()
	return t.Add(offset)
}

// Now returns the current time adjusted by NTP offset
func (c *NTPClient) Now() time.Time {
	return c.AdjustTime(time.Now())
}

// Status returns the current NTP status
type Status struct {
	Synced   bool          `json:"synced"`
	Offset   time.Duration `json:"offset"`
	Latency  time.Duration `json:"latency"`
	SyncedAt time.Time     `json:"synced_at"`
	Servers  []string      `json:"servers"`
}

// GetStatus returns the current NTP status
func (c *NTPClient) GetStatus() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return Status{
		Synced:   c.synced.Load(),
		Offset:   c.offset,
		Latency:  c.latency,
		SyncedAt: c.syncedAt,
		Servers:  c.servers,
	}
}

// NTPStats provides NTP statistics
type NTPStats struct {
	SyncCount     int64         `json:"sync_count"`
	FailCount     int64         `json:"fail_count"`
	LastOffset    time.Duration `json:"last_offset"`
	AverageOffset time.Duration `json:"average_offset"`
	MaxOffset     time.Duration `json:"max_offset"`
	MinOffset     time.Duration `json:"min_offset"`
}

// Server represents an NTP server for configuration
type Server struct {
	Address  string `yaml:"address"`
	Port     int    `yaml:"port"`
	Priority int    `yaml:"priority"`
}
