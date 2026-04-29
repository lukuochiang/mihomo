package pool

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnPool configuration
type Config struct {
	// Maximum number of connections per host
	MaxConnsPerHost int `yaml:"max-conns-per-host"`
	// Maximum number of idle connections per host
	MaxIdleConnsPerHost int `yaml:"max-idle-conns-per-host"`
	// Maximum total idle connections
	MaxIdleConns int `yaml:"max-idle-conns"`
	// Idle connection timeout
	IdleConnTimeout time.Duration `yaml:"idle-conn-timeout"`
	// Connection lifetime
	ConnMaxLifetime time.Duration `yaml:"conn-max-lifetime"`
	// Connection health check interval
	HealthCheckInterval time.Duration `yaml:"health-check-interval"`
	// Dial timeout
	DialTimeout time.Duration `yaml:"dial-timeout"`
	// Keep alive interval
	KeepAlive time.Duration `yaml:"keep-alive"`
}

// DefaultConfig returns default pool configuration
func DefaultConfig() *Config {
	return &Config{
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 10,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		ConnMaxLifetime:     10 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		DialTimeout:         30 * time.Second,
		KeepAlive:           30 * time.Second,
	}
}

// ConnPool manages a pool of network connections
type ConnPool struct {
	config   *Config
	mu       sync.RWMutex
	pools    map[string]*hostPool // per-host connection pools
	stopped  atomic.Bool
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// hostPool manages connections for a single host
type hostPool struct {
	host    string
	idle    []*PooledConn
	active  int
	mu      sync.Mutex
	waiters []chan *PooledConn
	pool    *ConnPool
}

// PooledConn is a connection from the pool
type PooledConn struct {
	net.Conn
	pool      *ConnPool
	host      string
	createdAt time.Time
	usedAt    time.Time
	closed    atomic.Bool
}

// PoolStats holds pool statistics
type PoolStats struct {
	TotalConns  int64 `json:"total_conns"`
	IdleConns   int64 `json:"idle_conns"`
	ActiveConns int64 `json:"active_conns"`
	WaitCount   int64 `json:"wait_count"`
	HitCount    int64 `json:"hit_count"`
	MissCount   int64 `json:"miss_count"`
}

// DialFunc is a function that creates a new connection
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// globalStats tracks global pool statistics
var globalStats = &PoolStats{}

// NewConnPool creates a new connection pool
func NewConnPool(cfg *Config) *ConnPool {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	pool := &ConnPool{
		config:   cfg,
		pools:    make(map[string]*hostPool),
		stopChan: make(chan struct{}),
	}

	// Start background cleanup
	pool.wg.Add(1)
	go pool.cleanupLoop()

	// Start health check
	pool.wg.Add(1)
	go pool.healthCheckLoop()

	return pool
}

// Get gets a connection from the pool or creates a new one
func (p *ConnPool) Get(ctx context.Context, network, addr string, dialFn DialFunc) (*PooledConn, error) {
	if p.stopped.Load() {
		return nil, fmt.Errorf("pool is stopped")
	}

	hp := p.getHostPool(addr)

	// Try to get idle connection
	if conn := hp.getIdle(); conn != nil {
		atomic.AddInt64(&globalStats.HitCount, 1)
		conn.usedAt = time.Now()
		return conn, nil
	}

	atomic.AddInt64(&globalStats.MissCount, 1)

	// Check if we can create new connection
	if !hp.canCreate(p.config.MaxConnsPerHost) {
		// Wait for a connection to become available
		return hp.waitForConn(ctx, p)
	}

	// Create new connection
	conn, err := dialFn(ctx, network, addr)
	if err != nil {
		hp.releaseSlot()
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	// Set keep-alive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(p.config.KeepAlive)
	}

	atomic.AddInt64(&globalStats.TotalConns, 1)

	return &PooledConn{
		Conn:      conn,
		pool:      p,
		host:      addr,
		createdAt: time.Now(),
		usedAt:    time.Now(),
	}, nil
}

// Put returns a connection to the pool
func (p *ConnPool) Put(conn *PooledConn) {
	if conn.closed.Swap(true) {
		return // Already closed
	}

	// Check if connection is still usable
	if p.isConnExpired(conn) {
		conn.Conn.Close()
		atomic.AddInt64(&globalStats.TotalConns, -1)
		return
	}

	hp := p.getHostPool(conn.host)

	// Check if pool can accept idle connections
	if !hp.canIdle(p.config.MaxIdleConnsPerHost) {
		conn.Conn.Close()
		atomic.AddInt64(&globalStats.TotalConns, -1)
		return
	}

	// Check if there are any waiters
	if hp.sendToWaiter(conn) {
		conn.closed.Store(false)
		return
	}

	// Return to idle pool
	hp.putIdle(conn)
	atomic.AddInt64(&globalStats.IdleConns, 1)
}

// Close closes the pool and all connections
func (p *ConnPool) Close() error {
	if !p.stopped.CompareAndSwap(false, true) {
		return nil // Already stopped
	}

	close(p.stopChan)
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, hp := range p.pools {
		hp.closeAll()
	}
	p.pools = make(map[string]*hostPool)
	return nil
}

// getHostPool gets or creates a host pool
func (p *ConnPool) getHostPool(host string) *hostPool {
	p.mu.RLock()
	hp, ok := p.pools[host]
	p.mu.RUnlock()

	if ok {
		return hp
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if hp, ok = p.pools[host]; ok {
		return hp
	}

	hp = &hostPool{
		host: host,
		pool: p,
		idle: make([]*PooledConn, 0, p.config.MaxIdleConnsPerHost),
	}
	p.pools[host] = hp
	return hp
}

// isConnExpired checks if a connection has expired
func (p *ConnPool) isConnExpired(conn *PooledConn) bool {
	if p.config.ConnMaxLifetime > 0 && time.Since(conn.createdAt) > p.config.ConnMaxLifetime {
		return true
	}
	if p.config.IdleConnTimeout > 0 && time.Since(conn.usedAt) > p.config.IdleConnTimeout {
		return true
	}
	return false
}

// cleanupLoop cleans up expired idle connections
func (p *ConnPool) cleanupLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.stopChan:
			return
		}
	}
}

// cleanup removes expired idle connections
func (p *ConnPool) cleanup() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, hp := range p.pools {
		hp.cleanup(p)
	}
}

// healthCheckLoop performs periodic connection health checks
func (p *ConnPool) healthCheckLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.healthCheck()
		case <-p.stopChan:
			return
		}
	}
}

// healthCheck performs health check on idle connections
func (p *ConnPool) healthCheck() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, hp := range p.pools {
		hp.healthCheck(p)
	}
}

// GetStats returns pool statistics
func (p *ConnPool) GetStats() PoolStats {
	var idleConns, activeConns int64

	p.mu.RLock()
	for _, hp := range p.pools {
		hp.mu.Lock()
		idleConns += int64(len(hp.idle))
		activeConns += int64(hp.active)
		hp.mu.Unlock()
	}
	p.mu.RUnlock()

	return PoolStats{
		TotalConns:  atomic.LoadInt64(&globalStats.TotalConns),
		IdleConns:   idleConns,
		ActiveConns: activeConns,
		WaitCount:   atomic.LoadInt64(&globalStats.WaitCount),
		HitCount:    atomic.LoadInt64(&globalStats.HitCount),
		MissCount:   atomic.LoadInt64(&globalStats.MissCount),
	}
}

// getIdle gets an idle connection from the host pool
func (hp *hostPool) getIdle() *PooledConn {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	n := len(hp.idle)
	if n == 0 {
		return nil
	}

	// Get the most recently used connection (LIFO for better utilization)
	conn := hp.idle[n-1]
	hp.idle = hp.idle[:n-1]
	hp.active++
	atomic.AddInt64(&globalStats.IdleConns, -1)

	conn.closed.Store(false)
	return conn
}

// putIdle puts a connection into the idle pool
func (hp *hostPool) putIdle(conn *PooledConn) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	hp.active--
	hp.idle = append(hp.idle, conn)
	conn.usedAt = time.Now()
}

// canCreate checks if we can create a new connection
func (hp *hostPool) canCreate(maxConns int) bool {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	total := len(hp.idle) + hp.active
	if total >= maxConns {
		return false
	}
	hp.active++
	return true
}

// releaseSlot releases a connection slot
func (hp *hostPool) releaseSlot() {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.active--
}

// canIdle checks if we can add an idle connection
func (hp *hostPool) canIdle(maxIdle int) bool {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	return len(hp.idle) < maxIdle
}

// waitForConn waits for an available connection
func (hp *hostPool) waitForConn(ctx context.Context, pool *ConnPool) (*PooledConn, error) {
	ch := make(chan *PooledConn, 1)

	hp.mu.Lock()
	hp.waiters = append(hp.waiters, ch)
	hp.mu.Unlock()

	atomic.AddInt64(&globalStats.WaitCount, 1)

	select {
	case conn := <-ch:
		if conn == nil {
			return nil, fmt.Errorf("connection unavailable")
		}
		return conn, nil
	case <-ctx.Done():
		hp.mu.Lock()
		for i, waiter := range hp.waiters {
			if waiter == ch {
				hp.waiters = append(hp.waiters[:i], hp.waiters[i+1:]...)
				break
			}
		}
		hp.mu.Unlock()
		return nil, ctx.Err()
	}
}

// sendToWaiter sends a connection to a waiting caller
func (hp *hostPool) sendToWaiter(conn *PooledConn) bool {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if len(hp.waiters) == 0 {
		return false
	}

	waiter := hp.waiters[0]
	hp.waiters = hp.waiters[1:]
	waiter <- conn
	return true
}

// closeAll closes all idle connections
func (hp *hostPool) closeAll() {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	for _, conn := range hp.idle {
		conn.Conn.Close()
	}
	hp.idle = hp.idle[:0]
}

// cleanup removes expired idle connections
func (hp *hostPool) cleanup(pool *ConnPool) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	var remaining []*PooledConn
	for _, conn := range hp.idle {
		if pool.isConnExpired(conn) {
			conn.Conn.Close()
			atomic.AddInt64(&globalStats.TotalConns, -1)
			atomic.AddInt64(&globalStats.IdleConns, -1)
			slog.Debug("closed expired idle connection", "host", hp.host)
		} else {
			remaining = append(remaining, conn)
		}
	}
	hp.idle = remaining
}

// healthCheck validates idle connections
func (hp *hostPool) healthCheck(pool *ConnPool) {
	hp.mu.Lock()
	var toCheck []*PooledConn
	copy(hp.idle, toCheck) // Make a copy
	toCheck = make([]*PooledConn, len(hp.idle))
	copy(toCheck, hp.idle)
	hp.mu.Unlock()

	for _, conn := range toCheck {
		if !isConnAlive(conn.Conn) {
			slog.Debug("removing dead connection", "host", hp.host)
			hp.removeConn(conn)
		}
	}
}

// removeConn removes a specific connection from the pool
func (hp *hostPool) removeConn(target *PooledConn) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	for i, conn := range hp.idle {
		if conn == target {
			conn.Conn.Close()
			hp.idle = append(hp.idle[:i], hp.idle[i+1:]...)
			atomic.AddInt64(&globalStats.TotalConns, -1)
			atomic.AddInt64(&globalStats.IdleConns, -1)
			break
		}
	}
}

// isConnAlive checks if a connection is still alive
func isConnAlive(conn net.Conn) bool {
	// Try to set a very short read deadline and check for errors
	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
		return false
	}
	defer conn.SetReadDeadline(time.Time{}) // Reset deadline

	// Try to read 1 byte
	buf := make([]byte, 1)
	_, err := conn.Read(buf)

	if err != nil {
		// Check if it's just a timeout (expected) or a real error
		netErr, ok := err.(net.Error)
		if ok && netErr.Timeout() {
			return true // Timeout means connection is alive but no data
		}
		return false
	}

	return true
}

// PooledConn implements net.Conn
// Close returns the connection to the pool instead of closing it
func (c *PooledConn) Close() error {
	if c.closed.Swap(true) {
		return nil // Already returned
	}

	// Check if connection is still usable
	if c.pool != nil && !c.pool.isConnExpired(c) {
		c.pool.Put(c)
		return nil
	}

	// Actually close the connection
	atomic.AddInt64(&globalStats.TotalConns, -1)
	return c.Conn.Close()
}

// DefaultDialer creates a standard net dialer
func DefaultDialer(cfg *Config) DialFunc {
	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: cfg.KeepAlive,
	}
	return dialer.DialContext
}

// ============ Buffer Pool ============

// BufferPool is a pool of byte buffers
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool
func NewBufferPool(size int) *BufferPool {
	if size <= 0 {
		size = 32 * 1024 // Default 32KB
	}
	return &BufferPool{
		size: size,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)[:p.size]
}

// Put returns a buffer to the pool
func (p *BufferPool) Put(buf []byte) {
	if cap(buf) >= p.size {
		p.pool.Put(buf[:p.size])
	}
}

// CopyPool is a specialized pool for io.Copy operations
type CopyPool struct {
	pool sync.Pool
}

type copyBuffers struct {
	buf  []byte
	buf2 []byte
}

// NewCopyPool creates a pool optimized for io.Copy
func NewCopyPool() *CopyPool {
	return &CopyPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &copyBuffers{
					buf:  make([]byte, 32*1024),
					buf2: make([]byte, 32*1024),
				}
			},
		},
	}
}

// Get retrieves copy buffers
func (p *CopyPool) Get() (dst, src []byte) {
	cb := p.pool.Get().(*copyBuffers)
	return cb.buf, cb.buf2
}

// Put returns copy buffers to the pool
func (p *CopyPool) Put(dst, src []byte) {
	cb := &copyBuffers{
		buf:  dst,
		buf2: src,
	}
	p.pool.Put(cb)
}

// Copy pools data between readers and writers using pooled buffers
func (p *CopyPool) Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	buf1, buf2 := p.Get()
	defer p.Put(buf1, buf2)

	for {
		nr, er := src.Read(buf1)
		if nr > 0 {
			nw, ew := dst.Write(buf1[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
		_ = buf2 // Keep buf2 for next iteration
	}
	return written, err
}

// Default copy pool instance
var defaultCopyPool = NewCopyPool()

// PooledCopy uses the default pool for copying
func PooledCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	return defaultCopyPool.Copy(dst, src)
}

// Global buffer pools for common sizes
var (
	// DefaultBufferPool is the default 32KB buffer pool
	DefaultBufferPool = NewBufferPool(32 * 1024)

	// SmallBufferPool is for 4KB buffers
	SmallBufferPool = NewBufferPool(4 * 1024)

	// LargeBufferPool is for 64KB buffers
	LargeBufferPool = NewBufferPool(64 * 1024)
)

// GetBuffer gets a buffer from the default pool
func GetBuffer() []byte {
	return DefaultBufferPool.Get()
}

// PutBuffer returns a buffer to the default pool
func PutBuffer(buf []byte) {
	DefaultBufferPool.Put(buf)
}
