package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lukuochiang/mihomo/config"
)

// HotReloadConfig holds hot reload configuration
type HotReloadConfig struct {
	Enabled       bool     `yaml:"enabled"`
	WatchPaths    []string `yaml:"watch-paths"`
	DebounceDelay int      `yaml:"debounce-delay"` // milliseconds
	WatchInterval int      `yaml:"watch-interval"` // seconds for polling fallback
}

// ReloadHandler handles configuration reload
type ReloadHandler struct {
	config        *config.Config
	watchPaths    []string
	debounceDelay time.Duration
	mu            sync.RWMutex
	watcher       *fsnotify.Watcher
	stopChan      chan struct{}
	eventChan     chan fsnotify.Event
	handlerFunc   func(*config.Config) error
	onReload      func(oldCfg, newCfg *config.Config)
	lastReload    time.Time

	// Rollback support
	rollbackConfig *config.Config
	rollbackMu     sync.RWMutex

	// Reload history
	history    []ReloadHistoryEntry
	historyMu  sync.RWMutex
	maxHistory int
}

// ReloadHistoryEntry represents a single reload event
type ReloadHistoryEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Duration  string    `json:"duration"`
	Error     string    `json:"error,omitempty"`
	Changes   []string  `json:"changes,omitempty"`
}

// NewReloadHandler creates a new hot reload handler
func NewReloadHandler(cfg *HotReloadConfig, handlerFunc func(*config.Config) error) (*ReloadHandler, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	delay := 500 * time.Millisecond
	if cfg.DebounceDelay > 0 {
		delay = time.Duration(cfg.DebounceDelay) * time.Millisecond
	}

	return &ReloadHandler{
		config:        nil,
		watchPaths:    cfg.WatchPaths,
		debounceDelay: delay,
		watcher:       watcher,
		stopChan:      make(chan struct{}),
		eventChan:     make(chan fsnotify.Event, 100),
		handlerFunc:   handlerFunc,
		lastReload:    time.Time{},
		maxHistory:    50, // Keep last 50 reload history entries
	}, nil
}

// SetOnReload sets the callback function to call after successful reload
func (h *ReloadHandler) SetOnReload(callback func(oldCfg, newCfg *config.Config)) {
	h.onReload = callback
}

// Start begins watching for file changes
func (h *ReloadHandler) Start(initialCfg *config.Config) error {
	h.mu.Lock()
	h.config = initialCfg
	h.mu.Unlock()

	// Add watch paths
	for _, path := range h.watchPaths {
		if err := h.addWatchPath(path); err != nil {
			slog.Warn("failed to add watch path", "path", path, "error", err)
		}
	}

	// Start event handler goroutine
	go h.eventLoop()

	slog.Info("hot reload started", "paths", h.watchPaths)
	return nil
}

// addWatchPath adds a path to the watcher
func (h *ReloadHandler) addWatchPath(path string) error {
	// Check if path exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Watch parent directory
			dir := getParentDir(path)
			return h.watcher.Add(dir)
		}
		return err
	}

	if info.IsDir() {
		return h.watcher.Add(path)
	}
	// Watch file's directory
	return h.watcher.Add(getParentDir(path))
}

// eventLoop handles file change events
func (h *ReloadHandler) eventLoop() {
	debounceTimer := time.NewTimer(0)
	<-debounceTimer.C // Drain the channel

	for {
		select {
		case event := <-h.watcher.Events:
			h.handleEvent(event)
			// Reset debounce timer
			debounceTimer.Reset(h.debounceDelay)

		case err := <-h.watcher.Errors:
			slog.Warn("watcher error", "error", err)

		case <-h.stopChan:
			debounceTimer.Stop()
			return
		}
	}
}

// handleEvent processes a file change event
func (h *ReloadHandler) handleEvent(event fsnotify.Event) {
	// Filter events
	if !h.isRelevantEvent(event) {
		return
	}

	slog.Debug("config file changed", "event", event)

	// Check if this is a config file
	if !h.isConfigFile(event.Name) {
		return
	}

	// Check debounce
	h.mu.RLock()
	lastReload := h.lastReload
	h.mu.RUnlock()

	if time.Since(lastReload) < h.debounceDelay {
		slog.Debug("reload debounced")
		return
	}

	// Trigger reload
	h.reload()
}

// isRelevantEvent checks if the event should trigger reload
func (h *ReloadHandler) isRelevantEvent(event fsnotify.Event) bool {
	// Only handle write and rename events
	return event.Op&fsnotify.Write == fsnotify.Write ||
		event.Op&fsnotify.Create == fsnotify.Create
}

// isConfigFile checks if the file is a configuration file
func (h *ReloadHandler) isConfigFile(path string) bool {
	for _, watchPath := range h.watchPaths {
		if path == watchPath {
			return true
		}
	}
	return false
}

// reload performs the configuration reload with rollback support
func (h *ReloadHandler) reload() {
	startTime := time.Now()
	slog.Info("reloading configuration...")

	// Find the first existing config file
	var configPath string
	for _, path := range h.watchPaths {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	if configPath == "" {
		slog.Error("no config file found for reload")
		h.addHistoryEntry(false, time.Since(startTime), "no config file found", nil)
		return
	}

	// Load new config
	newCfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("failed to load new config", "error", err)
		h.addHistoryEntry(false, time.Since(startTime), fmt.Sprintf("load failed: %v", err), nil)
		return
	}

	// Store old config for potential rollback
	h.mu.RLock()
	oldCfg := h.config
	h.mu.RUnlock()

	// Store rollback config
	h.rollbackMu.Lock()
	h.rollbackConfig = oldCfg
	h.rollbackMu.Unlock()

	// Apply new config
	if err := h.handlerFunc(newCfg); err != nil {
		slog.Error("failed to apply new config, rolling back...", "error", err)

		// Rollback to previous config
		h.rollback()
		h.addHistoryEntry(false, time.Since(startTime), fmt.Sprintf("apply failed: %v", err), nil)
		return
	}

	// Update stored config
	h.mu.Lock()
	h.config = newCfg
	h.lastReload = time.Now()
	h.mu.Unlock()

	// Detect changes
	changes := h.detectChanges(oldCfg, newCfg)

	// Call callback
	if h.onReload != nil {
		go h.onReload(oldCfg, newCfg)
	}

	slog.Info("configuration reloaded successfully", "duration", time.Since(startTime))
	h.addHistoryEntry(true, time.Since(startTime), "", changes)
}

// rollback restores the previous configuration
func (h *ReloadHandler) rollback() {
	h.rollbackMu.Lock()
	defer h.rollbackMu.Unlock()

	if h.rollbackConfig == nil {
		slog.Warn("no config to rollback to")
		return
	}

	slog.Info("rolling back to previous configuration...")

	if err := h.handlerFunc(h.rollbackConfig); err != nil {
		slog.Error("failed to rollback configuration", "error", err)
		return
	}

	h.mu.Lock()
	h.config = h.rollbackConfig
	h.mu.Unlock()

	h.rollbackConfig = nil
	slog.Info("rollback completed successfully")
}

// Rollback manually triggers a rollback to the previous configuration
func (h *ReloadHandler) Rollback() error {
	h.rollbackMu.RLock()
	hasRollback := h.rollbackConfig != nil
	h.rollbackMu.RUnlock()

	if !hasRollback {
		return fmt.Errorf("no previous configuration to rollback to")
	}

	h.rollback()
	return nil
}

// detectChanges detects what changed between old and new config
func (h *ReloadHandler) detectChanges(oldCfg, newCfg *config.Config) []string {
	var changes []string

	if oldCfg == nil || newCfg == nil {
		return changes
	}

	// Compare proxy count
	if len(oldCfg.Outbounds) != len(newCfg.Outbounds) {
		changes = append(changes, fmt.Sprintf("proxy count: %d -> %d", len(oldCfg.Outbounds), len(newCfg.Outbounds)))
	}

	// Compare DNS settings
	if oldCfg.DNS.Enable != newCfg.DNS.Enable {
		changes = append(changes, fmt.Sprintf("dns: %v -> %v", oldCfg.DNS.Enable, newCfg.DNS.Enable))
	}

	// Compare port settings
	if oldCfg.MixedPort != newCfg.MixedPort {
		changes = append(changes, fmt.Sprintf("mixed-port: %d -> %d", oldCfg.MixedPort, newCfg.MixedPort))
	}
	if oldCfg.HTTPPort != newCfg.HTTPPort {
		changes = append(changes, fmt.Sprintf("http-port: %d -> %d", oldCfg.HTTPPort, newCfg.HTTPPort))
	}
	if oldCfg.SOCKSPort != newCfg.SOCKSPort {
		changes = append(changes, fmt.Sprintf("socks-port: %d -> %d", oldCfg.SOCKSPort, newCfg.SOCKSPort))
	}

	// Compare API settings
	if oldCfg.API.Enabled != newCfg.API.Enabled {
		changes = append(changes, fmt.Sprintf("api: %v -> %v", oldCfg.API.Enabled, newCfg.API.Enabled))
	}

	// Compare Dashboard settings
	if oldCfg.Dashboard.Enabled != newCfg.Dashboard.Enabled {
		changes = append(changes, fmt.Sprintf("dashboard: %v -> %v", oldCfg.Dashboard.Enabled, newCfg.Dashboard.Enabled))
	}

	// Compare TUN settings
	if oldCfg.TUN.Enable != newCfg.TUN.Enable {
		changes = append(changes, fmt.Sprintf("tun: %v -> %v", oldCfg.TUN.Enable, newCfg.TUN.Enable))
	}

	if len(changes) == 0 {
		changes = append(changes, "configuration updated")
	}

	return changes
}

// addHistoryEntry adds an entry to the reload history
func (h *ReloadHandler) addHistoryEntry(success bool, duration time.Duration, errMsg string, changes []string) {
	h.historyMu.Lock()
	defer h.historyMu.Unlock()

	entry := ReloadHistoryEntry{
		Timestamp: time.Now(),
		Success:   success,
		Duration:  duration.String(),
		Error:     errMsg,
		Changes:   changes,
	}

	h.history = append(h.history, entry)

	// Trim history if too long
	if len(h.history) > h.maxHistory {
		h.history = h.history[len(h.history)-h.maxHistory:]
	}
}

// GetHistory returns the reload history
func (h *ReloadHandler) GetHistory() []ReloadHistoryEntry {
	h.historyMu.RLock()
	defer h.historyMu.RUnlock()

	// Return a copy
	result := make([]ReloadHistoryEntry, len(h.history))
	copy(result, h.history)
	return result
}

// CanRollback returns whether a rollback is available
func (h *ReloadHandler) CanRollback() bool {
	h.rollbackMu.RLock()
	defer h.rollbackMu.RUnlock()
	return h.rollbackConfig != nil
}

// Stop stops the hot reload watcher
func (h *ReloadHandler) Stop() error {
	close(h.stopChan)
	if h.watcher != nil {
		return h.watcher.Close()
	}
	return nil
}

// TriggerReload manually triggers a configuration reload
func (h *ReloadHandler) TriggerReload(configPath string) error {
	if configPath == "" && len(h.watchPaths) > 0 {
		configPath = h.watchPaths[0]
	}

	if configPath == "" {
		return fmt.Errorf("no config path specified")
	}

	slog.Info("manual reload triggered", "path", configPath)

	newCfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	h.mu.RLock()
	oldCfg := h.config
	h.mu.RUnlock()

	if err := h.handlerFunc(newCfg); err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}

	h.mu.Lock()
	h.config = newCfg
	h.lastReload = time.Now()
	h.mu.Unlock()

	if h.onReload != nil {
		go h.onReload(oldCfg, newCfg)
	}

	return nil
}

// getParentDir returns the parent directory of a path
func getParentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}

// PollingWatcher provides polling-based file watching as fallback
type PollingWatcher struct {
	paths       []string
	intervals   time.Duration
	stopChan    chan struct{}
	handlerFunc func([]string) error
	checksums   map[string]string
	mu          sync.RWMutex
}

// NewPollingWatcher creates a new polling watcher
func NewPollingWatcher(paths []string, intervalSeconds int, handlerFunc func([]string) error) *PollingWatcher {
	interval := time.Duration(intervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	return &PollingWatcher{
		paths:       paths,
		intervals:   interval,
		stopChan:    make(chan struct{}),
		handlerFunc: handlerFunc,
		checksums:   make(map[string]string),
	}
}

// Start begins polling
func (w *PollingWatcher) Start(ctx context.Context) error {
	// Initialize checksums
	for _, path := range w.paths {
		if sum, err := fileChecksum(path); err == nil {
			w.checksums[path] = sum
		}
	}

	ticker := time.NewTicker(w.intervals)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.check()
		case <-w.stopChan:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// check checks all paths for changes
func (w *PollingWatcher) check() {
	var changedPaths []string

	w.mu.Lock()
	defer w.mu.Unlock()

	for _, path := range w.paths {
		sum, err := fileChecksum(path)
		if err != nil {
			continue
		}

		if oldSum, ok := w.checksums[path]; !ok || oldSum != sum {
			w.checksums[path] = sum
			changedPaths = append(changedPaths, path)
		}
	}

	if len(changedPaths) > 0 && w.handlerFunc != nil {
		if err := w.handlerFunc(changedPaths); err != nil {
			slog.Warn("handler failed", "error", err)
		}
	}
}

// Stop stops the polling watcher
func (w *PollingWatcher) Stop() {
	close(w.stopChan)
}

// fileChecksum computes a SHA256 checksum of a file
func fileChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	// Use SHA256 for reliable file change detection
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// APIReloadHandler handles reload requests via API
type APIReloadHandler struct {
	reloadHandler *ReloadHandler
	apiSecret     string
}

// NewAPIReloadHandler creates a new API reload handler
func NewAPIReloadHandler(h *ReloadHandler, secret string) *APIReloadHandler {
	return &APIReloadHandler{
		reloadHandler: h,
		apiSecret:     secret,
	}
}

// HandleReload handles an API reload request
func (h *APIReloadHandler) HandleReload(ctx context.Context, secret, configPath string) error {
	// Verify secret
	if h.apiSecret != "" && subtle.ConstantTimeCompare([]byte(secret), []byte(h.apiSecret)) != 1 {
		return fmt.Errorf("unauthorized")
	}

	return h.reloadHandler.TriggerReload(configPath)
}

// ReloadStatus represents the current reload status
type ReloadStatus struct {
	Enabled      bool      `json:"enabled"`
	LastReload   time.Time `json:"last_reload"`
	WatchPaths   []string  `json:"watch_paths"`
	IsWatching   bool      `json:"is_watching"`
	CanRollback  bool      `json:"can_rollback"`
	HistoryCount int       `json:"history_count"`
	LatestError  string    `json:"latest_error,omitempty"`
}

// GetStatus returns the current reload status
func (h *ReloadHandler) GetStatus() ReloadStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	h.rollbackMu.RLock()
	canRollback := h.rollbackConfig != nil
	h.rollbackMu.RUnlock()

	h.historyMu.RLock()
	historyCount := len(h.history)
	var latestError string
	if historyCount > 0 {
		latestError = h.history[historyCount-1].Error
	}
	h.historyMu.RUnlock()

	return ReloadStatus{
		Enabled:      true,
		LastReload:   h.lastReload,
		WatchPaths:   h.watchPaths,
		IsWatching:   h.watcher != nil,
		CanRollback:  canRollback,
		HistoryCount: historyCount,
		LatestError:  latestError,
	}
}
