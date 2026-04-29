package rules

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mihomo/smart/geoip"
)

// RuleProviderConfig holds rule provider configuration
type RuleProviderConfig struct {
	Name      string           `yaml:"name"`
	Type      string           `yaml:"type"`     // http, file, compatible
	Behavior  string           `yaml:"behavior"` // domain, ipcidr, classical
	URL       string           `yaml:"url"`
	Path      string           `yaml:"path"`
	Interval  time.Duration    `yaml:"interval"` // Update interval
	Filter    string           `yaml:"filter"`   // Domain filter
	TLSConfig *TLSClientConfig `yaml:"tls"`
	Format    string           `yaml:"format"` // text, yaml, json, source
}

// TLSClientConfig holds TLS client configuration for remote rule providers
type TLSClientConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Insecure   bool   `yaml:"insecure"` // Skip TLS verification
	CertFile   string `yaml:"cert"`
	KeyFile    string `yaml:"key"`
	CAFile     string `yaml:"ca"`
	ServerName string `yaml:"server-name"`
}

// RuleProvider represents a remote rule provider
type RuleProvider struct {
	config    *RuleProviderConfig
	engine    *RuleEngine
	geoip     *geoip.GeoIP
	rules     []Rule
	updatedAt time.Time
	mu        sync.RWMutex
	client    *http.Client
}

// RuleProviderManager manages all rule providers
type RuleProviderManager struct {
	providers map[string]*RuleProvider
	updater   *providerUpdater
	mu        sync.RWMutex
}

type providerUpdater struct {
	manager  *RuleProviderManager
	interval time.Duration
	stopChan chan struct{}
}

// NewRuleProviderManager creates a new rule provider manager
func NewRuleProviderManager() *RuleProviderManager {
	return &RuleProviderManager{
		providers: make(map[string]*RuleProvider),
	}
}

// Register registers a rule provider
func (m *RuleProviderManager) Register(cfg *RuleProviderConfig, engine *RuleEngine, geoipInstance *geoip.GeoIP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[cfg.Name]; exists {
		return fmt.Errorf("rule provider %s already exists", cfg.Name)
	}

	provider := &RuleProvider{
		config:    cfg,
		engine:    engine,
		geoip:     geoipInstance,
		rules:     make([]Rule, 0),
		updatedAt: time.Time{},
		client:    m.createHTTPClient(cfg.TLSConfig),
	}

	m.providers[cfg.Name] = provider
	return nil
}

// Unregister unregisters a rule provider
func (m *RuleProviderManager) Unregister(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; !exists {
		return fmt.Errorf("rule provider %s not found", name)
	}

	delete(m.providers, name)
	return nil
}

// Load loads rules from provider
func (p *RuleProvider) Load() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch p.config.Type {
	case "http":
		return p.loadFromHTTP()
	case "file":
		return p.loadFromFile()
	case "compatible":
		return p.loadCompatible()
	default:
		return fmt.Errorf("unsupported provider type: %s", p.config.Type)
	}
}

func (p *RuleProvider) loadFromHTTP() error {
	if p.config.URL == "" {
		return fmt.Errorf("URL is required for HTTP rule provider")
	}

	req, err := http.NewRequest("GET", p.config.URL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "mihomo")
	req.Header.Set("Accept", "*/*")

	// Support conditional GET
	if !p.updatedAt.IsZero() {
		req.Header.Set("If-Modified-Since", p.updatedAt.Format(http.TimeFormat))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	p.updatedAt = time.Now()
	return p.parseRules(data)
}

func (p *RuleProvider) loadFromFile() error {
	if p.config.Path == "" {
		return fmt.Errorf("path is required for file rule provider")
	}

	data, err := os.ReadFile(p.config.Path)
	if err != nil {
		return err
	}

	p.updatedAt = time.Now()
	return p.parseRules(data)
}

func (p *RuleProvider) loadCompatible() error {
	// Try HTTP first, fall back to file
	if p.config.URL != "" {
		if err := p.loadFromHTTP(); err == nil {
			return nil
		}
	}

	if p.config.Path != "" {
		return p.loadFromFile()
	}

	return fmt.Errorf("no valid source for compatible provider")
}

func (p *RuleProvider) parseRules(data []byte) error {
	p.rules = make([]Rule, 0)

	format := p.config.Format
	if format == "" {
		format = p.detectFormat(data)
	}

	switch format {
	case "text", "source", "clash":
		return p.parseTextRules(data)
	case "yaml":
		return p.parseYAMLRules(data)
	case "json":
		return p.parseJSONRules(data)
	default:
		// Auto-detect
		if err := p.parseTextRules(data); err != nil {
			return p.parseYAMLRules(data)
		}
		return nil
	}
}

func (p *RuleProvider) detectFormat(data []byte) string {
	content := strings.TrimSpace(string(data))

	// JSON format
	if strings.HasPrefix(content, "[") || strings.HasPrefix(content, "{") {
		return "json"
	}

	// YAML format (has colons)
	if strings.Contains(content, ":") && !strings.Contains(content, ",") {
		return "yaml"
	}

	// Default to text/clash format
	return "text"
}

func (p *RuleProvider) parseTextRules(data []byte) error {
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule, err := parseRuleLine(line)
		if err != nil {
			continue
		}

		// Apply filter if specified
		if p.config.Filter != "" && !p.matchFilter(rule) {
			continue
		}

		// Convert behavior
		if p.config.Behavior == "domain" && rule.Type == RuleTypeDomain {
			// Domain behavior: convert to suffix match
			rule.Type = RuleTypeDomainSuffix
		}

		p.rules = append(p.rules, rule)
	}

	return nil
}

func (p *RuleProvider) parseYAMLRules(data []byte) error {
	// Simple YAML parsing for rules
	// In production, use yaml library

	type yamlRule struct {
		Type     string `yaml:"type"`
		Value    string `yaml:"value"`
		Outbound string `yaml:"outbound"`
	}

	type yamlConfig struct {
		Rules []yamlRule `yaml:"rules"`
	}

	var cfg yamlConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		// Try as plain text if JSON fails
		return p.parseTextRules(data)
	}

	for _, yr := range cfg.Rules {
		rule := Rule{
			Type:     RuleType(strings.ToUpper(yr.Type)),
			Value:    yr.Value,
			Outbound: yr.Outbound,
		}
		p.rules = append(p.rules, rule)
	}

	return nil
}

func (p *RuleProvider) parseJSONRules(data []byte) error {
	type jsonRule struct {
		Type     string `json:"type"`
		Payload  string `json:"payload"`
		Outbound string `json:"outbound"`
	}

	var rules []jsonRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	for _, jr := range rules {
		rule := Rule{
			Type:     RuleType(strings.ToUpper(jr.Type)),
			Value:    jr.Payload,
			Outbound: jr.Outbound,
		}
		p.rules = append(p.rules, rule)
	}

	return nil
}

func (p *RuleProvider) matchFilter(rule Rule) bool {
	if p.config.Filter == "" {
		return true
	}

	filter := strings.ToLower(p.config.Filter)

	switch rule.Type {
	case RuleTypeDomain, RuleTypeDomainSuffix, RuleTypeDomainKeyword, RuleTypeDomainRegex:
		domain := strings.ToLower(rule.Value)
		return strings.Contains(domain, filter)
	case RuleTypeGeoIP:
		return strings.EqualFold(rule.Value, filter)
	default:
		return true
	}
}

// Apply applies the provider's rules to the engine
func (p *RuleProvider) Apply() error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, rule := range p.rules {
		if err := p.engine.AddRule(rule); err != nil {
			// Log but continue
		}
	}

	return nil
}

// GetRules returns the provider's rules
func (p *RuleProvider) GetRules() []Rule {
	p.mu.RLock()
	defer p.mu.RUnlock()

	rules := make([]Rule, len(p.rules))
	copy(rules, p.rules)
	return rules
}

// GetUpdatedAt returns the last update time
func (p *RuleProvider) GetUpdatedAt() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.updatedAt
}

// StartUpdater starts the automatic update loop
func (m *RuleProviderManager) StartUpdater(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.updater != nil {
		return
	}

	m.updater = &providerUpdater{
		manager:  m,
		interval: interval,
		stopChan: make(chan struct{}),
	}

	go m.updater.run()
}

// StopUpdater stops the automatic update loop
func (m *RuleProviderManager) StopUpdater() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.updater == nil {
		return
	}

	close(m.updater.stopChan)
	m.updater = nil
}

func (u *providerUpdater) run() {
	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()

	for {
		select {
		case <-u.stopChan:
			return
		case <-ticker.C:
			u.updateAll()
		}
	}
}

func (u *providerUpdater) updateAll() {
	u.manager.mu.RLock()
	providers := make([]*RuleProvider, 0, len(u.manager.providers))
	for _, p := range u.manager.providers {
		providers = append(providers, p)
	}
	u.manager.mu.RUnlock()

	for _, p := range providers {
		if err := p.Load(); err != nil {
			// Log error but continue
			continue
		}
		if err := p.Apply(); err != nil {
			// Log error but continue
			continue
		}
	}
}

func (m *RuleProviderManager) createHTTPClient(cfg *TLSClientConfig) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 60 * time.Second,
	}

	if cfg != nil && cfg.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.Insecure,
			ServerName:         cfg.ServerName,
		}

		// Load certificates if provided
		if cfg.CAFile != "" {
			if cert, err := os.ReadFile(cfg.CAFile); err == nil {
				// In production, properly configure root CA pool
				_ = cert
			}
		}

		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// GetProviders returns all registered providers
func (m *RuleProviderManager) GetProviders() []*RuleProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*RuleProvider, 0, len(m.providers))
	for _, p := range m.providers {
		result = append(result, p)
	}
	return result
}

// UpdateProvider updates a single provider
func (m *RuleProviderManager) UpdateProvider(name string) error {
	m.mu.RLock()
	p, exists := m.providers[name]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("rule provider %s not found", name)
	}

	if err := p.Load(); err != nil {
		return err
	}

	return p.Apply()
}

// RuleSetFromProvider creates a RuleSet from a provider
func RuleSetFromProvider(provider *RuleProvider) *RuleSet {
	return &RuleSet{
		Name:  provider.config.Name,
		Type:  provider.config.Type,
		Rules: provider.GetRules(),
	}
}

// LoadRuleSetFromURL loads a rule set from URL
func LoadRuleSetFromURL(name string, url string, format string) (*RuleSet, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mihomo")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	rs := &RuleSet{
		Name:   name,
		Type:   "http",
		Format: format,
		Rules:  make([]Rule, 0),
	}

	// Parse rules based on format
	switch format {
	case "text", "source", "clash":
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rule, err := parseRuleLine(line)
			if err != nil {
				continue
			}
			rs.Rules = append(rs.Rules, rule)
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	return rs, nil
}

// SaveRuleSet saves a rule set to file
func SaveRuleSet(rs *RuleSet, path string) error {
	var sb strings.Builder

	for _, rule := range rs.Rules {
		sb.WriteString(string(rule.Type))
		sb.WriteString(",")
		sb.WriteString(rule.Value)
		sb.WriteString(",")
		sb.WriteString(rule.Outbound)
		sb.WriteString("\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// GetRuleSetCacheDir returns the cache directory for rule sets
func GetRuleSetCacheDir() string {
	cacheDir := filepath.Join(os.Getenv("HOME"), ".cache", "mihomo", "rules")
	os.MkdirAll(cacheDir, 0755)
	return cacheDir
}
