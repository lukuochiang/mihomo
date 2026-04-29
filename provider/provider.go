package provider

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Provider represents a node provider
type Provider struct {
	Name        string
	Type        ProviderType // http, file, compatible
	URL         string
	Path        string
	Interval    time.Duration
	Filter      string
	LastUpdate  time.Time
	Nodes       []*ProviderNode
	HealthCheck *HealthCheckConfig
	mu          sync.RWMutex
	httpClient  *http.Client
}

// ProviderType defines provider type
type ProviderType string

const (
	ProviderTypeHTTP       ProviderType = "http"
	ProviderTypeFile       ProviderType = "file"
	ProviderTypeCompatible ProviderType = "compatible"
)

// Protocol link prefixes - using constants for better maintainability
const (
	prefixVMess     = "vmess://"
	prefixVLESS     = "vless://"
	prefixTrojan    = "trojan://"
	prefixSS        = "ss://"
	prefixSnell     = "snell://"
	prefixTUIC      = "tuic://"
	prefixHysteria  = "hysteria://"
	prefixHysteria2 = "hysteria2://"
)

// ProviderNode represents a node from provider
type ProviderNode struct {
	Tag       string
	Type      string
	Server    string
	Port      int
	UUID      string
	Password  string
	Cipher    string
	Network   string
	TLS       TLSConfig
	WSPath    string
	WSHeaders map[string]string
	Extra     map[string]interface{}
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled    bool
	ServerName string
	Insecure   bool
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Enable   bool
	URL      string
	Interval time.Duration
	Lazy     bool
	Suspend  bool
}

// Manager manages providers
type Manager struct {
	providers map[string]*Provider
	updater   *ProviderUpdater
	mu        sync.RWMutex
}

// ProviderUpdater updates providers periodically
type ProviderUpdater struct {
	manager  *Manager
	interval time.Duration
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewManager creates a new provider manager
func NewManager() *Manager {
	return &Manager{
		providers: make(map[string]*Provider),
	}
}

// AddProvider adds a provider
func (m *Manager) AddProvider(p *Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[p.Name]; exists {
		return fmt.Errorf("provider %s already exists", p.Name)
	}

	// Initialize HTTP client
	p.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Set default health check
	if p.HealthCheck == nil {
		p.HealthCheck = &HealthCheckConfig{
			Enable:   true,
			URL:      "https://www.gstatic.com/generate_204",
			Interval: 5 * time.Minute,
			Lazy:     true,
		}
	}

	m.providers[p.Name] = p
	return nil
}

// RemoveProvider removes a provider
func (m *Manager) RemoveProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; !exists {
		return fmt.Errorf("provider %s not found", name)
	}

	delete(m.providers, name)
	return nil
}

// GetProvider returns a provider
func (m *Manager) GetProvider(name string) (*Provider, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.providers[name]
	return p, ok
}

// GetAllNodes returns all nodes from all providers
func (m *Manager) GetAllNodes() []*ProviderNode {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var allNodes []*ProviderNode
	for _, p := range m.providers {
		nodes := p.GetNodes()
		allNodes = append(allNodes, nodes...)
	}

	return allNodes
}

// GetNodes returns nodes from provider
func (p *Provider) GetNodes() []*ProviderNode {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Nodes
}

// Update updates provider nodes
func (p *Provider) Update() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch p.Type {
	case ProviderTypeHTTP:
		return p.updateFromHTTP()
	case ProviderTypeFile:
		return p.updateFromFile()
	case ProviderTypeCompatible:
		return p.updateFromHTTP()
	default:
		return fmt.Errorf("unknown provider type: %s", p.Type)
	}
}

func (p *Provider) updateFromHTTP() error {
	if p.URL == "" {
		return fmt.Errorf("URL is required for HTTP provider")
	}

	req, err := http.NewRequest("GET", p.URL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "clash")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Check if data is base64 encoded (some providers)
	if IsLikelyBase64(string(data)) && len(data) > 100 {
		decoded, err := Decode(string(data))
		if err == nil {
			data = decoded
		}
	}

	return p.parseNodes(data)
}

func (p *Provider) updateFromFile() error {
	if p.Path == "" {
		return fmt.Errorf("path is required for file provider")
	}

	data, err := os.ReadFile(p.Path)
	if err != nil {
		return err
	}

	return p.parseNodes(data)
}

func (p *Provider) parseNodes(data []byte) error {
	content := string(data)

	// Try to parse as JSON first ( Surge, Clash Meta format )
	if err := p.parseJSON(content); err == nil {
		return nil
	}

	// Try to parse as subscription link list
	if strings.Contains(content, "vmess://") || strings.Contains(content, "vless://") {
		return p.parseLinks(content)
	}

	// Try to parse as base64 encoded content
	decoded, err := Decode(content)
	if err != nil {
		return fmt.Errorf("failed to parse provider content")
	}

	if err := p.parseJSON(string(decoded)); err != nil {
		return p.parseLinks(string(decoded))
	}

	return nil
}

func (p *Provider) parseJSON(content string) error {
	// Try to parse as Clash Meta config
	var config struct {
		Proxies []struct {
			Name      string                 `json:"name"`
			Type      string                 `json:"type"`
			Server    string                 `json:"server"`
			Port      int                    `json:"port"`
			UUID      string                 `json:"uuid"`
			Password  string                 `json:"password"`
			Cipher    string                 `json:"cipher"`
			Network   string                 `json:"network"`
			TLS       string                 `json:"tls"`
			WSPath    string                 `json:"ws-path"`
			WSHeaders map[string]string      `json:"ws-headers"`
			Extra     map[string]interface{} `json:"-"`
		} `json:"proxies"`
	}

	if err := json.Unmarshal([]byte(content), &config); err != nil {
		return err
	}

	for _, proxy := range config.Proxies {
		node := &ProviderNode{
			Tag:       proxy.Name,
			Type:      proxy.Type,
			Server:    proxy.Server,
			Port:      proxy.Port,
			UUID:      proxy.UUID,
			Password:  proxy.Password,
			Cipher:    proxy.Cipher,
			Network:   proxy.Network,
			TLS:       TLSConfig{Enabled: proxy.TLS != ""},
			WSPath:    proxy.WSPath,
			WSHeaders: proxy.WSHeaders,
		}
		if proxy.TLS != "" {
			node.TLS.Enabled = true
		}
		p.Nodes = append(p.Nodes, node)
	}

	return nil
}

func (p *Provider) parseLinks(content string) error {
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		node, err := ParseNodeLink(line)
		if err != nil {
			continue
		}

		// Apply filter
		if p.Filter != "" && !matchFilter(node.Tag, p.Filter) {
			continue
		}

		p.Nodes = append(p.Nodes, node)
	}

	return nil
}

// ParseNodeLink parses a node from subscription link
func ParseNodeLink(link string) (*ProviderNode, error) {
	link = strings.TrimSpace(link)

	if strings.HasPrefix(link, "vmess://") {
		return parseVMessLink(link)
	}
	if strings.HasPrefix(link, "vless://") {
		return parseVLESSLink(link)
	}
	if strings.HasPrefix(link, "trojan://") {
		return parseTrojanLink(link)
	}
	if strings.HasPrefix(link, "ss://") {
		return parseSSLink(link)
	}
	if strings.HasPrefix(link, "snell://") {
		return parseSnellLink(link)
	}
	if strings.HasPrefix(link, "tuic://") {
		return parseTUICLink(link)
	}
	if strings.HasPrefix(link, "hysteria://") {
		return parseHysteriaLink(link)
	}

	return nil, fmt.Errorf("unsupported link format")
}

func parseVMessLink(link string) (*ProviderNode, error) {
	if !strings.HasPrefix(link, prefixVMess) {
		return nil, fmt.Errorf("not a VMess link")
	}

	data, err := Decode(link[len(prefixVMess):])
	if err != nil {
		return nil, err
	}

	var vmess struct {
		Ps   string `json:"ps"`
		Add  string `json:"add"`
		Port int    `json:"port"`
		ID   string `json:"id"`
		Aid  int    `json:"aid"`
		Scy  string `json:"scy"`
		Net  string `json:"net"`
		TLS  string `json:"tls"`
		Host string `json:"host"`
		Path string `json:"path"`
		Type string `json:"type"`
	}

	if err := json.Unmarshal(data, &vmess); err != nil {
		return nil, err
	}

	return &ProviderNode{
		Tag:     vmess.Ps,
		Type:    "vmess",
		Server:  vmess.Add,
		Port:    vmess.Port,
		UUID:    vmess.ID,
		Cipher:  vmess.Scy,
		Network: vmess.Net,
		TLS:     TLSConfig{Enabled: vmess.TLS != ""},
		WSPath:  vmess.Path,
	}, nil
}

func parseVLESSLink(link string) (*ProviderNode, error) {
	if !strings.HasPrefix(link, prefixVLESS) {
		return nil, fmt.Errorf("not a VLESS link")
	}

	rest := link[len(prefixVLESS):]
	atIdx := strings.Index(rest, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid VLESS link")
	}

	uuid := rest[:atIdx]
	serverInfo := rest[atIdx+1:]

	// Parse server and params
	queryIdx := strings.Index(serverInfo, "?")
	hashIdx := strings.Index(serverInfo, "#")

	var server, name, params string
	var portInt int

	// Extract name from hash first
	if hashIdx != -1 {
		name = serverInfo[hashIdx+1:]
		name, _ = url.QueryUnescape(name)
	}

	if queryIdx != -1 {
		server = serverInfo[:queryIdx]
		params = serverInfo[queryIdx+1:]
		// Truncate params if there's a hash after the query
		if hashIdx != -1 && hashIdx > queryIdx {
			params = params[:hashIdx-queryIdx-1]
		}
	} else {
		if hashIdx != -1 {
			server = serverInfo[:hashIdx]
		} else {
			server = serverInfo
		}
	}

	colonIdx := strings.LastIndex(server, ":")
	if colonIdx == -1 {
		return nil, fmt.Errorf("invalid server address")
	}

	host := server[:colonIdx]
	fmt.Sscanf(server[colonIdx+1:], "%d", &portInt)

	// Parse params
	paramMap := make(map[string]string)
	for _, pair := range strings.Split(params, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			paramMap[kv[0]], _ = url.QueryUnescape(kv[1])
		}
	}

	return &ProviderNode{
		Tag:     name,
		Type:    "vless",
		Server:  host,
		Port:    portInt,
		UUID:    uuid,
		Network: paramMap["type"],
		TLS:     TLSConfig{Enabled: paramMap["security"] == "tls" || paramMap["security"] == "reality"},
		WSPath:  paramMap["path"],
	}, nil
}

func parseTrojanLink(link string) (*ProviderNode, error) {
	if !strings.HasPrefix(link, prefixTrojan) {
		return nil, fmt.Errorf("not a Trojan link")
	}

	rest := link[len(prefixTrojan):]
	atIdx := strings.Index(rest, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid Trojan link")
	}

	password := rest[:atIdx]
	serverInfo := rest[atIdx+1:]

	hashIdx := strings.Index(serverInfo, "#")
	queryIdx := strings.Index(serverInfo, "?")

	var server, name string
	var portInt int
	var paramMap = make(map[string]string)

	if queryIdx != -1 {
		server = serverInfo[:queryIdx]
		if hashIdx != -1 {
			params := serverInfo[queryIdx+1 : hashIdx]
			for _, pair := range strings.Split(params, "&") {
				kv := strings.SplitN(pair, "=", 2)
				if len(kv) == 2 {
					paramMap[kv[0]], _ = url.QueryUnescape(kv[1])
				}
			}
		}
	} else {
		if hashIdx != -1 {
			server = serverInfo[:hashIdx]
			name, _ = url.QueryUnescape(serverInfo[hashIdx+1:])
		} else {
			server = serverInfo
		}
	}

	colonIdx := strings.LastIndex(server, ":")
	if colonIdx == -1 {
		return nil, fmt.Errorf("invalid server address")
	}

	host := server[:colonIdx]
	fmt.Sscanf(server[colonIdx+1:], "%d", &portInt)

	return &ProviderNode{
		Tag:      name,
		Type:     "trojan",
		Server:   host,
		Port:     portInt,
		Password: password,
		TLS:      TLSConfig{Enabled: true},
	}, nil
}

func parseSSLink(link string) (*ProviderNode, error) {
	if !strings.HasPrefix(link, prefixSS) {
		return nil, fmt.Errorf("not a SS link")
	}

	rest := link[len(prefixSS):]
	atIdx := strings.Index(rest, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid SS link")
	}

	userInfo := rest[:atIdx]
	serverInfo := rest[atIdx+1:]

	// Decode userInfo
	decoded, err := Decode(userInfo)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid SS user info")
	}

	cipher := parts[0]
	password := parts[1]

	// Parse server
	hashIdx := strings.Index(serverInfo, "#")
	var server, name string
	if hashIdx != -1 {
		server = serverInfo[:hashIdx]
		name, _ = url.QueryUnescape(serverInfo[hashIdx+1:])
	} else {
		server = serverInfo
	}

	hostPort := strings.Split(server, ":")
	if len(hostPort) != 2 {
		return nil, fmt.Errorf("invalid SS server")
	}

	var portNum int
	fmt.Sscanf(hostPort[1], "%d", &portNum)

	return &ProviderNode{
		Tag:      name,
		Type:     "ss",
		Server:   hostPort[0],
		Port:     portNum,
		Cipher:   cipher,
		Password: password,
	}, nil
}

func parseSnellLink(link string) (*ProviderNode, error) {
	// Snell protocol
	if !strings.HasPrefix(link, prefixSnell) {
		return nil, fmt.Errorf("not a Snell link")
	}

	rest := link[len(prefixSnell):]
	hashIdx := strings.Index(rest, "#")

	var server, password, name string
	var portInt int
	if hashIdx != -1 {
		server = rest[:hashIdx]
		name, _ = url.QueryUnescape(rest[hashIdx+1:])
	} else {
		server = rest
	}

	atIdx := strings.Index(server, "@")
	if atIdx != -1 {
		password = server[:atIdx]
		server = server[atIdx+1:]
	}

	colonIdx := strings.LastIndex(server, ":")
	if colonIdx != -1 {
		host := server[:colonIdx]
		fmt.Sscanf(server[colonIdx+1:], "%d", &portInt)
		server = host
	}

	return &ProviderNode{
		Tag:      name,
		Type:     "snell",
		Server:   server,
		Port:     portInt,
		Password: password,
	}, nil
}

func parseTUICLink(link string) (*ProviderNode, error) {
	if !strings.HasPrefix(link, prefixTUIC) {
		return nil, fmt.Errorf("not a TUIC link")
	}

	// TUIC protocol: tuic://[uuid:password@]host:port[?params]#name
	rest := link[len(prefixTUIC):]

	// Extract name from fragment
	name := ""
	hashIdx := strings.Index(rest, "#")
	if hashIdx != -1 {
		name = rest[hashIdx+1:]
		rest = rest[:hashIdx]
	}

	// Extract UUID:password
	var uuid, password string
	atIdx := strings.Index(rest, "@")
	if atIdx != -1 {
		authPart := rest[:atIdx]
		colonIdx := strings.Index(authPart, ":")
		if colonIdx != -1 {
			// UUID:password format
			uuid = authPart[:colonIdx]
			password = authPart[colonIdx+1:]
		} else {
			// UUID only format (no password)
			uuid = authPart
		}
		rest = rest[atIdx+1:]
	}

	// Extract host:port
	var host string
	var port int
	colonIdx := strings.LastIndex(rest, ":")
	if colonIdx != -1 {
		host = rest[:colonIdx]
		fmt.Sscanf(rest[colonIdx+1:], "%d", &port)
	} else {
		host = rest
		port = 443
	}

	// Parse query parameters
	sni := host
	queryIdx := strings.Index(rest, "?")
	if queryIdx != -1 {
		// Extract query part
		queryEnd := len(rest)
		query := rest[queryIdx+1 : queryEnd]
		for _, param := range strings.Split(query, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 && kv[0] == "sni" {
				sni = kv[1]
			}
		}
	}

	return &ProviderNode{
		Tag:      name,
		Type:     "tuic",
		Server:   host,
		Port:     port,
		UUID:     uuid,
		Password: password,
		TLS: TLSConfig{
			ServerName: sni,
		},
	}, nil
}

func parseHysteriaLink(link string) (*ProviderNode, error) {
	// Support both hysteria:// and hysteria2:// formats
	var rest string
	var isHysteria2 bool
	if strings.HasPrefix(link, prefixHysteria2) {
		rest = link[len(prefixHysteria2):]
		isHysteria2 = true
	} else if strings.HasPrefix(link, prefixHysteria) {
		rest = link[len(prefixHysteria):]
	} else {
		return nil, fmt.Errorf("not a Hysteria link")
	}

	// Extract name from fragment
	name := ""
	hashIdx := strings.Index(rest, "#")
	if hashIdx != -1 {
		name = rest[hashIdx+1:]
		rest = rest[:hashIdx]
	}

	// Extract auth password
	var auth, obfs string
	atIdx := strings.Index(rest, "@")
	if atIdx != -1 {
		auth = rest[:atIdx]
		rest = rest[atIdx+1:]
	}

	// Extract host:port
	var host string
	var port int
	colonIdx := strings.LastIndex(rest, ":")
	if colonIdx != -1 {
		host = rest[:colonIdx]
		fmt.Sscanf(rest[colonIdx+1:], "%d", &port)
	} else {
		host = rest
		port = 443
	}

	// Parse query parameters
	sni := host
	queryIdx := strings.Index(rest, "?")
	if queryIdx != -1 {
		query := rest[queryIdx+1:]
		for _, param := range strings.Split(query, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				switch kv[0] {
				case "sni":
					sni = kv[1]
				case "obfs":
					obfs = kv[1]
				}
			}
		}
	}

	nodeType := "hysteria"
	if isHysteria2 {
		nodeType = "hysteria2"
	}

	return &ProviderNode{
		Tag:      name,
		Type:     nodeType,
		Server:   host,
		Port:     port,
		Password: auth,
		TLS: TLSConfig{
			ServerName: sni,
			Enabled:    true,
		},
		Extra: map[string]interface{}{
			"obfs": obfs,
		},
	}, nil
}

func matchFilter(name, filter string) bool {
	if filter == "" {
		return true
	}

	// Support regex filter
	if strings.HasPrefix(filter, "re:") {
		pattern := filter[3:]
		match, _ := regexp.MatchString(pattern, name)
		return match
	}

	// Support keyword filter
	return strings.Contains(strings.ToLower(name), strings.ToLower(filter))
}

// StartUpdater starts provider update loop
func (m *Manager) StartUpdater(interval time.Duration) {
	m.mu.Lock()
	if m.updater != nil {
		m.mu.Unlock()
		return
	}

	m.updater = &ProviderUpdater{
		manager:  m,
		interval: interval,
		stopChan: make(chan struct{}),
	}
	m.mu.Unlock()

	m.updater.wg.Add(1)
	go m.updater.run()
}

// StopUpdater stops provider update loop
func (m *Manager) StopUpdater() {
	m.mu.Lock()
	if m.updater == nil {
		m.mu.Unlock()
		return
	}
	updater := m.updater
	m.updater = nil
	close(updater.stopChan)
	m.mu.Unlock()

	updater.wg.Wait()
}

func (u *ProviderUpdater) run() {
	defer u.wg.Done()

	// Initial update
	u.updateAll()

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

func (u *ProviderUpdater) updateAll() {
	u.manager.mu.RLock()
	providers := make([]*Provider, 0, len(u.manager.providers))
	for _, p := range u.manager.providers {
		providers = append(providers, p)
	}
	u.manager.mu.RUnlock()

	for _, p := range providers {
		if err := p.Update(); err != nil {
			// Log error but continue
		}
	}
}

// GetProviders returns all providers
func (m *Manager) GetProviders() []*Provider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Provider, 0, len(m.providers))
	for _, p := range m.providers {
		result = append(result, p)
	}
	return result
}

// FilterNodes filters nodes by criteria
func FilterNodes(nodes []*ProviderNode, criteria NodeCriteria) []*ProviderNode {
	var result []*ProviderNode

	for _, n := range nodes {
		if criteria.Type != "" && n.Type != criteria.Type {
			continue
		}
		if criteria.TagContains != "" && !strings.Contains(n.Tag, criteria.TagContains) {
			continue
		}
		result = append(result, n)
	}

	return result
}

// NodeCriteria defines node filtering criteria
type NodeCriteria struct {
	Type         string
	TagContains  string
	ServerPrefix string
}
