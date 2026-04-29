package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidationResult holds validation results
type ValidationResult struct {
	Valid    bool
	Warnings []string
	Errors   []string
}

// ValidateComplete performs comprehensive validation
func (c *Config) ValidateComplete() *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
	}

	// Validate general settings
	c.validateGeneral(result)

	// Validate API settings
	c.validateAPI(result)

	// Validate Dashboard settings
	c.validateDashboard(result)

	// Validate Proxy settings
	c.validateProxy(result)

	// Validate DNS settings
	c.validateDNS(result)

	// Validate Outbounds
	c.validateOutbounds(result)

	// Validate Groups
	c.validateGroups(result)

	// Validate Routing
	c.validateRouting(result)

	// Validate Providers
	c.validateProviders(result)

	// Validate Tunnels
	c.validateTunnels(result)

	// Update valid status
	result.Valid = len(result.Errors) == 0

	return result
}

func (r *ValidationResult) addError(format string, args ...interface{}) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
}

func (r *ValidationResult) addWarning(format string, args ...interface{}) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

func (c *Config) validateGeneral(r *ValidationResult) {
	if c.LogLevel != "" {
		validLevels := map[string]bool{
			"debug": true, "info": true, "warn": true,
			"warning": true, "error": true, "fatal": true,
			"panic": true,
		}
		if !validLevels[strings.ToLower(c.LogLevel)] {
			r.addWarning("Invalid log level: %s", c.LogLevel)
		}
	}

	if c.BindPort < 1 || c.BindPort > 65535 {
		r.addWarning("Bind port %d is out of valid range", c.BindPort)
	}
}

func (c *Config) validateAPI(r *ValidationResult) {
	if !c.API.Enabled {
		return
	}

	if c.API.Listen == "" {
		return
	}

	if !isValidListenAddr(c.API.Listen) {
		r.addError("Invalid API listen address: %s", c.API.Listen)
	}
}

func (c *Config) validateDashboard(r *ValidationResult) {
	if !c.Dashboard.Enabled {
		return
	}

	if c.Dashboard.Listen == "" {
		return
	}

	if !isValidListenAddr(c.Dashboard.Listen) {
		r.addError("Invalid dashboard listen address: %s", c.Dashboard.Listen)
	}
}

func (c *Config) validateProxy(r *ValidationResult) {
	// Check all proxy ports
	ports := []int{c.HTTPPort, c.SOCKSPort, c.MixedPort, c.RedirPort, c.TProxyPort}
	portNames := []string{"HTTP", "SOCKS", "Mixed", "Redir", "TProxy"}

	for i, port := range ports {
		if port > 0 && (port < 1 || port > 65535) {
			r.addError("%s port %d is out of valid range", portNames[i], port)
		}
	}

	// Check for port conflicts
	if c.HTTPPort > 0 && c.HTTPPort == c.SOCKSPort {
		r.addError("HTTP and SOCKS cannot use the same port")
	}
	if c.HTTPPort > 0 && c.HTTPPort == c.MixedPort {
		r.addError("HTTP and Mixed cannot use the same port")
	}
	if c.SOCKSPort > 0 && c.SOCKSPort == c.MixedPort {
		r.addError("SOCKS and Mixed cannot use the same port")
	}

	// Check authentication
	for _, auth := range c.Authentication {
		if auth.User == "" || auth.Password == "" {
			r.addWarning("Proxy auth entry has empty username or password")
		}
	}
}

func (c *Config) validateDNS(r *ValidationResult) {
	if !c.DNS.Enable {
		return
	}

	for _, server := range c.DNS.Nameserver {
		if strings.HasPrefix(server, "https://") ||
			strings.HasPrefix(server, "tls://") ||
			strings.HasPrefix(server, "dhcp://") {
			continue
		}

		if _, err := net.LookupHost(server); err != nil {
			r.addWarning("DNS server %s may be unreachable", server)
		}
	}

	if c.DNS.EnhancedMode != "" {
		validModes := map[string]bool{
			"off": true, "fake-ip": true, "redir-host": true,
		}
		if !validModes[c.DNS.EnhancedMode] {
			r.addError("Invalid DNS enhanced mode: %s", c.DNS.EnhancedMode)
		}
	}

	if c.DNS.EnhancedMode == "fake-ip" && c.DNS.FakeIPRange != "" {
		if _, _, err := net.ParseCIDR(c.DNS.FakeIPRange); err != nil {
			r.addError("Invalid fake IP range: %s", c.DNS.FakeIPRange)
		}
	}
}

func (c *Config) validateOutbounds(r *ValidationResult) {
	if len(c.Outbounds) == 0 {
		r.addWarning("No outbounds defined")
		return
	}

	nodeNames := make(map[string]bool)
	for _, ob := range c.Outbounds {
		if nodeNames[ob.Name] {
			r.addError("Duplicate outbound name: %s", ob.Name)
		}
		nodeNames[ob.Name] = true

		if ob.Server == "" {
			r.addError("Outbound %s has no address", ob.Name)
		}

		if ob.Port < 1 || ob.Port > 65535 {
			r.addError("Outbound %s has invalid port: %d", ob.Name, ob.Port)
		}

		switch strings.ToLower(ob.Type) {
		case "vmess", "vless":
			if ob.UUID == "" {
				r.addWarning("Outbound %s (%s) has no UUID", ob.Name, ob.Type)
			}
		case "trojan":
			if ob.Password == "" {
				r.addError("Trojan outbound %s has no password", ob.Name)
			}
		case "shadowsocks", "ss":
			if ob.Password == "" {
				r.addError("Shadowsocks outbound %s has no password", ob.Name)
			}
			if ob.Cipher == "" {
				r.addWarning("Shadowsocks outbound %s has no cipher specified", ob.Name)
			}
		}
	}
}

func (c *Config) validateGroups(r *ValidationResult) {
	if len(c.Groups) == 0 {
		r.addWarning("No proxy groups defined")
		return
	}

	groupNames := make(map[string]bool)
	for _, group := range c.Groups {
		if groupNames[group.Name] {
			r.addError("Duplicate group name: %s", group.Name)
		}
		groupNames[group.Name] = true

		validTypes := map[string]bool{
			"selector": true, "url-test": true, "fallback": true,
			"load-balance": true, "smart": true,
		}
		if !validTypes[group.Type] {
			r.addError("Invalid group type: %s", group.Type)
		}

		// Validate smart-mode if group type is smart
		if group.Type == "smart" {
			validModes := map[string]bool{
				"auto": true, "fast": true, "stable": true,
				"balanced": true, "learning": true,
			}
			if group.SmartMode != "" && !validModes[group.SmartMode] {
				r.addWarning("Invalid smart-mode in group %s: %s", group.Name, group.SmartMode)
			}
		}

		if group.Type == "url-test" && group.URL != "" {
			if _, err := url.Parse(group.URL); err != nil {
				r.addWarning("Invalid url-test URL in group %s: %s", group.Name, err)
			}
		}
	}
}

func (c *Config) validateRouting(r *ValidationResult) {
	if c.Routing.DomainStrategy != "" {
		validStrategies := map[string]bool{
			"as-is": true, "prefer-ipv4": true, "ipv4-only": true,
			"prefer-ipv6": true, "ipv6-only": true,
		}
		if !validStrategies[c.Routing.DomainStrategy] {
			r.addWarning("Invalid domain strategy: %s", c.Routing.DomainStrategy)
		}
	}

	for i, rule := range c.Routing.Rules {
		if err := validateRule(&rule); err != nil {
			r.addWarning("Rule %d: %s", i, err)
		}
	}
}

func validateRule(rule *RuleConfig) error {
	if rule.Type == "" {
		return fmt.Errorf("rule type is required")
	}

	if rule.Outbound == "" {
		return fmt.Errorf("rule outbound is required")
	}

	validTypes := map[string]bool{
		"domain": true, "domain-suffix": true, "domain-keyword": true,
		"domain-regex": true, "geoip": true, "geosite": true,
		"ip-cidr": true, "ip-cidr6": true, "src-ip-cidr": true,
		"src-port": true, "dest-port": true, "process": true,
		"process-path": true, "rule-set": true, "match": true,
	}

	if !validTypes[strings.ToLower(rule.Type)] {
		return fmt.Errorf("invalid rule type: %s", rule.Type)
	}

	switch strings.ToLower(rule.Type) {
	case "ip-cidr", "ip-cidr6", "src-ip-cidr":
		if rule.Value == "" {
			return fmt.Errorf("CIDR value is required")
		}
		if _, _, err := net.ParseCIDR(rule.Value); err != nil {
			return fmt.Errorf("invalid CIDR: %s", rule.Value)
		}
	case "geoip":
		if len(rule.Value) != 2 {
			return fmt.Errorf("GEOIP value must be 2-letter country code")
		}
	}

	return nil
}

func (c *Config) validateProviders(r *ValidationResult) {
	for _, p := range c.Providers {
		if p.Name == "" {
			r.addError("Provider has no name")
			continue
		}

		validTypes := map[string]bool{
			"http": true, "file": true, "compatible": true,
		}
		if !validTypes[p.Type] {
			r.addWarning("Invalid provider type: %s", p.Type)
		}

		switch p.Type {
		case "http":
			if p.URL == "" {
				r.addError("HTTP provider %s has no URL", p.Name)
			} else if _, err := url.Parse(p.URL); err != nil {
				r.addError("Invalid URL in provider %s: %s", p.Name, err)
			}
		case "file":
			if p.Path == "" {
				r.addError("File provider %s has no path", p.Name)
			}
		}

		if p.Interval < 0 {
			r.addWarning("Provider %s has negative interval", p.Name)
		}
	}
}

func (c *Config) validateTunnels(r *ValidationResult) {
	for _, t := range c.Tunnels {
		if t.Name == "" {
			r.addError("Tunnel has no name")
		}

		if t.Type == "" {
			r.addWarning("Tunnel %s has no type", t.Name)
		}

		for _, addr := range t.Addresses {
			if _, _, err := net.ParseCIDR(addr); err != nil {
				r.addWarning("Invalid tunnel address: %s", addr)
			}
		}
	}
}

// isValidListenAddr checks if a listen address is valid
func isValidListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	if host == "" || host == "*" {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		return true
	}

	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}

	if host == "0.0.0.0" {
		return true
	}

	return false
}

// SuggestFixes provides suggestions for fixing validation errors
func (r *ValidationResult) SuggestFixes() []string {
	suggestions := []string{}

	for _, errStr := range r.Errors {
		if strings.Contains(errStr, "port") {
			suggestions = append(suggestions, "Ensure port numbers are between 1 and 65535")
		}
		if strings.Contains(errStr, "address") {
			suggestions = append(suggestions, "Check that all addresses are in valid IP:port format")
		}
		if strings.Contains(errStr, "uuid") {
			suggestions = append(suggestions, "Ensure all VMess/VLESS nodes have valid UUIDs")
		}
	}

	return suggestions
}
