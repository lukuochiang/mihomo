package rules

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/mihomo/smart/geoip"
)

// RuleType defines rule types
type RuleType string

const (
	RuleTypeDomain         RuleType = "DOMAIN"
	RuleTypeDomainSuffix   RuleType = "DOMAIN-SUFFIX"
	RuleTypeDomainKeyword  RuleType = "DOMAIN-KEYWORD"
	RuleTypeDomainRegex    RuleType = "DOMAIN-REGEX"
	RuleTypeGeoIP          RuleType = "GEOIP"
	RuleTypeGeoSite        RuleType = "GEOSITE"
	RuleTypeIPCIDR         RuleType = "IP-CIDR"
	RuleTypeIPCIDR6        RuleType = "IP-CIDR6"
	RuleTypeIPCidrRange    RuleType = "IP-CIDR"
	RuleTypeProcess        RuleType = "PROCESS"
	RuleTypeProcessPath    RuleType = "PROCESS-PATH"
	RuleTypeRuleSet        RuleType = "RULE-SET"
	RuleTypeMatch          RuleType = "MATCH"
	RuleTypeURL            RuleType = "URL"
	RuleTypeHTTPHost       RuleType = "HTTP-HOST"
	RuleTypeProtocol       RuleType = "PROTOCOL"
	RuleTypeSourceIPCIDR   RuleType = "SRC-IP-CIDR"
	RuleTypeSourcePort     RuleType = "SRC-PORT"
	RuleTypeDestPort       RuleType = "DEST-PORT"
	RuleTypeInboundTag     RuleType = "INBOUND-TAG"
	RuleTypeRuleSetPayload RuleType = "RULE-SET"
)

// Special outbound types
const (
	OutboundDirect      = "DIRECT"
	OutboundReject      = "REJECT"
	OutboundRejectTLS   = "REJECT-TLS"
	OutboundRejectDrops = "REJECT-DROP"
)

// Rule represents a routing rule
type Rule struct {
	Type     RuleType
	Value    string
	Outbound string
	Params   map[string]string
	Payload  interface{}
}

// Matcher matches requests against rules
type Matcher interface {
	Match(ctx *RuleContext) bool
}

// RuleContext holds context for rule matching
type RuleContext struct {
	Domain        string
	Host          string
	Destination   string
	SourceIP      net.IP
	DestinationIP net.IP
	Port          int
	SourcePort    int
	Protocol      string
	ProcessName   string
	ProcessPath   string
	Network       string // tcp, udp
	HTTPHost      string
	URL           string
	Timestamp     int64
}

// RuleEngine manages routing rules
type RuleEngine struct {
	rules      []Rule
	geoip      *geoip.GeoIP
	geosite    *geoip.GeoSite
	domainTree *DomainTree
	ipSet      *IPSet
	mu         sync.RWMutex
}

// DomainTree is an efficient domain matching structure
type DomainTree struct {
	root *domainNode
}

type domainNode struct {
	label      string
	isWildcard bool
	children   map[string]*domainNode
	rules      []int // Rule indices that match this domain
}

// IPSet is an efficient IP matching structure
type IPSet struct {
	ipv4Ranges []ipCIDR
	ipv6Ranges []ipCIDR
}

type ipCIDR struct {
	network *net.IPNet
	rules   []int
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(g *geoip.GeoIP, gs *geoip.GeoSite) *RuleEngine {
	return &RuleEngine{
		rules:   make([]Rule, 0),
		geoip:   g,
		geosite: gs,
		domainTree: &DomainTree{
			root: &domainNode{
				children: make(map[string]*domainNode),
			},
		},
		ipSet: &IPSet{
			ipv4Ranges: make([]ipCIDR, 0),
			ipv6Ranges: make([]ipCIDR, 0),
		},
	}
}

// AddRule adds a rule
func (e *RuleEngine) AddRule(rule Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Pre-process rule
	switch rule.Type {
	case RuleTypeDomainSuffix, RuleTypeDomainKeyword:
		rule.Payload = rule.Value
	case RuleTypeDomain:
		rule.Payload = strings.ToLower(rule.Value)
	case RuleTypeGeoIP:
		// Already processed in geoip
	case RuleTypeIPCIDR:
		_, ipNet, err := net.ParseCIDR(rule.Value)
		if err != nil {
			return err
		}
		rule.Payload = ipNet
	case RuleTypeIPCIDR6:
		_, ipNet, err := net.ParseCIDR(rule.Value)
		if err != nil {
			return err
		}
		rule.Payload = ipNet
	}

	e.rules = append(e.rules, rule)
	return nil
}

// Match finds matching rule for context
func (e *RuleEngine) Match(ctx *RuleContext) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Normalize context
	ctx.normalize()

	for i, rule := range e.rules {
		if e.matchRule(&rule, ctx) {
			if rule.Type == RuleTypeMatch {
				return "", nil // No match
			}
			return rule.Outbound, nil
		}
		_ = i // Used implicitly
	}

	return "", nil
}

// MatchWithIndex finds matching rule and returns rule index
func (e *RuleEngine) MatchWithIndex(ctx *RuleContext) (string, int, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ctx.normalize()

	for i, rule := range e.rules {
		if e.matchRule(&rule, ctx) {
			if rule.Type == RuleTypeMatch {
				return "", -1, nil
			}
			return rule.Outbound, i, nil
		}
	}

	return "", -1, nil
}

// MatchAll finds all matching rules
func (e *RuleEngine) MatchAll(ctx *RuleContext) []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ctx.normalize()

	var matched []Rule
	for i := range e.rules {
		if e.matchRule(&e.rules[i], ctx) {
			matched = append(matched, e.rules[i])
		}
	}

	return matched
}

// GetRuleCount returns the number of rules
func (e *RuleEngine) GetRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// GetRules returns all rules
func (e *RuleEngine) GetRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rules := make([]Rule, len(e.rules))
	copy(rules, e.rules)
	return rules
}

// ClearRules removes all rules
func (e *RuleEngine) ClearRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = make([]Rule, 0)
}

// LoadRulesFromRuleSet loads rules from a RuleSet
func (e *RuleEngine) LoadRulesFromRuleSet(rs *RuleSet) error {
	for _, rule := range rs.Rules {
		if err := e.AddRule(rule); err != nil {
			continue
		}
	}
	return nil
}

func (e *RuleEngine) matchRule(rule *Rule, ctx *RuleContext) bool {
	switch rule.Type {
	case RuleTypeDomain:
		return e.matchDomain(rule.Value, ctx.Domain)
	case RuleTypeDomainSuffix:
		return e.matchDomainSuffix(rule.Value, ctx.Domain)
	case RuleTypeDomainKeyword:
		return e.matchDomainKeyword(rule.Value, ctx.Domain)
	case RuleTypeDomainRegex:
		return e.matchDomainRegex(rule.Value, ctx.Domain)
	case RuleTypeGeoIP:
		return e.matchGeoIP(rule.Value, ctx.DestinationIP)
	case RuleTypeGeoSite:
		return e.matchGeoSite(rule.Value, ctx.Domain)
	case RuleTypeIPCIDR:
		return e.matchIPCIDR(rule.Payload.(*net.IPNet), ctx.DestinationIP)
	case RuleTypeIPCIDR6:
		return e.matchIPCIDR(rule.Payload.(*net.IPNet), ctx.DestinationIP)
	case RuleTypeSourceIPCIDR:
		return e.matchIPCIDR(rule.Payload.(*net.IPNet), ctx.SourceIP)
	case RuleTypeProcess:
		return e.matchProcess(rule.Value, ctx.ProcessName)
	case RuleTypeProcessPath:
		return e.matchProcessPath(rule.Value, ctx.ProcessPath)
	case RuleTypeHTTPHost:
		return e.matchDomainKeyword(rule.Value, ctx.HTTPHost)
	case RuleTypeProtocol:
		return e.matchProtocol(rule.Value, ctx.Protocol)
	case RuleTypeSourcePort:
		return e.matchPort(rule.Value, ctx.SourcePort)
	case RuleTypeDestPort:
		return e.matchPort(rule.Value, ctx.Port)
	case RuleTypeRuleSet:
		return e.matchRuleSet(rule.Value, ctx)
	case RuleTypeMatch:
		return true
	default:
		return false
	}
}

func (e *RuleEngine) matchDomain(pattern, domain string) bool {
	if domain == "" {
		return false
	}
	domain = strings.ToLower(domain)
	return domain == pattern
}

func (e *RuleEngine) matchDomainSuffix(suffix, domain string) bool {
	if domain == "" {
		return false
	}
	domain = strings.ToLower(domain)
	suffix = strings.ToLower(suffix)

	if domain == suffix {
		return true
	}
	if strings.HasSuffix(domain, "."+suffix) {
		return true
	}
	return false
}

func (e *RuleEngine) matchDomainKeyword(keyword, domain string) bool {
	if domain == "" {
		return false
	}
	domain = strings.ToLower(domain)
	return strings.Contains(domain, keyword)
}

func (e *RuleEngine) matchGeoIP(countryCode string, ip net.IP) bool {
	if ip == nil {
		return false
	}

	if geoip.IsPrivate(ip) {
		return false
	}

	country := e.geoip.Lookup(ip)
	return country == countryCode
}

func (e *RuleEngine) matchGeoSite(category, domain string) bool {
	if domain == "" || e.geosite == nil {
		return false
	}

	// Check if domain matches the category
	return e.geosite.Match(domain, category)
}

func (e *RuleEngine) matchIPCIDR(ipNet *net.IPNet, ip net.IP) bool {
	if ip == nil || ipNet == nil {
		return false
	}
	return ipNet.Contains(ip)
}

func (e *RuleEngine) matchProcess(name, processName string) bool {
	return strings.EqualFold(name, processName)
}

func (e *RuleEngine) matchProcessPath(pattern, processPath string) bool {
	if processPath == "" {
		return false
	}

	// Support wildcard matching
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(processPath, prefix)
	}

	return strings.EqualFold(pattern, processPath)
}

func (e *RuleEngine) matchProtocol(pattern, protocol string) bool {
	return strings.EqualFold(pattern, protocol)
}

func (e *RuleEngine) matchPort(pattern string, port int) bool {
	// Support port ranges like "80,443" or "80-8080"
	parts := strings.Split(pattern, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				var start, end int
				fmt.Sscanf(rangeParts[0], "%d", &start)
				fmt.Sscanf(rangeParts[1], "%d", &end)
				if port >= start && port <= end {
					return true
				}
			}
		} else {
			var p int
			fmt.Sscanf(part, "%d", &p)
			if p == port {
				return true
			}
		}
	}
	return false
}

func (e *RuleEngine) matchDomainRegex(pattern, domain string) bool {
	if domain == "" || pattern == "" {
		return false
	}

	// Cache compiled regex
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}

	return re.MatchString(domain)
}

func (e *RuleEngine) matchRuleSet(setName string, ctx *RuleContext) bool {
	// RULE-SET would be handled by loading external rules
	// For now, return false as we don't have RULE-SET loaded
	_ = setName
	_ = ctx
	return false
}

// normalize normalizes rule context
func (ctx *RuleContext) normalize() {
	if ctx.Domain != "" && ctx.Host != "" {
		// Use whichever is more specific
		if len(ctx.Host) > len(ctx.Domain) {
			ctx.Domain = ctx.Host
		}
	}

	if ctx.Domain == "" && ctx.HTTPHost != "" {
		ctx.Domain = ctx.HTTPHost
	}

	if ctx.Domain == "" && ctx.Host != "" {
		ctx.Domain = ctx.Host
	}

	// Extract domain from URL if needed
	if ctx.Domain == "" && ctx.URL != "" {
		if u, err := url.Parse(ctx.URL); err == nil {
			ctx.Domain = u.Hostname()
		}
	}

	// Extract host from destination if needed
	if ctx.Domain == "" && ctx.Destination != "" {
		if host, _, err := net.SplitHostPort(ctx.Destination); err == nil {
			ctx.Domain = host
		} else {
			ctx.Domain = ctx.Destination
		}
	}
}

// DomainMatcher provides efficient domain matching
type DomainMatcher struct {
	exact   map[string]bool
	suffix  *SuffixMatcher
	keyword []string
	regex   []*regexp.Regexp
}

// SuffixMatcher matches domain suffixes efficiently
type SuffixMatcher struct {
	tree *domainNode
}

// NewSuffixMatcher creates a new suffix matcher
func NewSuffixMatcher() *SuffixMatcher {
	return &SuffixMatcher{
		tree: &domainNode{
			children: make(map[string]*domainNode),
		},
	}
}

// Add adds a suffix to match
func (m *SuffixMatcher) Add(suffix string) {
	node := m.tree
	labels := strings.Split(suffix, ".")

	// Process from end to start
	for i := len(labels) - 1; i >= 0; i-- {
		label := strings.ToLower(labels[i])
		if label == "" {
			continue
		}

		if node.children == nil {
			node.children = make(map[string]*domainNode)
		}

		if node.children[label] == nil {
			node.children[label] = &domainNode{
				children: make(map[string]*domainNode),
			}
		}
		node = node.children[label]
	}
}

// Match checks if domain matches any suffix
func (m *SuffixMatcher) Match(domain string) bool {
	node := m.tree
	labels := strings.Split(domain, ".")

	for i := len(labels) - 1; i >= 0; i-- {
		label := strings.ToLower(labels[i])
		if label == "" {
			continue
		}

		if node.children == nil {
			return false
		}

		next, ok := node.children[label]
		if !ok {
			// Check for wildcard match
			if star, ok := node.children["*"]; ok && star != nil {
				return true
			}
			return false
		}
		node = next

		// Check if this is an end node
		if node.children == nil || len(node.children) == 0 {
			return true
		}
	}

	return true
}

// RuleSet represents a collection of rules
type RuleSet struct {
	Name    string
	Type    string // local, http, file
	Rules   []Rule
	BaseURL string
	Path    string
	Format  string // text, yaml, json, source
}

// LoadRuleSet loads rules from a source
func LoadRuleSet(name string, source string) (*RuleSet, error) {
	rs := &RuleSet{
		Name: name,
	}

	// Determine source type
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		rs.Type = "http"
		rs.BaseURL = source
	} else if strings.HasPrefix(source, "tag:") {
		rs.Type = "local"
		rs.Format = strings.TrimPrefix(source, "tag:")
	} else {
		rs.Type = "file"
		rs.Path = source
	}

	return rs, nil
}

// Fetch fetches rules from remote source
func (rs *RuleSet) Fetch() error {
	if rs.Type != "http" {
		return nil
	}

	// TODO: Implement HTTP fetch
	return nil
}

// Parse parses rules from content
func (rs *RuleSet) Parse(content []byte) error {
	switch rs.Format {
	case "text", "clash":
		return rs.parseText(content)
	case "yaml":
		return rs.parseYAML(content)
	case "json":
		return rs.parseJSON(content)
	default:
		return rs.parseText(content)
	}
}

func (rs *RuleSet) parseText(content []byte) error {
	lines := strings.Split(string(content), "\n")

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

	return nil
}

func (rs *RuleSet) parseYAML(content []byte) error {
	// Simple YAML parsing for rules
	// In production, use yaml library
	return rs.parseText(content)
}

func (rs *RuleSet) parseJSON(content []byte) error {
	// Simple JSON parsing for rules
	return rs.parseText(content)
}

func parseRuleLine(line string) (Rule, error) {
	// Format: RULE-TYPE,VALUE,OUTBOUND
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return Rule{}, fmt.Errorf("invalid rule format")
	}

	ruleType := RuleType(strings.ToUpper(parts[0]))
	value := strings.TrimSpace(parts[1])
	outbound := strings.TrimSpace(parts[2])

	// Parse extra params if present
	params := make(map[string]string)
	if len(parts) > 3 {
		for _, param := range parts[3:] {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				params[kv[0]] = kv[1]
			}
		}
	}

	return Rule{
		Type:     ruleType,
		Value:    value,
		Outbound: outbound,
		Params:   params,
	}, nil
}

// RuleGroup represents a group of rules
type RuleGroup struct {
	Name   string
	Type   string
	Rules  []Rule
	Policy string
}

// Strategy defines rule matching strategy
type Strategy int

const (
	StrategyFirst Strategy = iota
	StrategyBest
	StrategyAll
)

// Compile compiles rules for efficient matching
func (e *RuleEngine) Compile() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Build optimized structures
	for i, rule := range e.rules {
		switch rule.Type {
		case RuleTypeDomainSuffix:
			// Use suffix matcher for domain suffixes
			_ = i          // Used for rule lookup
			_ = rule.Value // domain suffix value
		case RuleTypeIPCIDR:
			_, ipNet, _ := net.ParseCIDR(rule.Value)
			if ipNet != nil {
				e.ipSet.addIPv4(ipNet, i)
			}
		case RuleTypeIPCIDR6:
			_, ipNet, _ := net.ParseCIDR(rule.Value)
			if ipNet != nil {
				e.ipSet.addIPv6(ipNet, i)
			}
		}
	}

	return nil
}

// addIPv4 adds an IPv4 CIDR to the set
func (s *IPSet) addIPv4(ipNet *net.IPNet, ruleIdx int) {
	if ip4 := ipNet.IP.To4(); ip4 != nil {
		s.ipv4Ranges = append(s.ipv4Ranges, ipCIDR{
			network: ipNet,
			rules:   []int{ruleIdx},
		})
	}
}

// addIPv6 adds an IPv6 CIDR to the set
func (s *IPSet) addIPv6(ipNet *net.IPNet, ruleIdx int) {
	if ip4 := ipNet.IP.To4(); ip4 == nil {
		s.ipv6Ranges = append(s.ipv6Ranges, ipCIDR{
			network: ipNet,
			rules:   []int{ruleIdx},
		})
	}
}

// DNSRuleEngine is specialized for DNS rules
type DNSRuleEngine struct {
	engine *RuleEngine
}

// NewDNSRuleEngine creates a DNS-specific rule engine
func NewDNSRuleEngine(g *geoip.GeoIP, gs *geoip.GeoSite) *DNSRuleEngine {
	return &DNSRuleEngine{
		engine: NewRuleEngine(g, gs),
	}
}

// MatchDNS matches DNS query
func (e *DNSRuleEngine) MatchDNS(domain string) (string, bool) {
	ctx := &RuleContext{
		Domain: domain,
	}

	outbound, err := e.engine.Match(ctx)
	return outbound, err == nil
}
