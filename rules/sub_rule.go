package rules

import (
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// SubRule represents a sub-rule with nested rules
type SubRule struct {
	Name     string         `yaml:"name"`
	Type     string         `yaml:"type"` // sub-rule, sub-group
	Rules    []*SubRuleItem `yaml:"rules"`
	Policy   string         `yaml:"policy"` // All match, Any match
	Outbound string         `yaml:"outbound"`
}

// SubRuleItem represents an item in a sub-rule
type SubRuleItem struct {
	Type   RuleType `yaml:"type"` // Rule type or "sub-rule"
	Value  string   `yaml:"value"`
	Params []string `yaml:"params"` // Extra parameters
}

// SubRuleEngine handles sub-rule matching
type SubRuleEngine struct {
	subRules   map[string]*SubRule
	ruleEngine *RuleEngine
}

// NewSubRuleEngine creates a new sub-rule engine
func NewSubRuleEngine(engine *RuleEngine) *SubRuleEngine {
	return &SubRuleEngine{
		subRules:   make(map[string]*SubRule),
		ruleEngine: engine,
	}
}

// Register registers a sub-rule
func (e *SubRuleEngine) Register(subRule *SubRule) error {
	if subRule.Name == "" {
		return fmt.Errorf("sub-rule name is required")
	}
	if _, exists := e.subRules[subRule.Name]; exists {
		return fmt.Errorf("sub-rule %s already exists", subRule.Name)
	}
	if subRule.Policy == "" {
		subRule.Policy = "all" // Default: all rules must match
	}
	e.subRules[subRule.Name] = subRule
	return nil
}

// Unregister unregisters a sub-rule
func (e *SubRuleEngine) Unregister(name string) error {
	if _, exists := e.subRules[name]; !exists {
		return fmt.Errorf("sub-rule %s not found", name)
	}
	delete(e.subRules, name)
	return nil
}

// Match matches a sub-rule against context
func (e *SubRuleEngine) Match(name string, ctx *RuleContext) (string, error) {
	subRule, exists := e.subRules[name]
	if !exists {
		return "", fmt.Errorf("sub-rule %s not found", name)
	}
	return e.matchSubRule(subRule, ctx)
}

func (e *SubRuleEngine) matchSubRule(subRule *SubRule, ctx *RuleContext) (string, error) {
	var matched bool
	var ruleOutbound string

	switch strings.ToLower(subRule.Policy) {
	case "all":
		// All rules must match
		matched = true
		for _, item := range subRule.Rules {
			itemMatched, outbound, err := e.matchItem(item, ctx)
			if err != nil {
				return "", err
			}
			if !itemMatched {
				matched = false
				break
			}
			ruleOutbound = outbound
		}

	case "any":
		// Any rule matches
		matched = false
		for _, item := range subRule.Rules {
			itemMatched, outbound, err := e.matchItem(item, ctx)
			if err != nil {
				return "", err
			}
			if itemMatched {
				matched = true
				ruleOutbound = outbound
				break
			}
		}

	default:
		// Default: all must match
		matched = true
		for _, item := range subRule.Rules {
			itemMatched, outbound, err := e.matchItem(item, ctx)
			if err != nil {
				return "", err
			}
			if !itemMatched {
				matched = false
				break
			}
			ruleOutbound = outbound
		}
	}

	if matched {
		// Use item's outbound, or sub-rule's outbound
		if ruleOutbound != "" {
			return ruleOutbound, nil
		}
		return subRule.Outbound, nil
	}

	return "", nil
}

func (e *SubRuleEngine) matchItem(item *SubRuleItem, ctx *RuleContext) (bool, string, error) {
	// Check if this is a reference to another sub-rule
	if item.Type == RuleType("sub-rule") || item.Type == RuleType("") {
		// Recursively match sub-rule
		subRule, exists := e.subRules[item.Value]
		if !exists {
			return false, "", nil
		}
		outbound, err := e.matchSubRule(subRule, ctx)
		return err == nil && outbound != "", outbound, nil
	}

	// Match as regular rule
	rule := Rule{
		Type:     item.Type,
		Value:    item.Value,
		Outbound: item.Params[0], // First param is outbound
	}

	// Check if rule matches
	if e.ruleEngine.matchRule(&rule, ctx) {
		return true, rule.Outbound, nil
	}

	return false, "", nil
}

// ParseSubRule parses a sub-rule from text format
// Format: sub-rule,name,[all|any],rule1,rule2,...,outbound
// Or: sub-rule,name,policy,(DOMAIN-SUFFIX,example.com,DIRECT),(GEOIP,CN,PROXY),outbound
func ParseSubRule(line string) (*SubRule, error) {
	if !strings.HasPrefix(line, "sub-rule,") {
		return nil, fmt.Errorf("invalid sub-rule format")
	}

	parts := strings.Split(line, ",")
	if len(parts) < 4 {
		return nil, fmt.Errorf("sub-rule must have name, policy, and at least one rule")
	}

	subRule := &SubRule{
		Name:   strings.TrimSpace(parts[1]),
		Policy: strings.TrimSpace(parts[2]),
		Rules:  make([]*SubRuleItem, 0),
	}

	// Parse rules from parts
	// Each rule is in format: (TYPE,VALUE)
	for i := 3; i < len(parts)-1; i++ {
		part := strings.TrimSpace(parts[i])
		part = strings.Trim(part, "() ")

		ruleParts := strings.SplitN(part, ",", 2)
		if len(ruleParts) != 2 {
			continue
		}

		item := &SubRuleItem{
			Type:  RuleType(strings.TrimSpace(ruleParts[0])),
			Value: strings.TrimSpace(ruleParts[1]),
		}
		subRule.Rules = append(subRule.Rules, item)
	}

	// Last part is outbound
	if len(parts) > 0 {
		subRule.Outbound = strings.TrimSpace(parts[len(parts)-1])
	}

	return subRule, nil
}

// ParseSubRuleYAML parses sub-rules from YAML format
type YAMLSubRule struct {
	Name   string            `yaml:"name"`
	Type   string            `yaml:"type"`
	Policy string            `yaml:"policy"`
	Rules  []YAMLSubRuleItem `yaml:"rules"`
}

type YAMLSubRuleItem struct {
	Type   string   `yaml:"type"`
	Value  string   `yaml:"value"`
	Params []string `yaml:"params"`
}

// SubRuleGroup represents a group of sub-rules
type SubRuleGroup struct {
	Name     string     `yaml:"name"`
	Type     string     `yaml:"type"` // sub-rule-group
	SubRules []*SubRule `yaml:"sub-rules"`
	mu       sync.RWMutex
}

// NewSubRuleGroup creates a new sub-rule group
func NewSubRuleGroup(name string) *SubRuleGroup {
	return &SubRuleGroup{
		Name:     name,
		Type:     "sub-rule-group",
		SubRules: make([]*SubRule, 0),
	}
}

// Add adds a sub-rule to the group
func (g *SubRuleGroup) Add(subRule *SubRule) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.SubRules = append(g.SubRules, subRule)
}

// Match matches the group against context
func (g *SubRuleGroup) Match(ctx *RuleContext) (string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, subRule := range g.SubRules {
		outbound, err := matchSubRuleSimple(subRule, ctx)
		if err != nil {
			continue
		}
		if outbound != "" {
			return outbound, nil
		}
	}

	return "", nil
}

// matchSubRuleSimple is a simple matcher for sub-rules
func matchSubRuleSimple(subRule *SubRule, ctx *RuleContext) (string, error) {
	// Simplified matching for sub-rule groups
	// Full implementation would use SubRuleEngine
	for _, item := range subRule.Rules {
		if item.Type == RuleTypeDomain && ctx.Domain == item.Value {
			if len(item.Params) > 0 {
				return item.Params[0], nil
			}
			return subRule.Outbound, nil
		}
	}
	return "", nil
}

// CompositeRule represents a composite rule with multiple conditions
type CompositeRule struct {
	Conditions []CompositeCondition `yaml:"conditions"`
	Operator   string               `yaml:"operator"` // AND, OR
	Outbound   string               `yaml:"outbound"`
}

// CompositeCondition represents a condition in a composite rule
type CompositeCondition struct {
	Type  string `yaml:"type"` // domain, geoip, ipcidr, process, etc.
	Value string `yaml:"value"`
	Not   bool   `yaml:"not"` // Negate the condition
}

// MatchCompositeRule matches a composite rule against context
func MatchCompositeRule(rule *CompositeRule, ctx *RuleContext) bool {
	if len(rule.Conditions) == 0 {
		return false
	}

	results := make([]bool, len(rule.Conditions))
	for i, cond := range rule.Conditions {
		results[i] = matchCompositeCondition(cond, ctx)
		if cond.Not {
			results[i] = !results[i]
		}
	}

	switch strings.ToUpper(rule.Operator) {
	case "AND":
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	case "OR":
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func matchCompositeCondition(cond CompositeCondition, ctx *RuleContext) bool {
	switch strings.ToLower(cond.Type) {
	case "domain":
		return ctx.Domain == cond.Value
	case "domain-suffix":
		return strings.HasSuffix(ctx.Domain, "."+cond.Value)
	case "domain-keyword":
		return strings.Contains(ctx.Domain, cond.Value)
	case "geoip":
		return false // Would use geoip lookup
	case "ipcidr":
		return false // Would check IP against CIDR
	case "src-ipcidr":
		return false // Would check source IP against CIDR
	case "process":
		return strings.EqualFold(ctx.ProcessName, cond.Value)
	case "protocol":
		return strings.EqualFold(ctx.Protocol, cond.Value)
	case "src-port":
		return fmt.Sprintf("%d", ctx.SourcePort) == cond.Value
	case "dest-port":
		return fmt.Sprintf("%d", ctx.Port) == cond.Value
	default:
		return false
	}
}

// RuleMatcher provides advanced rule matching capabilities
type RuleMatcher struct {
	engine     *RuleEngine
	subEngine  *SubRuleEngine
	composites []*CompositeRule
}

// NewRuleMatcher creates a new rule matcher
func NewRuleMatcher(engine *RuleEngine) *RuleMatcher {
	return &RuleMatcher{
		engine:     engine,
		subEngine:  NewSubRuleEngine(engine),
		composites: make([]*CompositeRule, 0),
	}
}

// AddCompositeRule adds a composite rule
func (m *RuleMatcher) AddCompositeRule(rule *CompositeRule) {
	m.composites = append(m.composites, rule)
}

// Match performs comprehensive rule matching
func (m *RuleMatcher) Match(ctx *RuleContext) (string, error) {
	// Try composite rules first (highest priority)
	for _, rule := range m.composites {
		if MatchCompositeRule(rule, ctx) {
			return rule.Outbound, nil
		}
	}

	// Try sub-rules
	for name := range m.subEngine.subRules {
		outbound, err := m.subEngine.Match(name, ctx)
		if err == nil && outbound != "" {
			return outbound, nil
		}
	}

	// Try regular rules
	return m.engine.Match(ctx)
}

// GetSubRuleEngine returns the sub-rule engine
func (m *RuleMatcher) GetSubRuleEngine() *SubRuleEngine {
	return m.subEngine
}

// RuleSet represents a collection of rules with metadata
type RuleSetWithMetadata struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	Author      string           `yaml:"author"`
	Version     string           `yaml:"version"`
	Updated     string           `yaml:"updated"`
	Rules       []Rule           `yaml:"rules"`
	SubRules    []*SubRule       `yaml:"sub-rules"`
	Composites  []*CompositeRule `yaml:"composites"`
}

// LoadRuleSetWithMetadata loads a rule set with full metadata
func LoadRuleSetWithMetadata(data []byte) (*RuleSetWithMetadata, error) {
	var rs RuleSetWithMetadata
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}
