package geoip

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// GeoSite provides domain category lookup
type GeoSite struct {
	mu         sync.RWMutex
	categories map[string]*GeoSiteCategory
	trie       *domainTrie
}

// GeoSiteCategory represents a domain category
type GeoSiteCategory struct {
	Name    string
	Domains []string
	count   int
}

// domainTrie is a trie for efficient domain matching
type domainTrie struct {
	root    *trieNode
	version string
}

// trieNode represents a node in the domain trie
type trieNode struct {
	children map[string]*trieNode
	isEnd    bool
	category string
	wildcard bool // true if this node represents a wildcard
}

// NewGeoSite creates a new GeoSite instance
func NewGeoSite() *GeoSite {
	return &GeoSite{
		categories: make(map[string]*GeoSiteCategory),
		trie: &domainTrie{
			root: &trieNode{
				children: make(map[string]*trieNode),
			},
		},
	}
}

// LoadFromFile loads GeoSite data from a file
func (g *GeoSite) LoadFromFile(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	ext := filepath.Ext(path)
	isGzip := ext == ".gz"

	var data []byte
	var err error

	if isGzip {
		data, err = g.loadGzipFile(path)
	} else {
		data, err = os.ReadFile(path)
	}

	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Detect format based on content
	content := string(data)
	if strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
		return g.parseJSONFormat(data)
	}

	return g.parseTextFormat(content)
}

// parseTextFormat parses GeoSite data in text format (Clash GeoSite format)
func (g *GeoSite) parseTextFormat(data string) error {
	lines := strings.Split(data, "\n")
	var currentCategory *GeoSiteCategory

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for category header (full-width colon or regular colon)
		if strings.HasPrefix(line, "domain:") || strings.HasPrefix(line, "domain：") {
			categoryName := strings.TrimPrefix(line, "domain:")
			categoryName = strings.TrimPrefix(categoryName, "domain：")
			categoryName = strings.TrimSpace(categoryName)

			if currentCategory != nil {
				g.categories[currentCategory.Name] = currentCategory
				g.buildTrie(currentCategory)
			}

			currentCategory = &GeoSiteCategory{
				Name:    categoryName,
				Domains: make([]string, 0),
			}
			continue
		}

		// Check for full-width full stop (。) for category end
		if strings.HasPrefix(line, "。") || strings.HasPrefix(line, ".") {
			if currentCategory != nil {
				g.categories[currentCategory.Name] = currentCategory
				g.buildTrie(currentCategory)
			}
			currentCategory = nil
			continue
		}

		// Add domain to current category
		if currentCategory != nil {
			currentCategory.Domains = append(currentCategory.Domains, line)
		}
	}

	// Handle last category
	if currentCategory != nil {
		g.categories[currentCategory.Name] = currentCategory
		g.buildTrie(currentCategory)
	}

	return nil
}

// loadGzipFile loads a gzip compressed file
func (g *GeoSite) loadGzipFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	data := make([]byte, 0, 64*1024)
	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	return data, nil
}

// parseJSONFormat parses GeoSite data in JSON format (Clash format)
func (g *GeoSite) parseJSONFormat(data []byte) error {
	var geositeData struct {
		Version string `json:"version"`
		Rules   []struct {
			Type         string   `json:"type"`
			CountryCodes []string `json:"country_codes"`
			Domains      []string `json:"domains"`
		} `json:"rules"`
	}

	if err := json.Unmarshal(data, &geositeData); err != nil {
		// Try simpler format
		var simpleData []map[string]interface{}
		if err := json.Unmarshal(data, &simpleData); err != nil {
			return err
		}

		for _, item := range simpleData {
			category, ok := item["category"].(string)
			if !ok {
				continue
			}

			domains, _ := item["domains"].([]interface{})
			cat := &GeoSiteCategory{
				Name:    category,
				Domains: make([]string, 0, len(domains)),
			}

			for _, d := range domains {
				if domain, ok := d.(string); ok {
					cat.Domains = append(cat.Domains, domain)
					g.trie.insert(domain, category)
				}
			}

			g.categories[category] = cat
		}

		return nil
	}

	// Parse structured JSON
	for _, rule := range geositeData.Rules {
		category := rule.Type
		if len(rule.CountryCodes) > 0 {
			category = rule.CountryCodes[0]
		}

		cat := &GeoSiteCategory{
			Name:    category,
			Domains: rule.Domains,
		}

		for _, domain := range rule.Domains {
			g.trie.insert(domain, category)
		}

		g.categories[category] = cat
	}

	return nil
}

// LoadFromData loads GeoSite data from a string
func (g *GeoSite) LoadFromData(data string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.parseGeoSiteData(data)
}

func (g *GeoSite) parseGeoSiteData(data string) error {
	lines := strings.Split(data, "\n")
	var currentCategory *GeoSiteCategory

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for category header (full-width colon or regular colon)
		if strings.HasPrefix(line, "domain:") || strings.HasPrefix(line, "domain：") {
			categoryName := strings.TrimPrefix(line, "domain:")
			categoryName = strings.TrimPrefix(categoryName, "domain：")
			categoryName = strings.TrimSpace(categoryName)

			if currentCategory != nil {
				g.categories[currentCategory.Name] = currentCategory
			}

			currentCategory = &GeoSiteCategory{
				Name:    categoryName,
				Domains: make([]string, 0),
			}
			continue
		}

		// Check for full-width full stop (。) for category end
		if strings.HasPrefix(line, "。") || strings.HasPrefix(line, ".") {
			if currentCategory != nil {
				g.categories[currentCategory.Name] = currentCategory
				g.buildTrie(currentCategory)
			}
			currentCategory = nil
			continue
		}

		// Add domain to current category
		if currentCategory != nil {
			currentCategory.Domains = append(currentCategory.Domains, line)
		}
	}

	// Handle last category
	if currentCategory != nil {
		g.categories[currentCategory.Name] = currentCategory
		g.buildTrie(currentCategory)
	}

	return nil
}

func (g *GeoSite) buildTrie(category *GeoSiteCategory) {
	for _, domain := range category.Domains {
		g.trie.insert(domain, category.Name)
	}
}

// insert inserts a domain into the trie
func (t *domainTrie) insert(domain, category string) {
	node := t.root
	labels := strings.Split(domain, ".")

	// Process from end to start for suffix matching
	for i := len(labels) - 1; i >= 0; i-- {
		label := strings.ToLower(labels[i])
		if label == "" {
			continue
		}

		if node.children == nil {
			node.children = make(map[string]*trieNode)
		}

		if node.children[label] == nil {
			node.children[label] = &trieNode{
				children: make(map[string]*trieNode),
			}
		}
		node = node.children[label]
	}
	node.isEnd = true
	node.category = category
}

// Match checks if a domain matches a category
func (g *GeoSite) Match(domain, category string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.categories[category]; !ok {
		return false
	}

	return g.trie.match(domain, category)
}

// MatchAny checks if a domain matches any category
func (g *GeoSite) MatchAny(domain string) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.trie.matchAny(domain)
}

// match checks if a domain matches a specific category
func (t *domainTrie) match(domain, category string) bool {
	node := t.root
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
			// Check for wildcard
			if star, ok := node.children["*"]; ok {
				return star.category == category
			}
			return false
		}
		node = next

		if node.isEnd && node.category == category {
			return true
		}
	}

	return false
}

// matchAny checks if a domain matches any category
func (t *domainTrie) matchAny(domain string) (string, bool) {
	node := t.root
	labels := strings.Split(domain, ".")

	for i := len(labels) - 1; i >= 0; i-- {
		label := strings.ToLower(labels[i])
		if label == "" {
			continue
		}

		if node.children == nil {
			break
		}

		next, ok := node.children[label]
		if !ok {
			// Check for wildcard
			if star, ok := node.children["*"]; ok {
				return star.category, true
			}
			break
		}
		node = next

		if node.isEnd {
			return node.category, true
		}
	}

	// Final wildcard check
	if node.children != nil {
		if star, ok := node.children["*"]; ok {
			return star.category, true
		}
	}

	return "", false
}

// GetCategories returns all available categories
func (g *GeoSite) GetCategories() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	categories := make([]string, 0, len(g.categories))
	for name := range g.categories {
		categories = append(categories, name)
	}
	return categories
}

// GetDomains returns all domains in a category
func (g *GeoSite) GetDomains(category string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	cat, ok := g.categories[category]
	if !ok {
		return nil
	}
	return cat.Domains
}

// GetDomainCount returns the number of domains in a category
func (g *GeoSite) GetDomainCount(category string) int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	cat, ok := g.categories[category]
	if !ok {
		return 0
	}
	return len(cat.Domains)
}

// MatchSuffix checks if a domain ends with the given suffix
func (g *GeoSite) MatchSuffix(domain, suffix string) bool {
	return strings.HasSuffix(domain, suffix) || strings.HasSuffix(domain, "."+suffix)
}

// MatchPrefix checks if a domain starts with the given prefix
func (g *GeoSite) MatchPrefix(domain, prefix string) bool {
	return strings.HasPrefix(domain, prefix) || strings.HasPrefix(domain, prefix+".")
}

// MatchKeyword checks if a domain contains the given keyword
func (g *GeoSite) MatchKeyword(domain, keyword string) bool {
	return strings.Contains(domain, keyword)
}

// MatchDomain checks exact domain match
func (g *GeoSite) MatchDomain(domain, target string) bool {
	return strings.EqualFold(domain, target)
}

// MatchMultiple checks if a domain matches any of the given categories
func (g *GeoSite) MatchMultiple(domain string, categories []string) bool {
	for _, cat := range categories {
		if g.Match(domain, cat) {
			return true
		}
	}
	return false
}

// GetAllMatches returns all matching categories for a domain
func (g *GeoSite) GetAllMatches(domain string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var matches []string
	for category := range g.categories {
		if g.trie.match(domain, category) {
			matches = append(matches, category)
		}
	}
	return matches
}

// CommonGeoSiteCategories returns common category names
var CommonGeoSiteCategories = []string{
	"google",
	"facebook",
	"twitter",
	"youtube",
	"instagram",
	"netflix",
	"telegram",
	"whatsapp",
	"apple",
	"microsoft",
	"cloudflare",
	"amazon",
	"aws",
	"github",
	"steam",
	"discord",
	"spotify",
	"tiktok",
	"baidu",
	"tencent",
	"alibaba",
	"163",
	"qq",
	"bilibili",
}

// IsCommonCategory checks if a category name is a common category
func IsCommonCategory(name string) bool {
	name = strings.ToLower(name)
	for _, cat := range CommonGeoSiteCategories {
		if cat == name {
			return true
		}
	}
	return false
}
