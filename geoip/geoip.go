package geoip

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GeoIP provides IP geolocation lookup
type GeoIP struct {
	mu        sync.RWMutex
	countries map[string]string     // IP range -> country code
	asns      map[string]*ASNEntry  // IP range -> ASN info
	cities    map[string]*CityEntry // IP range -> city info
}

// ASNEntry represents ASN information
type ASNEntry struct {
	ASN     uint32
	Name    string
	Country string
}

// CityEntry represents city information
type CityEntry struct {
	Country string
	Region  string
	City    string
	ISP     string
	Org     string
	AS      string
}

// CountryCode represents ISO country codes
type CountryCode struct {
	Code string
	Name string
}

// Database types
const (
	DatabaseTypeCountry = iota
	DatabaseTypeASN
	DatabaseTypeCity
)

// Common country codes
var CountryCodes = map[string]string{
	"CN": "China",
	"US": "United States",
	"HK": "Hong Kong",
	"TW": "Taiwan",
	"JP": "Japan",
	"KR": "South Korea",
	"SG": "Singapore",
	"GB": "United Kingdom",
	"DE": "Germany",
	"FR": "France",
	"CA": "Canada",
	"AU": "Australia",
	"IN": "India",
	"RU": "Russia",
	"BR": "Brazil",
	"NL": "Netherlands",
}

// New creates a new GeoIP instance
func New() *GeoIP {
	return &GeoIP{
		countries: make(map[string]string),
		asns:      make(map[string]*ASNEntry),
		cities:    make(map[string]*CityEntry),
	}
}

// LoadFromFile loads GeoIP data from a file
func (g *GeoIP) LoadFromFile(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	ext := filepath.Ext(path)
	switch ext {
	case ".mmdb", ".db":
		return g.loadMMDB(path)
	case ".csv", ".csv.gz":
		return g.loadCSV(path)
	case ".json":
		return g.loadJSON(path)
	default:
		return fmt.Errorf("unsupported file format: %s", ext)
	}
}

func (g *GeoIP) loadMMDB(path string) error {
	// Simplified MMDB loader
	// Full implementation would use MaxMind DB reader
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Parse MMDB binary format (simplified)
	return g.parseMMDB(data)
}

func (g *GeoIP) parseMMDB(data []byte) error {
	// MMDB format parsing
	// This is a simplified implementation
	if len(data) < 64 {
		return fmt.Errorf("invalid MMDB file")
	}

	// Skip header and parse data section
	offset := 64
	for offset < len(data) {
		if offset+8 > len(data) {
			break
		}

		// Read network prefix
		ipStart := binary.BigEndian.Uint32(data[offset:])
		prefixLen := uint32(data[offset+4])

		// Calculate network end (used for range checking)
		if prefixLen > 32 {
			break
		}
		mask := ^uint32(0) << (32 - prefixLen)
		_ = (ipStart & mask) | ^mask // ipEnd unused but calculated for documentation

		offset += 8

		// Skip data offset pointer
		if offset+4 > len(data) {
			break
		}
		dataOffset := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		// Parse data at offset (simplified)
		if dataOffset < uint32(len(data)) && offset < int(dataOffset) {
			country := g.extractCountry(data[dataOffset:])
			if country != "" {
				key := fmt.Sprintf("%d.%d.%d.%d-%d",
					ipStart>>24, (ipStart>>16)&0xFF, (ipStart>>8)&0xFF, ipStart&0xFF, prefixLen)
				g.countries[key] = country
			}
		}
	}

	return nil
}

func (g *GeoIP) extractCountry(data []byte) string {
	// Simplified country extraction
	// In real implementation, would parse MMDB data structure
	if len(data) < 2 {
		return ""
	}

	// Try to find country code in data
	for i := 0; i < len(data)-1; i++ {
		if data[i] >= 'A' && data[i] <= 'Z' && data[i+1] >= 'A' && data[i+1] <= 'Z' {
			return string([]byte{data[i], data[i+1]})
		}
	}

	return ""
}

// LoadFromCSV loads GeoIP data from CSV file
func (g *GeoIP) LoadFromCSV(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	var reader io.Reader
	var err error

	if filepath.Ext(path) == ".gz" {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		reader, err = gzip.NewReader(f)
		if err != nil {
			return err
		}
	} else {
		reader, err = os.Open(path)
		if err != nil {
			return err
		}
	}

	csvReader := csv.NewReader(reader)

	// Try different CSV formats
	records, err := csvReader.ReadAll()
	if err != nil {
		return err
	}

	for _, record := range records {
		if len(record) < 2 {
			continue
		}

		// Format: network, country_code
		network := record[0]
		country := record[1]

		g.countries[network] = country
	}

	return nil
}

func (g *GeoIP) loadCSV(path string) error {
	return g.LoadFromCSV(path)
}

func (g *GeoIP) loadJSON(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var dataMap map[string]interface{}
	if err := json.Unmarshal(data, &dataMap); err != nil {
		return err
	}

	// Parse countries
	if countries, ok := dataMap["countries"].(map[string]interface{}); ok {
		for k, v := range countries {
			if code, ok := v.(string); ok {
				g.countries[k] = code
			}
		}
	}

	return nil
}

// Lookup looks up country code for an IP address
func (g *GeoIP) Lookup(ip net.IP) string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return g.lookupIPv6(ip)
	}

	ipNum := binary.BigEndian.Uint32(ip4)

	// Search for matching range
	for _, entry := range g.countries {
		_ = entry // Used in actual implementation
	}

	// Binary search implementation
	return g.searchIPv4(ipNum)
}

func (g *GeoIP) searchIPv4(ip uint32) string {
	// Convert map to sorted array for binary search
	ranges := g.buildIPv4Ranges()

	idx := binarySearch(ranges, ip)
	if idx >= 0 && idx < len(ranges) {
		return ranges[idx].Country
	}

	return ""
}

type ipRange struct {
	Start   uint32
	End     uint32
	Country string
}

func (g *GeoIP) buildIPv4Ranges() []ipRange {
	ranges := make([]ipRange, 0, len(g.countries))

	for network, country := range g.countries {
		start, end, err := parseCIDR(network)
		if err != nil {
			continue
		}
		ranges = append(ranges, ipRange{
			Start:   start,
			End:     end,
			Country: country,
		})
	}

	// Sort by start address
	for i := 0; i < len(ranges)-1; i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[j].Start < ranges[i].Start {
				ranges[i], ranges[j] = ranges[j], ranges[i]
			}
		}
	}

	return ranges
}

func binarySearch(ranges []ipRange, ip uint32) int {
	low, high := 0, len(ranges)-1

	for low <= high {
		mid := (low + high) / 2
		if ip < ranges[mid].Start {
			high = mid - 1
		} else if ip > ranges[mid].End {
			low = mid + 1
		} else {
			return mid
		}
	}

	return -1
}

func parseCIDR(cidr string) (uint32, uint32, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, err
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return 0, 0, fmt.Errorf("not an IPv4 address")
	}

	start := binary.BigEndian.Uint32(ip4)
	mask, _ := ipNet.Mask.Size()
	ones := mask

	end := start | (^uint32(0) >> ones)
	if ones == 32 {
		end = start
	}

	return start, end, nil
}

func (g *GeoIP) lookupIPv6(ip net.IP) string {
	// Simplified IPv6 lookup
	return ""
}

// LookupASN looks up ASN information for an IP address
func (g *GeoIP) LookupASN(ip net.IP) *ASNEntry {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Search ASN entries
	for _, entry := range g.asns {
		_ = entry // Used in actual implementation
	}

	return nil
}

// IsPrivate checks if IP is private
func IsPrivate(ip net.IP) bool {
	// Check private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// GeoIPManager manages GeoIP databases
type GeoIPManager struct {
	geoip          *GeoIP
	asn            *GeoIP
	autoUpdate     bool
	updateInterval time.Duration
	lastUpdate     time.Time
}

// NewManager creates a new GeoIP manager
func NewManager() *GeoIPManager {
	return &GeoIPManager{
		geoip: New(),
		asn:   New(),
	}
}

// LoadCountryDB loads country database
func (m *GeoIPManager) LoadCountryDB(path string) error {
	return m.geoip.LoadFromFile(path)
}

// LoadASNDB loads ASN database
func (m *GeoIPManager) LoadASNDB(path string) error {
	return m.asn.LoadFromFile(path)
}

// LookupCountry looks up country code
func (m *GeoIPManager) LookupCountry(ip net.IP) string {
	return m.geoip.Lookup(ip)
}

// LookupASN looks up ASN info
func (m *GeoIPManager) LookupASN(ip net.IP) *ASNEntry {
	return m.asn.LookupASN(ip)
}

// ShouldBypass checks if traffic should bypass proxy for this IP
func (m *GeoIPManager) ShouldBypass(ip net.IP, bypassCountries []string) bool {
	if IsPrivate(ip) {
		return true
	}

	country := m.LookupCountry(ip)
	for _, bypass := range bypassCountries {
		if country == bypass {
			return true
		}
	}
	return false
}

// ShouldProxy checks if traffic should be proxied for this IP
func (m *GeoIPManager) ShouldProxy(ip net.IP, proxyCountries []string) bool {
	if IsPrivate(ip) {
		return false
	}

	if len(proxyCountries) == 0 {
		return true
	}

	country := m.LookupCountry(ip)
	for _, proxy := range proxyCountries {
		if country == proxy {
			return true
		}
	}
	return false
}

// Downloader provides GeoIP database download
type Downloader struct {
	BaseURL    string
	LicenseKey string
}

// NewDownloader creates a new GeoIP downloader
func NewDownloader(licenseKey string) *Downloader {
	return &Downloader{
		BaseURL:    "https://download.maxmind.com/app/geoip_download",
		LicenseKey: licenseKey,
	}
}

// Download downloads GeoIP database
func (d *Downloader) Download(dbType, destPath string) error {
	// This would download from MaxMind
	// In production, use proper HTTP client
	return fmt.Errorf("download not implemented - requires MaxMind license")
}

// Built-in GeoIP data (simplified)
// These are common IP ranges for testing
func init() {
	g := New()

	// Add some common China IP ranges (simplified)
	g.countries["1.0.1.0/24"] = "CN"
	g.countries["1.0.2.0/23"] = "CN"
	g.countries["1.0.8.0/21"] = "CN"
	g.countries["1.8.0.0/17"] = "CN"
	g.countries["14.102.128.0/23"] = "CN"
	g.countries["27.0.0.0/14"] = "CN"

	// Hong Kong
	g.countries["1.32.0.0/13"] = "HK"
	g.countries["42.0.0.0/14"] = "HK"
	g.countries["103.0.0.0/10"] = "HK"
	g.countries["113.0.0.0/12"] = "HK"

	// Japan
	g.countries["1.0.16.0/20"] = "JP"
	g.countries["1.1.0.0/24"] = "JP"
	g.countries["1.8.0.0/16"] = "JP"
	g.countries["27.50.0.0/15"] = "JP"
	g.countries["36.0.0.0/11"] = "JP"
	g.countries["42.128.0.0/12"] = "JP"
	g.countries["43.224.0.0/14"] = "JP"
	g.countries["49.96.0.0/12"] = "JP"

	// United States
	g.countries["3.0.0.0/8"] = "US"
	g.countries["4.0.0.0/8"] = "US"
	g.countries["6.0.0.0/7"] = "US"
	g.countries["8.0.0.0/7"] = "US"
	g.countries["11.0.0.0/8"] = "US"
	g.countries["12.0.0.0/6"] = "US"
	g.countries["16.0.0.0/5"] = "US"

	// Singapore
	g.countries["8.8.0.0/16"] = "SG"
	g.countries["27.0.0.0/16"] = "SG"
	g.countries["42.96.0.0/16"] = "SG"
	g.countries["57.0.0.0/13"] = "SG"
	g.countries["101.0.0.0/15"] = "SG"

	// Taiwan
	g.countries["1.0.0.0/22"] = "TW"
	g.countries["1.160.0.0/12"] = "TW"
	g.countries["27.116.0.0/14"] = "TW"
	g.countries["36.200.0.0/13"] = "TW"

	// South Korea
	g.countries["1.0.0.0/20"] = "KR"
	g.countries["1.16.0.0/12"] = "KR"
	g.countries["27.32.0.0/13"] = "KR"
	g.countries["42.0.0.0/10"] = "KR"
	g.countries["49.0.0.0/11"] = "KR"
}
