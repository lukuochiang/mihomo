package config

import (
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RawConfig represents the raw configuration loaded from YAML (Clash/vernesong compatible)
type RawConfig struct {
	// Clash compatible general fields
	Port                    int    `yaml:"port"`                      // HTTP proxy port
	SocksPort               int    `yaml:"socks-port"`                // SOCKS5 proxy port
	RedirPort               int    `yaml:"redir-port"`                // Redirect proxy port (Linux)
	TProxyPort              int    `yaml:"tproxy-port"`               // TProxy port (Linux)
	MixedPort               int    `yaml:"mixed-port"`                // Mixed HTTP+SOCKS5 port
	AllowLan                bool   `yaml:"allow-lan"`                 // Allow LAN access
	BindAddress             string `yaml:"bind-address"`              // Bind address
	Mode                    string `yaml:"mode"`                      // rule/global/script
	LogLevel                string `yaml:"log-level"`                 // silent/info/warning/error/debug
	IPv6                    bool   `yaml:"ipv6"`                      // Enable IPv6
	UnifiedDelay            bool   `yaml:"unified-delay"`             // Unified delay calculation
	TcpConcurrent           bool   `yaml:"tcp-concurrent"`            // TCP concurrent connections
	FindProcessMode         string `yaml:"find-process-mode"`         // always/match/strict/off
	GlobalClientFingerprint string `yaml:"global-client-fingerprint"` // TLS fingerprint
	GlobalUA                string `yaml:"global-ua"`                 // Global User-Agent
	KeepAliveInterval       int    `yaml:"keep-alive-interval"`       // TCP keepalive interval (seconds)
	KeepAliveIdle           int    `yaml:"keep-alive-idle"`           // TCP keepalive idle time
	DisableKeepAlive        bool   `yaml:"disable-keep-alive"`        // Disable TCP keepalive
	EtagSupport             bool   `yaml:"etag-support"`              // ETag support for HTTP

	// External Controller (Clash/vernesong compatible)
	ExternalController     string                  `yaml:"external-controller"`      // RESTful API address
	ExternalControllerTLS  string                  `yaml:"external-controller-tls"`  // HTTPS API address
	ExternalControllerUnix string                  `yaml:"external-controller-unix"` // Unix Socket path
	ExternalControllerPipe string                  `yaml:"external-controller-pipe"` // Windows Pipe name
	Secret                 string                  `yaml:"secret"`                   // RESTful API secret
	ExternalUICors         RawExternalUICorsConfig `yaml:"external-controller-cors"`

	// External UI
	ExternalUI     string `yaml:"external-ui"`      // External UI path
	ExternalUIName string `yaml:"external-ui-name"` // External UI folder name
	ExternalUIURL  string `yaml:"external-ui-url"`  // External UI download URL

	// Authentication
	Authentication   []RawAuthItem `yaml:"authentication"`     // Proxy authentication
	SkipAuthPrefixes []string      `yaml:"skip-auth-prefixes"` // IPs to skip auth

	// Profile (Clash for Windows style)
	Profile RawProfileConfig `yaml:"profile"`

	// Experimental features
	Experimental RawExperimentalConfig `yaml:"experimental"`

	// Geox URLs
	GeoxURL RawGeoxURLConfig `yaml:"geox-url"`

	// TLS (global)
	TLS RawTLSGlobalConfig `yaml:"tls"`

	// DNS
	DNS RawDNSConfig `yaml:"dns"`

	// Sniffer
	Sniffer RawSnifferConfig `yaml:"sniffer"`

	// TUN
	TUN RawTUNConfig `yaml:"tun"`

	// Hosts
	Hosts map[string]string `yaml:"hosts"`

	// Proxy Providers
	ProxyProviders map[string]RawProxyProvider `yaml:"proxy-providers"`

	// Rule Providers
	RuleProviders map[string]RawRuleProvider `yaml:"rule-providers"`

	// Outbounds (proxies)
	Proxies []RawOutboundConfig `yaml:"proxies"`

	// Proxy Groups
	ProxyGroups []RawGroupConfig `yaml:"proxy-groups"`

	// Rules
	Rules []string `yaml:"rules"`

	// Sub Rules
	SubRules []RawSubRuleConfig `yaml:"sub-rules"`

	// NTP
	NTP RawNTPConfig `yaml:"ntp"`

	// IPTABLES
	IPTABLES RawIPTABLESConfig `yaml:"iptables"`

	// Clash for Android compatibility
	ClashForAndroid RawClashForAndroidConfig `yaml:"clash-for-android"`

	// Listeners (vernesong/mihomo extended)
	Listeners []RawListenerConfig `yaml:"listeners"`
}

// RawListenerConfig represents a listener configuration
type RawListenerConfig struct {
	Name       string               `yaml:"name"`        // Listener name
	Type       string               `yaml:"type"`        // mixed, http, socks, shadowsocks, tunnel
	Listen     string               `yaml:"listen"`      // Listen address
	Port       int                  `yaml:"port"`        // Port
	UDP        bool                 `yaml:"udp"`         // Enable UDP
	Password   string               `yaml:"password"`    // Shadowsocks password
	Cipher     string               `yaml:"cipher"`      // Shadowsocks cipher
	CipherKey  string               `yaml:"cipher-key"`  // Shadowsocks2022 cipher key
	Plugin     string               `yaml:"plugin"`      // Plugin name
	PluginOpts string               `yaml:"plugin-opts"` // Plugin options
	Proxy      string               `yaml:"proxy"`       // Bound proxy group name
	TLS        RawListenerTLSConfig `yaml:"tls"`         // TLS configuration
}

// RawListenerTLSConfig holds TLS configuration for listeners
type RawListenerTLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert"`
	KeyFile    string `yaml:"key"`
	ServerName string `yaml:"server-name"`
	Insecure   bool   `yaml:"insecure"`
}

// RawAuthItem represents proxy authentication (supports both object and string formats)
type RawAuthItem struct {
	User     string `yaml:"username"`
	Password string `yaml:"password"`
	// Support for string format "user:password"
	StringFormat string `yaml:"-"` // Internal use for string format parsing
}

// RawProfileConfig holds profile configuration
type RawProfileConfig struct {
	StoreSelected      bool    `yaml:"store-selected"`       // Store selected proxy
	StoreFakeIP        bool    `yaml:"store-fake-ip"`        // Store fake IP
	SmartCollectorSize float64 `yaml:"smart-collector-size"` // Smart data collection size (MB)
}

// RawExperimentalConfig holds experimental features
type RawExperimentalConfig struct {
	QUICGoDisableGSO bool `yaml:"quic-go-disable-gso"`
}

// RawGeoxURLConfig holds GeoIP/GeoSite download URLs
type RawGeoxURLConfig struct {
	GeoIP   string `yaml:"geoip"`
	GeoSite string `yaml:"geosite"`
	MMDB    string `yaml:"mmdb"`
}

// RawTLSGlobalConfig holds global TLS configuration
type RawTLSGlobalConfig struct {
	Certificate        string   `yaml:"certificate"`
	PrivateKey         string   `yaml:"private-key"`
	ClientAuthType     string   `yaml:"client-auth-type"`
	ClientAuthCert     string   `yaml:"client-auth-cert"`
	ECHKey             string   `yaml:"ech-key"`
	CustomCertificates []string `yaml:"custom-certificates"`
}

// RawExternalUICorsConfig holds CORS configuration
type RawExternalUICorsConfig struct {
	AllowOrigins        []string `yaml:"allow-origins"`
	AllowPrivateNetwork bool     `yaml:"allow-private-network"`
}

// RawProxyProvider represents proxy provider configuration
type RawProxyProvider struct {
	Type        string                 `yaml:"type"` // http, file, compatible
	URL         string                 `yaml:"url"`
	Path        string                 `yaml:"path"`
	Interval    int                    `yaml:"interval"` // Update interval in seconds
	Filter      string                 `yaml:"filter"`   // Node filter regex
	HealthCheck RawProviderHealthCheck `yaml:"health-check"`
	Proxy       string                 `yaml:"proxy"` // Outbound name for fetching
	Override    RawProviderOverride    `yaml:"override"`
}

// RawProviderHealthCheck holds health check configuration
type RawProviderHealthCheck struct {
	Enable   bool   `yaml:"enable"`
	URL      string `yaml:"url"`
	Interval int    `yaml:"interval"`
}

// RawProviderOverride holds node override configuration
type RawProviderOverride struct {
	AdditionalPrefix string `yaml:"additional-prefix"`
	AdditionalSuffix string `yaml:"additional-suffix"`
	RemovePrefix     string `yaml:"remove-prefix"`
	RemoveSuffix     string `yaml:"remove-suffix"`
	InterfaceName    string `yaml:"interface-name"`
	RoutingMark      int    `yaml:"routing-mark"`
}

// RawRuleProvider represents rule provider configuration
type RawRuleProvider struct {
	Type     string `yaml:"type"`     // http, file, compatible
	Behavior string `yaml:"behavior"` // domain, ipcidr, classical
	Format   string `yaml:"format"`   // mrs, yaml, text
	URL      string `yaml:"url"`
	Path     string `yaml:"path"`
	Interval int    `yaml:"interval"` // Update interval in seconds
}

// RawDNSConfig holds DNS configuration (extended for Clash compatibility)
type RawDNSConfig struct {
	Enable                       bool              `yaml:"enable"`
	Listen                       string            `yaml:"listen"`
	IPv6                         bool              `yaml:"ipv6"`
	EnhancedMode                 string            `yaml:"enhanced-mode"` // fake-ip, redir-host, off
	FakeIPRange                  string            `yaml:"fake-ip-range"`
	FakeIPFilter                 []string          `yaml:"fake-ip-filter"`
	FakeIPRange6                 string            `yaml:"fake-ip-range6"`
	FakeIPFilterMode             string            `yaml:"fake-ip-filter-mode"`
	FakeIPTTL                    int               `yaml:"fake-ip-ttl"`
	DefaultNameserver            []string          `yaml:"default-nameserver"`
	Nameserver                   []string          `yaml:"nameserver"`
	Servers                      []string          `yaml:"servers"` // Alias for nameserver
	NameserverPolicy             map[string]string `yaml:"nameserver-policy"`
	ProxyServerNameserver        []string          `yaml:"proxy-server-nameserver"`
	ProxyServerNameserverPolicy  map[string]string `yaml:"proxy-server-nameserver-policy"`
	DirectNameserver             []string          `yaml:"direct-nameserver"`
	DirectNameserverFollowPolicy bool              `yaml:"direct-nameserver-follow-policy"`
	Fallback                     []string          `yaml:"fallback"`
	FallbackFilter               RawFallbackFilter `yaml:"fallback-filter"`
	PreferH3                     bool              `yaml:"prefer-h3"`
	RespectRules                 bool              `yaml:"respect-rules"`
	CacheAlgorithm               string            `yaml:"cache-algorithm"`
	CacheMaxSize                 int               `yaml:"cache-max-size"`
	Strategy                     string            `yaml:"strategy"` // prefer_ipv4, prefer_ipv6, only_ipv4, only_ipv6
}

// RawFallbackFilter holds DNS fallback filter
type RawFallbackFilter struct {
	GeoIP   []string `yaml:"geoip"`
	GeoSite []string `yaml:"geosite"`
	IPCIDR  []string `yaml:"ipcidr"`
	Domain  []string `yaml:"domain"`
}

// RawSnifferConfig holds sniffer configuration
type RawSnifferConfig struct {
	Enable              bool                         `yaml:"enable"`
	OverrideDestination bool                         `yaml:"override-destination"`
	Sniff               map[string]RawSniffingConfig `yaml:"sniff"`
	Sniffing            []string                     `yaml:"sniffing"`
	ForceDomain         []string                     `yaml:"force-domain"`
	SkipSrcAddress      []string                     `yaml:"skip-src-address"`
	SkipDstAddress      []string                     `yaml:"skip-dst-address"`
	SkipDomain          []string                     `yaml:"skip-domain"`
	PortWhitelist       []string                     `yaml:"port-whitelist"`
	ForceDNSMapping     bool                         `yaml:"force-dns-mapping"`
	ParsePureIP         bool                         `yaml:"parse-pure-ip"`
}

// RawSniffingConfig holds sniffing configuration per protocol
type RawSniffingConfig struct {
	Ports               []string `yaml:"ports"`
	OverrideDestination *bool    `yaml:"override-destination"`
}

// RawTUNConfig holds TUN configuration (extended)
type RawTUNConfig struct {
	Enable               bool     `yaml:"enable"`
	Stack                string   `yaml:"stack"` // system/gvisor/mixed
	DNSHijack            []string `yaml:"dns-hijack"`
	AutoRoute            bool     `yaml:"auto-route"`
	AutoRedirect         bool     `yaml:"auto-redirect"`
	AutoDetectInterface  bool     `yaml:"auto-detect-interface"`
	MTU                  int      `yaml:"mtu"`
	InterfaceName        string   `yaml:"interface-name"`
	RoutingMark          int      `yaml:"routing-mark"`
	Inet4Address         []string `yaml:"inet4-address"`
	Inet6Address         []string `yaml:"inet6-address"`
	TableIndex           int      `yaml:"table-index"`
	AutoExcludeInterface bool     `yaml:"auto-exclude-interface"`
	StrictRoute          bool     `yaml:"strict-route"`
	UDPTunnelTimeout     int      `yaml:"udp-timeout"` // seconds
	TCPTimeout           int      `yaml:"tcp-timeout"` // seconds
	UDPTimeout           int      `yaml:"udp-timeout"` // seconds (legacy)
	BufferSize           int      `yaml:"buffer-size"`
	ExtraUDP             bool     `yaml:"extra-udp"`
}

// RawGroupConfig holds proxy group configuration (extended for Smart)
type RawGroupConfig struct {
	Name           string   `yaml:"name"`
	Type           string   `yaml:"type"` // select, selector, url-test, fallback, load-balance, relay, smart
	Proxies        []string `yaml:"proxies"`
	URL            string   `yaml:"url"`
	Interval       int      `yaml:"interval"`
	Timeout        int      `yaml:"timeout"`
	Tolerance      int      `yaml:"tolerance"`
	Strategy       string   `yaml:"strategy"`
	DisableUDP     bool     `yaml:"disable-udp"`
	Filter         string   `yaml:"filter"`            // Node filter regex
	IncludeAll     bool     `yaml:"include-all"`       // Include all matching nodes
	Hidden         bool     `yaml:"hidden"`            // Hide from dashboard
	IconURL        string   `yaml:"icon"`              // Dashboard icon URL
	SourceIP       string   `yaml:"source-ip"`         // Source IP for health check
	UseLBMachineID bool     `yaml:"use-lb-machine-id"` // Use machine ID for load balance

	// Smart specific fields (vernesong/mihomo compatible)
	SmartMode      string  `yaml:"smart-mode"`      // auto, fast, stable, balanced, learning
	TargetRegion   string  `yaml:"target-region"`   // Preferred region (us, jp, hk, etc.)
	UseLightGBM    bool    `yaml:"uselightgbm"`     // Use LightGBM model
	CollectData    bool    `yaml:"collectdata"`     // Collect data for training
	PolicyPriority string  `yaml:"policy-priority"` // Multi-source priority: "Premium:0.9;SG:1.3"
	SampleRate     float64 `yaml:"sample-rate"`     // Data collection rate (0-1)
	PreferASN      bool    `yaml:"prefer-asn"`      // Prefer ASN lookup

	// Relay specific
	RelayChains []string `yaml:"relay-chains"` // For relay type: [[a, b, c]] means a->b->c

	// Interface/Outbound binding
	InterfaceName string `yaml:"interface-name"`
	RoutingMark   int    `yaml:"routing-mark"`
}

// RawOutboundConfig holds outbound node configuration
type RawOutboundConfig struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"`
	Server   string            `yaml:"server"`
	Address  string            `yaml:"address"` // Alias for server
	Port     int               `yaml:"port"`
	UUID     string            `yaml:"uuid"`
	Cipher   string            `yaml:"cipher"`
	Password string            `yaml:"password"`
	TLS      RawTLSConfig      `yaml:"tls"`
	Extra    map[string]string `yaml:"extra"`

	// Network
	Network string `yaml:"network"` // tcp, udp, h2, grpc
	UDP     bool   `yaml:"udp"`     // Enable UDP

	// SSR specific
	Protocol      string `yaml:"protocol"`
	ProtocolParam string `yaml:"protocol-param"`
	OBFS          string `yaml:"obfs"`
	OBFSParam     string `yaml:"obfs-param"`

	// VMess specific
	AlterId  int    `yaml:"alterId"`
	GlobalID string `yaml:"global-id"`

	// Shadowsocks
	SSPlugin   string `yaml:"plugin"`
	PluginOpts string `yaml:"plugin-opts"`
	PluginArgs string `yaml:"plugin-args"`

	// Shadowsocks2022
	PluginProvider string `yaml:"plugin-provider"`

	// SSH
	Username       string `yaml:"username"`
	SSHPrivateKey  string `yaml:"ssh-private-key"`  // SSH private key (base64)
	PrivateKeyPath string `yaml:"private-key-path"` // Path to private key file
	PrivateKeyPass string `yaml:"private-key-pass"` // Private key passphrase
	Pubkey算法       string `yaml:"pubkey-algorithm"`

	// TLS options
	ServerName        string   `yaml:"servername"`
	SkipCertVerify    bool     `yaml:"skip-cert-verify"`
	Fingerprint       string   `yaml:"fingerprint"`
	ALPN              []string `yaml:"alpn"`
	ClientFingerprint string   `yaml:"client-fingerprint"`

	// Hysteria/TUIC
	Auth         string `yaml:"auth"`
	AuthStr      string `yaml:"auth-str"`
	Obfs         string `yaml:"obfs"`
	ProtocolMode string `yaml:"protocol-mode"`

	// WireGuard
	WGPrivateKey     string   `yaml:"wg-private-key"` // WireGuard private key
	PeerPublicKey    string   `yaml:"peer-public-key"`
	PeerPreSharedKey string   `yaml:"peer-pre-shared-key"`
	LocalAddress     []string `yaml:"local-address"`
	Reserved         []int    `yaml:"reserved"`
	MTU              int      `yaml:"mtu"`

	// Interface binding
	InterfaceName string `yaml:"interface-name"`
	RoutingMark   int    `yaml:"routing-mark"`

	// Dialer
	DialerProxy string `yaml:"dialer"`

	// Relay
	Relay string `yaml:"relay"`
}

// RawTLSConfig holds TLS configuration
type RawTLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ServerName string `yaml:"server-name"`
	Insecure   bool   `yaml:"insecure"`
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
	PKCS8      bool   `yaml:"pkcs8"`
}

// RawSubRuleConfig holds sub-rule configuration
type RawSubRuleConfig struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"` // http, file
	URL      string   `yaml:"url"`
	Path     string   `yaml:"path"`
	Interval int      `yaml:"interval"`
	Behavior string   `yaml:"behavior"`
	Format   string   `yaml:"format"`
	Rules    []string `yaml:"rules"`
}

// RawNTPConfig holds NTP configuration
type RawNTPConfig struct {
	Enable   bool   `yaml:"enable"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Timeout  int    `yaml:"timeout"`
	Interval int    `yaml:"interval"`
}

// RawIPTABLESConfig holds IPTABLES configuration
type RawIPTABLESConfig struct {
	RedirectTo bool `yaml:"redirect-to"`
	Auto       bool `yaml:"auto"`
}

// RawClashForAndroidConfig holds Clash for Android compatibility settings
type RawClashForAndroidConfig struct {
	YacdDictionary           string `yaml:"yacd-dictionary"`
	Conflation               bool   `yaml:"conflation"`
	RestrictNetworkInterface bool   `yaml:"restrict-network-interface"`
	TotalClipboardAccess     bool   `yaml:"total-clipboard-access"`
}

// ============================================
// Internal Config Types
// ============================================

// Config represents the normalized internal configuration
type Config struct {
	// Normalized general settings
	BindAddress string
	BindPort    int
	LogLevel    string
	Mode        string // rule/global/script

	// Proxy server ports
	HTTPPort   int
	SOCKSPort  int
	MixedPort  int
	RedirPort  int
	TProxyPort int

	// Network settings
	AllowLan          bool
	UnifiedDelay      bool
	TcpConcurrent     bool
	IPv6              bool
	FindProcessMode   string
	GlobalFingerprint string
	GlobalUA          string
	KeepAliveInterval time.Duration
	KeepAliveIdle     time.Duration
	DisableKeepAlive  bool

	// API & Dashboard
	API       APIConfig
	Dashboard DashboardConfig

	// DNS
	DNS DNSConfig

	// Sniffer
	Sniffer SnifferConfig

	// TUN
	TUN TUNConfig

	// Hosts
	Hosts map[string]string

	// Outbounds (proxies)
	Outbounds []OutboundConfig

	// Proxy Groups
	Groups []GroupConfig

	// Routing
	Routing RoutingConfig

	// Providers
	Providers []ProviderConfig

	// Tunnels
	Tunnels []TunnelConfig

	// Health Check
	HealthCheck HealthCheckConfig

	// Dialer
	Dialer DialerConfig

	// Experimental
	Experimental ExperimentalConfig

	// Profile
	Profile ProfileConfig

	// TLS Global
	TLS TLSGlobalConfig

	// Authentication
	Authentication []AuthItem

	// Listeners (vernesong/mihomo extended)
	Listeners []ListenerConfig
}

// ListenerConfig holds listener configuration
type ListenerConfig struct {
	Name       string
	Type       string // mixed, http, socks, shadowsocks, tunnel
	Listen     string
	Port       int
	UDP        bool
	Password   string
	Cipher     string
	CipherKey  string
	Plugin     string
	PluginOpts string
	Proxy      string // Bound proxy group name
	TLS        ListenerTLSConfig
}

// ListenerTLSConfig holds TLS configuration for listeners
type ListenerTLSConfig struct {
	Enabled    bool
	CertFile   string
	KeyFile    string
	ServerName string
	Insecure   bool
}

// APIConfig holds API server configuration
type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Secret  string `yaml:"secret"`
}

// DashboardConfig holds dashboard configuration
type DashboardConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"` // Dashboard listen address
	Static  string `yaml:"static"` // Static files directory
	URL     string `yaml:"url"`    // UI download URL
	Name    string `yaml:"name"`   // UI folder name
}

// DNSConfig holds DNS configuration
type DNSConfig struct {
	Enable            bool
	Listen            string
	IPv6              bool
	EnhancedMode      string
	FakeIPRange       string
	FakeIPFilter      []string
	DefaultNameserver []string
	Nameserver        []string
	NameserverPolicy  map[string]string
	Fallback          []string
	FallbackFilter    FallbackFilter
	Strategy          string
}

// FallbackFilter holds DNS fallback filter
type FallbackFilter struct {
	GeoIP   []string
	GeoSite []string
	IPCIDR  []string
	Domain  []string
}

// SnifferConfig holds sniffer configuration
type SnifferConfig struct {
	Enable              bool
	OverrideDestination bool
	Sniff               map[string]SniffingConfig
	SkipDomain          []string
}

// SniffingConfig holds sniffing configuration per protocol
type SniffingConfig struct {
	Ports               []string
	OverrideDestination bool
}

// TUNConfig holds TUN configuration
type TUNConfig struct {
	Enable              bool
	Stack               string
	DNSHijack           []string
	AutoRoute           bool
	AutoRedirect        bool
	AutoDetectInterface bool
	MTU                 int
	InterfaceName       string
	RoutingMark         int
}

// OutboundConfig holds outbound node configuration
type OutboundConfig struct {
	Name           string
	Type           string
	Server         string
	Port           int
	UUID           string
	Cipher         string
	Password       string
	TLS            TLSConfig
	Network        string
	UDP            bool
	Protocol       string
	OBFS           string
	OBFSParam      string
	ProtocolParam  string
	Username       string
	ServerName     string
	Fingerprint    string
	PrivateKeyPath string
	PrivateKeyPass string
	InterfaceName  string
	RoutingMark    int
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled    bool
	ServerName string
	Insecure   bool
}

// RoutingConfig holds routing configuration
type RoutingConfig struct {
	DomainStrategy string       `yaml:"domain-strategy"`
	Rules          []RuleConfig `yaml:"rules"`
}

// RuleConfig holds a routing rule
type RuleConfig struct {
	Type        string   `yaml:"type"`
	Value       string   `yaml:"value"`
	Outbound    string   `yaml:"outbound"`
	ExtraParams []string `yaml:"extra"`
}

// ProviderConfig holds provider configuration
type ProviderConfig struct {
	Name        string
	Type        string
	URL         string
	Path        string
	Interval    int
	Filter      string
	HealthCheck ProviderHealthCheck
	Override    ProviderOverride
}

// ProviderHealthCheck holds health check configuration
type ProviderHealthCheck struct {
	Enable   bool
	URL      string
	Interval int
}

// ProviderOverride holds node override configuration
type ProviderOverride struct {
	AdditionalPrefix string
	AdditionalSuffix string
	InterfaceName    string
	RoutingMark      int
}

// TunnelConfig holds tunnel configuration
type TunnelConfig struct {
	Name      string
	Type      string
	MTU       int
	Addresses []string
	DNS       []string
}

// HealthCheckConfig holds global health check configuration
type HealthCheckConfig struct {
	Enable   bool
	URL      string
	Interval int
	Timeout  int
	Lazy     bool
	Suspend  bool
	Fall     int
	Rise     int
}

// DialerConfig holds dialer configuration
type DialerConfig struct {
	Enable bool
	Mark   int
}

// ExperimentalConfig holds experimental features
type ExperimentalConfig struct {
	QUICGoDisableGSO bool
}

// ProfileConfig holds profile configuration
type ProfileConfig struct {
	StoreSelected      bool
	StoreFakeIP        bool
	SmartCollectorSize float64
}

// TLSGlobalConfig holds global TLS configuration
type TLSGlobalConfig struct {
	Certificate    string
	PrivateKey     string
	ClientAuthType string
	ClientAuthCert string
}

// GroupConfig holds proxy group configuration
type GroupConfig struct {
	Name           string
	Type           string
	Proxies        []string
	URL            string
	Interval       int
	Timeout        int
	Tolerance      int
	Strategy       string
	DisableUDP     bool
	Filter         string
	IncludeAll     bool
	Hidden         bool
	IconURL        string
	SmartMode      string
	TargetRegion   string
	UseLightGBM    bool
	CollectData    bool
	PolicyPriority string
	SampleRate     float64
	PreferASN      bool
	InterfaceName  string
	RoutingMark    int
	// Relay specific
	RelayChains [][]string // Supports [[a, b, c]] format for chained proxies
}

// AuthItem represents proxy authentication
type AuthItem struct {
	User     string
	Password string
}

// Load loads configuration from file with Clash/vernesong compatibility
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse YAML to intermediate map for string authentication format
	var rawMap map[string]interface{}
	if err := yaml.Unmarshal(data, &rawMap); err != nil {
		return nil, err
	}

	// Unmarshal as raw config
	var raw RawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	// Handle authentication string format (e.g., "mihomo:yyds666")
	// The YAML parser may put strings directly in authentication array
	if authList, ok := rawMap["authentication"].([]interface{}); ok {
		for _, item := range authList {
			switch v := item.(type) {
			case string:
				// String format: "user:password"
				raw.Authentication = append(raw.Authentication, RawAuthItem{
					StringFormat: v,
				})
			case map[string]interface{}:
				// Object format: {username: x, password: y}
				user := getString(v, "username")
				pass := getString(v, "password")
				raw.Authentication = append(raw.Authentication, RawAuthItem{
					User:     user,
					Password: pass,
				})
			}
		}
	}

	// Handle relay-chains parsing (nested array format)
	if proxyGroups, ok := rawMap["proxy-groups"].([]interface{}); ok {
		for i, item := range proxyGroups {
			if group, ok := item.(map[string]interface{}); ok {
				if chains, ok := group["relay-chains"]; ok {
					parsedChains := parseRelayChains(chains)
					if len(parsedChains) > 0 && i < len(raw.ProxyGroups) {
						// Convert to string format for yaml.Unmarshal
						chainsStr := make([]string, len(parsedChains))
						for j, chain := range parsedChains {
							chainsStr[j] = strings.Join(chain, ",")
						}
						raw.ProxyGroups[i].RelayChains = chainsStr
					}
				}
			}
		}
	}

	// Convert raw config to internal config
	cfg := convertRawToConfig(&raw)

	// Apply defaults
	applyDefaults(cfg)

	return cfg, nil
}

// getString safely extracts string from map
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// convertFakeIPFilter converts fake-ip-filter, handling special formats
// Supports: plain domains, "+.example.com", "rule-set:Name"
func convertFakeIPFilter(rawFilter []string) []string {
	// For now, return as-is
	// In a full implementation, this would expand rule-set references
	return rawFilter
}

// parseRelayChains parses relay-chains from various formats
// Supports: []string{"a,b,c"} or []interface{}{[]interface{}{"a", "b", "c"}}
func parseRelayChains(raw interface{}) [][]string {
	var chains [][]string

	switch v := raw.(type) {
	case []interface{}:
		for _, item := range v {
			switch chain := item.(type) {
			case []interface{}:
				var chainNodes []string
				for _, node := range chain {
					if s, ok := node.(string); ok {
						chainNodes = append(chainNodes, s)
					}
				}
				if len(chainNodes) > 0 {
					chains = append(chains, chainNodes)
				}
			case string:
				// Format: "a,b,c"
				parts := strings.Split(chain, ",")
				var chainNodes []string
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						chainNodes = append(chainNodes, p)
					}
				}
				if len(chainNodes) > 0 {
					chains = append(chains, chainNodes)
				}
			}
		}
	case []string:
		// Simple format: []string{"a,b,c"}
		for _, chain := range v {
			parts := strings.Split(chain, ",")
			var chainNodes []string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					chainNodes = append(chainNodes, p)
				}
			}
			if len(chainNodes) > 0 {
				chains = append(chains, chainNodes)
			}
		}
	}

	return chains
}

// LoadRaw loads raw configuration from file
func LoadRaw(path string) (*RawConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw RawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	// Handle authentication string format
	var rawMap map[string]interface{}
	if err := yaml.Unmarshal(data, &rawMap); err == nil {
		if authList, ok := rawMap["authentication"].([]interface{}); ok {
			for _, item := range authList {
				switch v := item.(type) {
				case string:
					raw.Authentication = append(raw.Authentication, RawAuthItem{
						StringFormat: v,
					})
				case map[string]interface{}:
					user := getString(v, "username")
					pass := getString(v, "password")
					raw.Authentication = append(raw.Authentication, RawAuthItem{
						User:     user,
						Password: pass,
					})
				}
			}
		}
	}

	return &raw, nil
}

// convertRawToConfig converts raw Clash/vernesong config to internal config
func convertRawToConfig(raw *RawConfig) *Config {
	cfg := &Config{
		BindAddress:       raw.BindAddress,
		LogLevel:          raw.LogLevel,
		Mode:              raw.Mode,
		AllowLan:          raw.AllowLan,
		UnifiedDelay:      raw.UnifiedDelay,
		TcpConcurrent:     raw.TcpConcurrent,
		IPv6:              raw.IPv6,
		FindProcessMode:   raw.FindProcessMode,
		GlobalFingerprint: raw.GlobalClientFingerprint,
		GlobalUA:          raw.GlobalUA,
	}

	// Port mapping (Clash compatible -> internal)
	if raw.Port != 0 {
		cfg.HTTPPort = raw.Port
	} else {
		cfg.HTTPPort = 7890
	}
	if raw.SocksPort != 0 {
		cfg.SOCKSPort = raw.SocksPort
	} else {
		cfg.SOCKSPort = 7891
	}
	cfg.MixedPort = raw.MixedPort
	cfg.RedirPort = raw.RedirPort
	cfg.TProxyPort = raw.TProxyPort

	// Bind address
	if raw.BindAddress == "" {
		cfg.BindAddress = "*"
	}

	// Log level
	if raw.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	// Mode
	if raw.Mode == "" {
		cfg.Mode = "rule"
	}

	// Keep alive
	if raw.KeepAliveInterval > 0 {
		cfg.KeepAliveInterval = time.Duration(raw.KeepAliveInterval) * time.Second
	}
	if raw.KeepAliveIdle > 0 {
		cfg.KeepAliveIdle = time.Duration(raw.KeepAliveIdle) * time.Second
	}

	// API config (compatible with both external-controller and api formats)
	if raw.ExternalController != "" || raw.Secret != "" {
		cfg.API = APIConfig{
			Enabled: true,
			Listen:  raw.ExternalController,
			Secret:  raw.Secret,
		}
	}

	// Dashboard config
	if raw.ExternalUI != "" || raw.ExternalUIURL != "" {
		cfg.Dashboard = DashboardConfig{
			Enabled: true,
			Static:  raw.ExternalUI,
			URL:     raw.ExternalUIURL,
			Name:    raw.ExternalUIName,
		}
	}

	// DNS config
	cfg.DNS = DNSConfig{
		Enable:            raw.DNS.Enable,
		Listen:            raw.DNS.Listen,
		IPv6:              raw.DNS.IPv6,
		EnhancedMode:      raw.DNS.EnhancedMode,
		FakeIPRange:       raw.DNS.FakeIPRange,
		FakeIPFilter:      convertFakeIPFilter(raw.DNS.FakeIPFilter),
		DefaultNameserver: raw.DNS.DefaultNameserver,
		Nameserver:        raw.DNS.Nameserver,
		NameserverPolicy:  raw.DNS.NameserverPolicy,
		Strategy:          raw.DNS.Strategy,
	}
	if len(cfg.DNS.Nameserver) == 0 && len(raw.DNS.Servers) > 0 {
		cfg.DNS.Nameserver = raw.DNS.Servers
	}

	// Convert FallbackFilter
	if len(raw.DNS.Fallback) > 0 {
		cfg.DNS.Fallback = raw.DNS.Fallback
	}
	if len(raw.DNS.FallbackFilter.GeoIP) > 0 || len(raw.DNS.FallbackFilter.GeoSite) > 0 ||
		len(raw.DNS.FallbackFilter.IPCIDR) > 0 || len(raw.DNS.FallbackFilter.Domain) > 0 {
		cfg.DNS.FallbackFilter = FallbackFilter{
			GeoIP:   raw.DNS.FallbackFilter.GeoIP,
			GeoSite: raw.DNS.FallbackFilter.GeoSite,
			IPCIDR:  raw.DNS.FallbackFilter.IPCIDR,
			Domain:  raw.DNS.FallbackFilter.Domain,
		}
	}

	// Sniffer config
	cfg.Sniffer = SnifferConfig{
		Enable:              raw.Sniffer.Enable,
		OverrideDestination: raw.Sniffer.OverrideDestination,
		Sniff:               make(map[string]SniffingConfig),
		SkipDomain:          raw.Sniffer.SkipDomain,
	}
	for k, v := range raw.Sniffer.Sniff {
		overrideDest := false
		if v.OverrideDestination != nil {
			overrideDest = *v.OverrideDestination
		}
		cfg.Sniffer.Sniff[k] = SniffingConfig{
			Ports:               v.Ports,
			OverrideDestination: overrideDest,
		}
	}

	// TUN config
	cfg.TUN = TUNConfig{
		Enable:              raw.TUN.Enable,
		Stack:               raw.TUN.Stack,
		DNSHijack:           raw.TUN.DNSHijack,
		AutoRoute:           raw.TUN.AutoRoute,
		AutoRedirect:        raw.TUN.AutoRedirect,
		AutoDetectInterface: raw.TUN.AutoDetectInterface,
		MTU:                 raw.TUN.MTU,
		InterfaceName:       raw.TUN.InterfaceName,
		RoutingMark:         raw.TUN.RoutingMark,
	}

	// Hosts
	cfg.Hosts = raw.Hosts

	// Convert outbounds
	for _, ob := range raw.Proxies {
		server := ob.Server
		if server == "" {
			server = ob.Address
		}
		cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{
			Name:           ob.Name,
			Type:           ob.Type,
			Server:         server,
			Port:           ob.Port,
			UUID:           ob.UUID,
			Cipher:         ob.Cipher,
			Password:       ob.Password,
			Network:        ob.Network,
			UDP:            ob.UDP,
			Protocol:       ob.Protocol,
			OBFS:           ob.OBFS,
			OBFSParam:      ob.OBFSParam,
			ProtocolParam:  ob.ProtocolParam,
			Username:       ob.Username,
			ServerName:     ob.ServerName,
			Fingerprint:    ob.Fingerprint,
			PrivateKeyPath: ob.PrivateKeyPath,
			PrivateKeyPass: ob.PrivateKeyPass,
			InterfaceName:  ob.InterfaceName,
			RoutingMark:    ob.RoutingMark,
		})
	}

	// Convert proxy groups
	for _, g := range raw.ProxyGroups {
		group := GroupConfig{
			Name:           g.Name,
			Type:           normalizeGroupType(g.Type),
			Proxies:        g.Proxies,
			URL:            g.URL,
			Interval:       g.Interval,
			Timeout:        g.Timeout,
			Tolerance:      g.Tolerance,
			Strategy:       g.Strategy,
			DisableUDP:     g.DisableUDP,
			Filter:         g.Filter,
			IncludeAll:     g.IncludeAll,
			Hidden:         g.Hidden,
			IconURL:        g.IconURL,
			SmartMode:      g.SmartMode,
			TargetRegion:   g.TargetRegion,
			UseLightGBM:    g.UseLightGBM,
			CollectData:    g.CollectData,
			PolicyPriority: g.PolicyPriority,
			SampleRate:     g.SampleRate,
			PreferASN:      g.PreferASN,
			InterfaceName:  g.InterfaceName,
			RoutingMark:    g.RoutingMark,
		}

		// Convert RelayChains (from "a,b,c" format to [][]string)
		if len(g.RelayChains) > 0 {
			for _, chain := range g.RelayChains {
				nodes := strings.Split(chain, ",")
				var validNodes []string
				for _, n := range nodes {
					n = strings.TrimSpace(n)
					if n != "" {
						validNodes = append(validNodes, n)
					}
				}
				if len(validNodes) > 0 {
					group.RelayChains = append(group.RelayChains, validNodes)
				}
			}
		}

		cfg.Groups = append(cfg.Groups, group)
	}

	// Convert rules
	for _, rule := range raw.Rules {
		cfg.Routing.Rules = append(cfg.Routing.Rules, parseRule(rule))
	}

	// Convert proxy providers
	for name, p := range raw.ProxyProviders {
		cfg.Providers = append(cfg.Providers, ProviderConfig{
			Name:     name,
			Type:     p.Type,
			URL:      p.URL,
			Path:     p.Path,
			Interval: p.Interval,
			Filter:   p.Filter,
			HealthCheck: ProviderHealthCheck{
				Enable:   p.HealthCheck.Enable,
				URL:      p.HealthCheck.URL,
				Interval: p.HealthCheck.Interval,
			},
			Override: ProviderOverride{
				AdditionalPrefix: p.Override.AdditionalPrefix,
				AdditionalSuffix: p.Override.AdditionalSuffix,
				InterfaceName:    p.Override.InterfaceName,
				RoutingMark:      p.Override.RoutingMark,
			},
		})
	}

	// Authentication (supports both object and string formats)
	for _, auth := range raw.Authentication {
		authItem := AuthItem{}
		if auth.User != "" {
			// Object format: username/password
			authItem.User = auth.User
			authItem.Password = auth.Password
		} else if auth.StringFormat != "" {
			// String format: "user:password"
			parts := splitAuthString(auth.StringFormat)
			if len(parts) == 2 {
				authItem.User = parts[0]
				authItem.Password = parts[1]
			}
		}
		if authItem.User != "" {
			cfg.Authentication = append(cfg.Authentication, authItem)
		}
	}

	// Convert listeners
	for _, l := range raw.Listeners {
		cfg.Listeners = append(cfg.Listeners, ListenerConfig{
			Name:       l.Name,
			Type:       normalizeListenerType(l.Type),
			Listen:     l.Listen,
			Port:       l.Port,
			UDP:        l.UDP,
			Password:   l.Password,
			Cipher:     l.Cipher,
			CipherKey:  l.CipherKey,
			Plugin:     l.Plugin,
			PluginOpts: l.PluginOpts,
			Proxy:      l.Proxy,
			TLS: ListenerTLSConfig{
				Enabled:    l.TLS.Enabled,
				CertFile:   l.TLS.CertFile,
				KeyFile:    l.TLS.KeyFile,
				ServerName: l.TLS.ServerName,
				Insecure:   l.TLS.Insecure,
			},
		})
	}

	// Experimental
	cfg.Experimental = ExperimentalConfig{
		QUICGoDisableGSO: raw.Experimental.QUICGoDisableGSO,
	}

	// Profile
	cfg.Profile = ProfileConfig{
		StoreSelected:      raw.Profile.StoreSelected,
		StoreFakeIP:        raw.Profile.StoreFakeIP,
		SmartCollectorSize: raw.Profile.SmartCollectorSize,
	}

	// Health check defaults
	cfg.HealthCheck = HealthCheckConfig{
		Enable:   true,
		URL:      "https://www.gstatic.com/generate_204",
		Interval: 300,
		Timeout:  5,
		Fall:     3,
		Rise:     2,
	}

	return cfg
}

// normalizeGroupType normalizes group type names
func normalizeGroupType(t string) string {
	switch t {
	case "select", "selector":
		return "selector"
	case "url-test", "urltest":
		return "url-test"
	case "fallback":
		return "fallback"
	case "load-balance", "loadbalance":
		return "load-balance"
	case "smart":
		return "smart"
	case "relay":
		return "relay"
	default:
		return t
	}
}

// normalizeListenerType normalizes listener type names
func normalizeListenerType(t string) string {
	switch t {
	case "http", "HTTP":
		return "http"
	case "socks", "socks5", "SOCKS", "SOCKS5":
		return "socks"
	case "mixed", "MIXED":
		return "mixed"
	case "shadowsocks", "ss", "SS":
		return "shadowsocks"
	case "tunnel", "TUNNEL":
		return "tunnel"
	default:
		return t
	}
}

// splitAuthString splits "user:password" format string
func splitAuthString(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// parseRule parses a rule string into RuleConfig
func parseRule(rule string) RuleConfig {
	parts := splitRule(rule)
	if len(parts) == 0 {
		return RuleConfig{}
	}

	ruleType := parts[0]
	value := ""
	outbound := ""
	extra := []string{}

	switch ruleType {
	case "DOMAIN":
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
	case "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
		if len(parts) >= 4 {
			extra = parts[3:]
		}
	case "GEOIP", "IP-CIDR", "IP-CIDR6", "GEOSITE":
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
		if len(parts) >= 4 {
			extra = parts[3:]
		}
	case "RULE-SET":
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
		if len(parts) >= 4 {
			extra = parts[3:]
		}
	case "PROCESS", "PROCESS-PATH":
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
	case "SRC-IP-CIDR":
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
	case "SRC-PORT", "DST-PORT":
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
	case "PROTOCOL":
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
	case "MATCH", "FINAL":
		outbound = parts[1]
	default:
		if len(parts) >= 2 {
			value = parts[1]
		}
		if len(parts) >= 3 {
			outbound = parts[2]
		}
	}

	return RuleConfig{
		Type:        ruleType,
		Value:       value,
		Outbound:    outbound,
		ExtraParams: extra,
	}
}

// splitRule splits a rule string by comma, respecting quoted strings
func splitRule(rule string) []string {
	var parts []string
	var current []byte
	inQuote := false

	for i := 0; i < len(rule); i++ {
		c := rule[i]
		if c == '\'' || c == '"' {
			inQuote = !inQuote
		} else if c == ',' && !inQuote {
			parts = append(parts, string(current))
			current = nil
		} else {
			current = append(current, c)
		}
	}
	if len(current) > 0 {
		parts = append(parts, string(current))
	}
	return parts
}

func applyDefaults(cfg *Config) {
	if cfg.BindAddress == "" {
		cfg.BindAddress = "*"
	}
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 7890
	}
	if cfg.SOCKSPort == 0 {
		cfg.SOCKSPort = 7891
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.Mode == "" {
		cfg.Mode = "rule"
	}

	// DNS defaults
	if cfg.DNS.Strategy == "" {
		cfg.DNS.Strategy = "prefer_ipv4"
	}

	// Routing defaults
	if cfg.Routing.DomainStrategy == "" {
		cfg.Routing.DomainStrategy = "as-is"
	}

	// Health check defaults
	if cfg.HealthCheck.URL == "" {
		cfg.HealthCheck.URL = "https://www.gstatic.com/generate_204"
	}
	if cfg.HealthCheck.Interval == 0 {
		cfg.HealthCheck.Interval = 300
	}
	if cfg.HealthCheck.Timeout == 0 {
		cfg.HealthCheck.Timeout = 5
	}
	if cfg.HealthCheck.Fall == 0 {
		cfg.HealthCheck.Fall = 3
	}
	if cfg.HealthCheck.Rise == 0 {
		cfg.HealthCheck.Rise = 2
	}

	// Provider defaults
	for i := range cfg.Providers {
		if cfg.Providers[i].Interval == 0 {
			cfg.Providers[i].Interval = 3600 // 1 hour default
		}
	}

	// TUN defaults
	if cfg.TUN.Enable {
		if cfg.TUN.Stack == "" {
			cfg.TUN.Stack = "system"
		}
		if cfg.TUN.MTU == 0 {
			cfg.TUN.MTU = 1500
		}
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate outbounds have at least name and server
	for _, ob := range c.Outbounds {
		if ob.Name == "" {
			return &ConfigError{Field: "proxies[].name", Message: "name is required"}
		}
		if ob.Server == "" && ob.Type != "direct" && ob.Type != "reject" && ob.Type != "block" {
			return &ConfigError{Field: "proxies[" + ob.Name + "].server", Message: "server is required"}
		}
	}

	// Validate groups
	for _, group := range c.Groups {
		if group.Name == "" {
			return &ConfigError{Field: "proxy-groups[].name", Message: "name is required"}
		}
		validTypes := map[string]bool{
			"selector": true, "url-test": true, "fallback": true,
			"load-balance": true, "smart": true, "relay": true,
		}
		if !validTypes[group.Type] {
			return &ConfigError{Field: "proxy-groups[" + group.Name + "].type", Message: "invalid type: " + group.Type}
		}
		// Validate smart-mode if smart type
		if group.Type == "smart" && group.SmartMode != "" {
			validModes := map[string]bool{
				"auto": true, "fast": true, "stable": true,
				"balanced": true, "learning": true,
			}
			if !validModes[group.SmartMode] {
				return &ConfigError{Field: "proxy-groups[" + group.Name + "].smart-mode", Message: "invalid smart-mode: " + group.SmartMode}
			}
		}
	}

	return nil
}

// ConfigError represents a configuration validation error
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Message
}
