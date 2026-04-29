package gateway

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Netfilter provides Netfilter/iptables integration
type Netfilter struct {
	mu         sync.RWMutex
	enabled    bool
	interfaces []string
	tproxyPort int
	redirPorts []int
	dnsHijack  bool
	dnsServers []string
}

// NewNetfilter creates a new Netfilter instance
func NewNetfilter() *Netfilter {
	return &Netfilter{
		enabled:    false,
		interfaces: []string{"lo"},
		tproxyPort: 9898,
		redirPorts: []int{7890},
	}
}

// Config holds Netfilter configuration
type Config struct {
	Enabled        bool
	Interface      string
	TProxyPort     int
	RedirectPorts  []int
	DNSHijack      bool
	DNSServers     []string
	ExtraIPv4Rules []string
	ExtraIPv6Rules []string
}

// Setup sets up iptables rules
func (n *Netfilter) Setup(cfg Config) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !cfg.Enabled {
		return n.Cleanup()
	}

	n.enabled = true
	n.interfaces = []string{cfg.Interface}
	n.tproxyPort = cfg.TProxyPort
	n.redirPorts = cfg.RedirectPorts
	n.dnsHijack = cfg.DNSHijack
	n.dnsServers = cfg.DNSServers

	// Check if running as root
	if !n.isRoot() {
		return fmt.Errorf("netfilter setup requires root privileges")
	}

	// Setup iptables
	if err := n.setupIPv4(); err != nil {
		return fmt.Errorf("failed to setup IPv4: %w", err)
	}

	return nil
}

// Cleanup removes all iptables rules
func (n *Netfilter) Cleanup() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.enabled = false

	if !n.isRoot() {
		return nil
	}

	// Remove all rules
	cmds := []string{
		// Flush mihomo chains
		"iptables -t nat -F mihomo 2>/dev/null",
		"iptables -t nat -X mihomo 2>/dev/null",
		"iptables -t nat -F mihomo-dns 2>/dev/null",
		"iptables -t nat -X mihomo-dns 2>/dev/null",
		"iptables -t filter -F mihomo-forward 2>/dev/null",
		"iptables -t filter -X mihomo-forward 2>/dev/null",

		// Remove redirects
		"iptables -t nat -D PREROUTING -j mihomo 2>/dev/null",
		"iptables -t nat -D OUTPUT -j mihomo 2>/dev/null",

		// Remove DNS hijack
		"iptables -t nat -D PREROUTING -j mihomo-dns 2>/dev/null",
		"iptables -t nat -D OUTPUT -j mihomo-dns 2>/dev/null",
	}

	for _, cmd := range cmds {
		exec.Command("sh", "-c", cmd).Run()
	}

	return nil
}

func (n *Netfilter) setupIPv4() error {
	// Create mihomo chain
	cmds := []string{
		// Create chains
		"iptables -t nat -N mihomo",
		"iptables -t nat -N mihomo-dns",
		"iptables -t filter -N mihomo-forward",

		// Bypass private networks
		"iptables -t nat -A mihomo -d 0.0.0.0/8 -j RETURN",
		"iptables -t nat -A mihomo -d 10.0.0.0/8 -j RETURN",
		"iptables -t nat -A mihomo -d 127.0.0.0/8 -j RETURN",
		"iptables -t nat -A mihomo -d 169.254.0.0/16 -j RETURN",
		"iptables -t nat -A mihomo -d 172.16.0.0/12 -j RETURN",
		"iptables -t nat -A mihomo -d 192.168.0.0/16 -j RETURN",
		"iptables -t nat -A mihomo -d 224.0.0.0/4 -j RETURN",
		"iptables -t nat -A mihomo -d 240.0.0.0/4 -j RETURN",

		// Redirect to proxy
		"iptables -t nat -A mihomo -p tcp -j REDIRECT --to-ports " + fmt.Sprintf("%d", n.tproxyPort),

		// DNS hijack
		"iptables -t nat -A mihomo-dns -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:53",

		// Forward chain
		"iptables -t filter -A mihomo-forward -m state --state ESTABLISHED,RELATED -j ACCEPT",
		"iptables -t filter -A mihomo-forward -j RETURN",

		// Insert into PREROUTING
		"iptables -t nat -I PREROUTING 1 -j mihomo",

		// Insert into OUTPUT
		"iptables -t nat -I OUTPUT 1 -j mihomo",
	}

	for _, cmd := range cmds {
		if err := n.run(cmd); err != nil {
			return err
		}
	}

	return nil
}

// run executes a shell command
func (n *Netfilter) run(cmd string) error {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return nil
	}

	execCmd := exec.Command("sh", "-c", cmd)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	return execCmd.Run()
}

// isRoot checks if running as root
func (n *Netfilter) isRoot() bool {
	return os.Getuid() == 0
}

// TProxy provides TPROXY support
type TProxy struct {
	mu      sync.RWMutex
	enabled bool
	port    int
	mark    uint32
}

// NewTProxy creates a new TProxy instance
func NewTProxy() *TProxy {
	return &TProxy{
		enabled: false,
		port:    9898,
		mark:    1,
	}
}

// Config holds TProxy configuration
type TProxyConfig struct {
	Enabled bool
	Port    int
	Mark    uint32
}

// Setup sets up TPROXY rules
func (t *TProxy) Setup(cfg TProxyConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !cfg.Enabled {
		return t.Cleanup()
	}

	t.enabled = true
	t.port = cfg.Port
	t.mark = cfg.Mark

	if !t.isRoot() {
		return fmt.Errorf("TProxy setup requires root privileges")
	}

	return t.setup()
}

func (t *TProxy) setup() error {
	cmds := []string{
		// Create mangle chain
		"ip rule add fwmark " + fmt.Sprintf("%d", t.mark) + " table 100",
		"ip route add local default dev lo table 100",

		// Create mangle chain
		"iptables -t mangle -N mihomo-tproxy",
		"iptables -t mangle -A mihomo-tproxy -d 0.0.0.0/8 -j RETURN",
		"iptables -t mangle -A mihomo-tproxy -d 10.0.0.0/8 -j RETURN",
		"iptables -t mangle -A mihomo-tproxy -d 127.0.0.0/8 -j RETURN",
		"iptables -t mangle -A mihomo-tproxy -d 169.254.0.0/16 -j RETURN",
		"iptables -t mangle -A mihomo-tproxy -d 172.16.0.0/12 -j RETURN",
		"iptables -t mangle -A mihomo-tproxy -d 192.168.0.0/16 -j RETURN",

		// Mark packets
		"iptables -t mangle -A mihomo-tproxy -p tcp -j TPROXY --tproxy-mark " + fmt.Sprintf("%d", t.mark) + " --on-port " + fmt.Sprintf("%d", t.port),
		"iptables -t mangle -A mihomo-tproxy -p udp -j TPROXY --tproxy-mark " + fmt.Sprintf("%d", t.mark) + " --on-port " + fmt.Sprintf("%d", t.port),

		// Insert into PREROUTING
		"iptables -t mangle -A PREROUTING -j mihomo-tproxy",
	}

	for _, cmd := range cmds {
		if err := t.run(cmd); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup removes TPROXY rules
func (t *TProxy) Cleanup() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.enabled = false

	if !t.isRoot() {
		return nil
	}

	cmds := []string{
		"iptables -t mangle -F mihomo-tproxy 2>/dev/null",
		"iptables -t mangle -X mihomo-tproxy 2>/dev/null",
		"iptables -t mangle -D PREROUTING -j mihomo-tproxy 2>/dev/null",
		"ip rule del fwmark " + fmt.Sprintf("%d", t.mark) + " table 100 2>/dev/null",
	}

	for _, cmd := range cmds {
		t.run(cmd)
	}

	return nil
}

func (t *TProxy) run(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

func (t *TProxy) isRoot() bool {
	return os.Getuid() == 0
}

// DNSRedirect provides DNS redirection
type DNSRedirect struct {
	mu         sync.RWMutex
	enabled    bool
	listenIP   string
	listenPort int
	targetIP   string
	targetPort int
}

// NewDNSRedirect creates a new DNS redirector
func NewDNSRedirect() *DNSRedirect {
	return &DNSRedirect{
		enabled:    true,
		listenIP:   "0.0.0.0",
		listenPort: 53,
		targetIP:   "127.0.0.1",
		targetPort: 53,
	}
}

// Config holds DNS redirect configuration
type DNSRedirectConfig struct {
	Enabled    bool
	ListenIP   string
	ListenPort int
	TargetIP   string
	TargetPort int
}

// Setup sets up DNS redirection
func (d *DNSRedirect) Setup(cfg DNSRedirectConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !cfg.Enabled {
		return d.Cleanup()
	}

	d.enabled = true
	d.listenIP = cfg.ListenIP
	d.listenPort = cfg.ListenPort
	d.targetIP = cfg.TargetIP
	d.targetPort = cfg.TargetPort

	if !d.isRoot() {
		return fmt.Errorf("DNS redirect requires root privileges")
	}

	return d.setup()
}

func (d *DNSRedirect) setup() error {
	cmds := []string{
		// Redirect DNS queries to local server
		"iptables -t nat -N mihomo-dns-redirect",
		"iptables -t nat -A mihomo-dns-redirect -p udp --dport 53 -j DNAT --to-destination " + d.targetIP + ":" + fmt.Sprintf("%d", d.targetPort),

		// Apply in PREROUTING
		"iptables -t nat -I PREROUTING 1 -j mihomo-dns-redirect",
	}

	for _, cmd := range cmds {
		if err := d.run(cmd); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup removes DNS redirect rules
func (d *DNSRedirect) Cleanup() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.enabled = false

	if !d.isRoot() {
		return nil
	}

	cmds := []string{
		"iptables -t nat -F mihomo-dns-redirect 2>/dev/null",
		"iptables -t nat -X mihomo-dns-redirect 2>/dev/null",
		"iptables -t nat -D PREROUTING -j mihomo-dns-redirect 2>/dev/null",
	}

	for _, cmd := range cmds {
		d.run(cmd)
	}

	return nil
}

func (d *DNSRedirect) run(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

func (d *DNSRedirect) isRoot() bool {
	return os.Getuid() == 0
}

// IPTablesHelper provides IPTables utilities
type IPTablesHelper struct{}

// NewIPTablesHelper creates a new IPTables helper
func NewIPTablesHelper() *IPTablesHelper {
	return &IPTablesHelper{}
}

// Exists checks if a rule exists
func (h *IPTablesHelper) Exists(table, chain string, rule ...string) (bool, error) {
	cmd := []string{"iptables", "-t", table, "-C", chain}
	cmd = append(cmd, rule...)

	err := exec.Command("sh", "-c", strings.Join(cmd, " ")).Run()
	if err == nil {
		return true, nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() == 1 {
			return false, nil
		}
	}

	return false, err
}

// List lists all rules in a chain
func (h *IPTablesHelper) List(table, chain string) ([]string, error) {
	cmd := exec.Command("iptables", "-t", table, "-L", chain, "-n", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	return lines, nil
}

// GetInterfaceIP gets the IP address of an interface
func GetInterfaceIP(iface string) (net.IP, error) {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	addrs, err := netIface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found for interface %s", iface)
}

// SetupTun sets up TUN device
func SetupTun(iface string, addresses []string, mtu int) error {
	cmds := []string{
		"ip link del " + iface + " 2>/dev/null",
		"ip link add " + iface + " type tun",
		"ip link set " + iface + " mtu " + fmt.Sprintf("%d", mtu),
		"ip link set " + iface + " up",
	}

	for _, addr := range addresses {
		cmds = append(cmds, "ip addr add "+addr+" dev "+iface)
	}

	for _, cmd := range cmds {
		if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
			return err
		}
	}

	return nil
}

// CleanupTun cleans up TUN device
func CleanupTun(iface string) error {
	return exec.Command("sh", "-c", "ip link del "+iface+" 2>/dev/null").Run()
}

// Sysctl sets a sysctl value
func Sysctl(key, value string) error {
	return exec.Command("sh", "-c", "sysctl -w "+key+"="+value).Run()
}

// EnableIPForward enables IP forwarding
func EnableIPForward() error {
	return Sysctl("net.ipv4.ip_forward", "1")
}

// EnableIPV6 enables IPv6
func EnableIPV6() error {
	cmds := []string{
		"sysctl -w net.ipv6.conf.all.forwarding=1",
		"sysctl -w net.ipv6.conf.all.accept_ra=0",
		"sysctl -w net.ipv6.conf.default.forwarding=1",
	}

	for _, cmd := range cmds {
		if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
			return err
		}
	}

	return nil
}

// LoadIPTV6 loads IPTV modules for OpenWrt
func LoadIPTV6() error {
	modules := []string{
		"ip",
		"iptable_nat",
		"iptable_mangle",
		"ip6table_mangle",
		"tun",
	}

	for _, mod := range modules {
		exec.Command("sh", "-c", "modprobe "+mod).Run()
	}

	return nil
}

// CheckRoot checks and exits if not root
func CheckRoot() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("this operation requires root privileges")
	}
	return nil
}

// GetKernelVersion returns the kernel version
func GetKernelVersion() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// IsOpenWrt checks if running on OpenWrt
func IsOpenWrt() bool {
	_, err := os.Stat("/etc/openwrt_release")
	return err == nil
}

// IsLEDE checks if running on LEDE
func IsLEDE() bool {
	_, err := os.Stat("/etc/lede_release")
	return err == nil
}
