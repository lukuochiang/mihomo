package openwrt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// System represents OpenWrt system
type System struct {
	Name         string
	Version      string
	Architecture string
}

// Init initializes OpenWrt support
func Init() (*System, error) {
	sys := &System{}

	// Detect system
	if err := sys.detect(); err != nil {
		return nil, err
	}

	return sys, nil
}

func (s *System) detect() error {
	// Check /etc/openwrt_release
	data, err := os.ReadFile("/etc/openwrt_release")
	if err == nil {
		s.Name = "OpenWrt"

		// Parse version
		re := regexp.MustCompile(`DISTRIB_RELEASE="([^"]+)"`)
		if matches := re.FindStringSubmatch(string(data)); len(matches) > 1 {
			s.Version = matches[1]
		}

		// Parse architecture
		re = regexp.MustCompile(`DISTRIB_TARGET="([^"]+)"`)
		if matches := re.FindStringSubmatch(string(data)); len(matches) > 1 {
			s.Architecture = matches[1]
		}
	}

	// Fallback detection
	if s.Name == "" {
		// Check LEDE
		data, err := os.ReadFile("/etc/lede_release")
		if err == nil {
			s.Name = "LEDE"
			re := regexp.MustCompile(`DISTRIB_RELEASE="([^"]+)"`)
			if matches := re.FindStringSubmatch(string(data)); len(matches) > 1 {
				s.Version = matches[1]
			}
		}
	}

	// Check OpenClash
	if _, err := os.Stat("/usr/share/openclash"); err == nil {
		s.Name = "OpenClash"
	}

	return nil
}

// Package represents an OpenWrt package
type Package struct {
	Name         string
	Version      string
	Architecture string
	Depends      []string
	Size         int64
}

// Manager provides package management
type Manager struct {
	sys  *System
	lock sync.Mutex
}

// NewManager creates a new package manager
func NewManager(sys *System) *Manager {
	return &Manager{sys: sys}
}

// Install installs a package
func (m *Manager) Install(name string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Check if already installed
	if m.IsInstalled(name) {
		return nil
	}

	// Update opkg
	if err := m.update(); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}

	// Install package
	cmd := exec.Command("opkg", "install", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Remove removes a package
func (m *Manager) Remove(name string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	cmd := exec.Command("opkg", "remove", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// IsInstalled checks if a package is installed
func (m *Manager) IsInstalled(name string) bool {
	cmd := exec.Command("opkg", "list_installed", name)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), name)
}

// List lists all installed packages
func (m *Manager) List() ([]Package, error) {
	cmd := exec.Command("opkg", "list-installed")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var packages []Package
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		parts := strings.SplitN(line, " - ", 3)
		if len(parts) < 3 {
			continue
		}

		packages = append(packages, Package{
			Name:    strings.TrimSpace(parts[0]),
			Version: strings.TrimSpace(parts[1]),
		})
	}

	return packages, nil
}

func (m *Manager) update() error {
	cmd := exec.Command("opkg", "update")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Firewall manages OpenWrt firewall
type Firewall struct {
	zoneName string
}

// NewFirewall creates a new firewall manager
func NewFirewall(zoneName string) *Firewall {
	if zoneName == "" {
		zoneName = "mihomo"
	}
	return &Firewall{zoneName: zoneName}
}

// Config holds firewall configuration
type FirewallConfig struct {
	Interface  string
	Zone       string
	TCPPorts   []int
	UDPPorts   []int
	DNS        bool
	Masquerade bool
}

// Setup configures firewall
func (f *Firewall) Setup(cfg FirewallConfig) error {
	if !f.isRoot() {
		return fmt.Errorf("firewall configuration requires root privileges")
	}

	cmds := []string{
		// Create zone
		"uci -q delete firewall." + f.zoneName,
		"uci set firewall." + f.zoneName + "=zone",
		"uci set firewall." + f.zoneName + ".name='" + f.zoneName + "'",
		"uci set firewall." + f.zoneName + ".network='" + f.zoneName + "'",
		"uci set firewall." + f.zoneName + ".input=ACCEPT",
		"uci set firewall." + f.zoneName + ".output=ACCEPT",
		"uci set firewall." + f.zoneName + ".forward=ACCEPT",
	}

	// Add masquerade if enabled
	if cfg.Masquerade {
		cmds = append(cmds, "uci set firewall."+f.zoneName+".masq=1")
	}

	// Create forwarding
	cmds = append(cmds,
		"uci -q delete firewall.mihomo_lan",
		"uci set firewall.mihomo_lan=forwarding",
		"uci set firewall.mihomo_lan.src=lan",
		"uci set firewall.mihomo_lan.dest="+f.zoneName,
	)

	// Add DNS redirect
	if cfg.DNS {
		cmds = append(cmds,
			"uci -q delete firewall.mihomo_dns",
			"uci set firewall.mihomo_dns=redirect",
			"uci set firewall.mihomo_dns.name='mihomo DNS'",
			"uci set firewall.mihomo_dns.src=lan",
			"uci set firewall.mihomo_dns.dest_port=53",
			"uci set firewall.mihomo_dns.proto=udp",
			"uci add_list firewall.mihomo_dns.dest_ip=127.0.0.1",
		)
	}

	// Apply configuration
	cmds = append(cmds,
		"uci commit firewall",
		"/etc/init.d/firewall reload 2>/dev/null || true",
	)

	for _, cmd := range cmds {
		if err := f.run(cmd); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup removes firewall configuration
func (f *Firewall) Cleanup() error {
	if !f.isRoot() {
		return nil
	}

	cmds := []string{
		"uci -q delete firewall." + f.zoneName,
		"uci -q delete firewall.mihomo_lan",
		"uci -q delete firewall.mihomo_dns",
		"uci commit firewall",
	}

	for _, cmd := range cmds {
		f.run(cmd)
	}

	return nil
}

func (f *Firewall) run(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

func (f *Firewall) isRoot() bool {
	return os.Getuid() == 0
}

// UCI provides UCI configuration management
type UCI struct{}

// NewUCI creates a new UCI manager
func NewUCI() *UCI {
	return &UCI{}
}

// Get gets a UCI value
func (u *UCI) Get(config, section, option string) (string, error) {
	cmd := exec.Command("uci", "-q", "get", config+"."+section+"."+option)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// Set sets a UCI value
func (u *UCI) Set(config, section, option, value string) error {
	return exec.Command("uci", "-q", "set", config+"."+section+"."+option+"="+value).Run()
}

// AddList adds to a UCI list
func (u *UCI) AddList(config, section, option, value string) error {
	return exec.Command("uci", "-q", "add_list", config+"."+section+"."+option+"="+value).Run()
}

// Commit commits UCI changes
func (u *UCI) Commit(config string) error {
	return exec.Command("uci", "commit", config).Run()
}

// Init scripts

// Service represents an init service
type Service struct {
	Name string
	Path string
}

// NewService creates a new init service
func NewService(name string) *Service {
	return &Service{
		Name: name,
		Path: "/etc/init.d/" + name,
	}
}

// Setup installs the init script
func (s *Service) Setup(script string) error {
	if !s.isRoot() {
		return fmt.Errorf("service setup requires root privileges")
	}

	// Write script
	if err := os.WriteFile(s.Path, []byte(script), 0755); err != nil {
		return err
	}

	// Enable service
	return exec.Command(s.Path, "enable").Run()
}

// Remove removes the init script
func (s *Service) Remove() error {
	if !s.isRoot() {
		return nil
	}

	// Stop and disable
	exec.Command(s.Path, "disable").Run()
	exec.Command(s.Path, "stop").Run()

	// Remove script
	return os.Remove(s.Path)
}

func (s *Service) isRoot() bool {
	return os.Getuid() == 0
}

// Network manages network configuration
type Network struct {
	interfaceName string
}

// NewNetwork creates a new network manager
func NewNetwork(iface string) *Network {
	if iface == "" {
		iface = "mihomo"
	}
	return &Network{interfaceName: iface}
}

// Config holds network configuration
type NetworkConfig struct {
	IP      string
	Netmask string
	Bridge  string
}

// Setup sets up network interface
func (n *Network) Setup(cfg NetworkConfig) error {
	if !n.isRoot() {
		return fmt.Errorf("network configuration requires root privileges")
	}

	uci := NewUCI()

	cmds := []string{
		// Delete existing interface
		"uci -q delete network." + n.interfaceName,

		// Create interface
		"uci set network." + n.interfaceName + "=interface",
		"uci set network." + n.interfaceName + ".proto=static",
		"uci set network." + n.interfaceName + ".ifname=tun0",
	}

	if cfg.IP != "" {
		cmds = append(cmds, "uci set network."+n.interfaceName+".ipaddr="+cfg.IP)
	}
	if cfg.Netmask != "" {
		cmds = append(cmds, "uci set network."+n.interfaceName+".netmask="+cfg.Netmask)
	}

	cmds = append(cmds,
		"uci commit network",
		"/etc/init.d/network reload 2>/dev/null || true",
	)

	for _, cmd := range cmds {
		if err := uci.run(cmd); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup removes network interface
func (n *Network) Cleanup() error {
	if !n.isRoot() {
		return nil
	}

	cmds := []string{
		"uci -q delete network." + n.interfaceName,
		"uci commit network",
	}

	for _, cmd := range cmds {
		uci := NewUCI()
		uci.run(cmd)
	}

	return nil
}

func (n *Network) isRoot() bool {
	return os.Getuid() == 0
}

func (u *UCI) run(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

// Dnsmasq integration

// DNSMasq provides DNSmasq configuration
type DNSMasq struct{}

// NewDNSMasq creates a new DNSmasq manager
func NewDNSMasq() *DNSMasq {
	return &DNSMasq{}
}

// Config holds DNSmasq configuration
type DNSMasqConfig struct {
	Server      []string
	IPSet       []string
	DomainList  []string
	NoResolv    bool
	LocalDomain string
}

// Setup configures DNSmasq
func (d *DNSMasq) Setup(cfg DNSMasqConfig) error {
	if !d.isRoot() {
		return fmt.Errorf("DNSmasq configuration requires root privileges")
	}

	_ = NewUCI() // UCI manager - future use

	cmds := []string{
		// Configure DHCP/DNS
		"uci set dhcp.@dnsmasq[0].domainneeded=1",
		"uci set dhcp.@dnsmasq[0].boguspriv=1",
	}

	if cfg.NoResolv {
		cmds = append(cmds, "uci set dhcp.@dnsmasq[0].noresolv=1")
	}

	// Set upstream servers
	for i, server := range cfg.Server {
		cmds = append(cmds, fmt.Sprintf("uci -q del dhcp.@dnsmasq[0].server.%d", i))
		cmds = append(cmds, "uci add_list dhcp.@dnsmasq[0].server="+server)
	}

	// Add local domains
	if cfg.LocalDomain != "" {
		cmds = append(cmds, "uci set dhcp.@dnsmasq[0].local=/"+cfg.LocalDomain+"/")
	}

	cmds = append(cmds, "uci commit dhcp")

	for _, cmd := range cmds {
		if err := d.run(cmd); err != nil {
			return err
		}
	}

	// Restart DNSmasq
	return exec.Command("/etc/init.d/dnsmasq", "restart").Run()
}

func (d *DNSMasq) run(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

func (d *DNSMasq) isRoot() bool {
	return os.Getuid() == 0
}

// Procd integration

// Procd manages procd services
type Procd struct{}

// NewProcd creates a new Procd manager
func NewProcd() *Procd {
	return &Procd{}
}

// Service represents a procd service
type ProcdService struct {
	Name string
}

// Service creates a new procd service
func (p *Procd) Service(name string) *ProcdService {
	return &ProcdService{Name: name}
}

// Instance creates a service instance
func (s *ProcdService) Instance(name string) *ProcdInstance {
	return &ProcdInstance{
		service:  s.Name,
		instance: name,
	}
}

// ProcdInstance represents a procd service instance
type ProcdInstance struct {
	service  string
	instance string
	command  []string
	stdin    string
	respawn  bool
}

// Command sets the command to run
func (i *ProcdInstance) Command(args ...string) *ProcdInstance {
	i.command = args
	return i
}

// Respawn enables respawning
func (i *ProcdInstance) Respawn() *ProcdInstance {
	i.respawn = true
	return i
}

// Start starts the service
func (i *ProcdInstance) Start() error {
	// In real implementation, would communicate with procd via ubus
	return nil
}

// Build builds the service configuration
func (i *ProcdInstance) Build() string {
	var buf bytes.Buffer
	buf.WriteString("service " + i.service + "/" + i.instance + " {\n")

	if len(i.command) > 0 {
		buf.WriteString("  command " + strings.Join(i.command, " ") + "\n")
	}

	if i.respawn {
		buf.WriteString("  respawn\n")
	}

	buf.WriteString("}\n")
	return buf.String()
}

// AutoStart generates init script
func GenerateInitScript(name string, execPath string, configPath string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=95
STOP=15
USE_PROCD=1

PROG=%s
CONFIG=%s

start_service() {
    procd_open_instance
    procd_set_param command $PROG -c $CONFIG
    procd_set_param respawn
    procd_close_instance
}

reload_service() {
    restart
}
`, execPath, configPath)
}

// Systemd compatibility

// Systemd represents systemd integration
type Systemd struct {
	Name string
}

// NewSystemd creates a new systemd manager
func NewSystemd(name string) *Systemd {
	return &Systemd{Name: name}
}

// Setup installs systemd service
func (s *Systemd) Setup(script string) error {
	path := "/etc/systemd/system/" + s.Name + ".service"
	if err := os.WriteFile(path, []byte(script), 0644); err != nil {
		return err
	}

	cmds := []string{
		"systemctl daemon-reload",
		"systemctl enable " + s.Name,
	}

	for _, cmd := range cmds {
		if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
			return err
		}
	}

	return nil
}

// Remove removes systemd service
func (s *Systemd) Remove() error {
	path := "/etc/systemd/system/" + s.Name + ".service"

	cmds := []string{
		"systemctl stop " + s.Name,
		"systemctl disable " + s.Name,
	}

	for _, cmd := range cmds {
		exec.Command("sh", "-c", cmd).Run()
	}

	return os.Remove(path)
}

// GenerateSystemdService generates systemd service file
func GenerateSystemdService(name, execPath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s -c %s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, name, execPath, configPath)
}

// DetectInit detects the init system
func DetectInit() string {
	// Check for systemd
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}

	// Check for OpenWrt procd
	if _, err := os.Stat("/etc/init.d"); err == nil {
		return "procd"
	}

	// Check for SysV init
	if _, err := os.Stat("/etc/rc.d"); err == nil {
		return "sysv"
	}

	return "unknown"
}

// Cross-compile for OpenWrt

// BuildTarget represents a build target
type BuildTarget struct {
	Architecture string
	Subtarget    string
}

// OpenWrtTargets are common OpenWrt targets
var OpenWrtTargets = []BuildTarget{
	{"x86_64", "64"},
	{"x86", "generic"},
	{"aarch64", "cortex-a53"},
	{"arm_arm1176jzf-s_vfp", "generic"},
	{"mipsel", "24kc"},
	{"mips64el", "64"},
	{"i386", "generic"},
}

// GetTargetForArchitecture returns the target for an architecture
func GetTargetForArchitecture(arch string) *BuildTarget {
	for _, target := range OpenWrtTargets {
		if strings.Contains(arch, target.Architecture) {
			return &target
		}
	}
	return nil
}

// BuildScript generates OpenWrt build script
func BuildScript(target, subtarget, outputDir string) string {
	return fmt.Sprintf(`#!/bin/bash
set -e

TARGET=%s
SUBTARGET=%s
OUTPUT=%s

# Clone OpenWrt
git clone https://github.com/openwrt/openwrt.git openwrt-build
cd openwrt-build

# Select target
./scripts/feeds update -a
./scripts/feeds install -a
make defconfig
make menuconfig

# Build
make -j$(nproc)
`, target, subtarget, outputDir)
}

// CreateIPK creates an IPK package
func CreateIPK(name, version, arch string, files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	// Control file
	control := fmt.Sprintf(`Package: %s
Version: %s
Architecture: %s
Description: mihomo smart
`, name, version, arch)

	if err := tw.WriteHeader(&tar.Header{
		Name: "./control",
		Size: int64(len(control)),
		Mode: 0644,
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write([]byte(control)); err != nil {
		return nil, err
	}

	// Add files
	for path, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: path,
			Size: int64(len(content)),
			Mode: 0755,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// isRoot checks if running as root
func isRoot() bool {
	return os.Getuid() == 0
}
