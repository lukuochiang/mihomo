package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// ProcessMatcher matches processes by name or path
type ProcessMatcher struct {
	names map[string]bool
	paths map[string]*regexp.Regexp
	mu    sync.RWMutex
}

// NewProcessMatcher creates a new process matcher
func NewProcessMatcher() *ProcessMatcher {
	return &ProcessMatcher{
		names: make(map[string]bool),
		paths: make(map[string]*regexp.Regexp),
	}
}

// AddName adds a process name to match
func (m *ProcessMatcher) AddName(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.names[strings.ToLower(name)] = true
}

// AddPath adds a process path pattern to match
func (m *ProcessMatcher) AddPath(pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Convert shell glob to regex
	regexPattern := globToRegex(pattern)
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return err
	}
	m.paths[pattern] = re
	return nil
}

// Match checks if process matches
func (m *ProcessMatcher) Match(name, path string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check name
	if name != "" && m.names[strings.ToLower(name)] {
		return true
	}

	// Check path
	if path != "" {
		for _, re := range m.paths {
			if re.MatchString(path) {
				return true
			}
		}
	}

	return false
}

// globToRegex converts shell glob pattern to regex
func globToRegex(pattern string) string {
	pattern = strings.ReplaceAll(pattern, ".", "\\.")
	pattern = strings.ReplaceAll(pattern, "*", ".*")
	pattern = strings.ReplaceAll(pattern, "?", ".")
	return "^" + pattern + "$"
}

// ProcessInfo holds process information
type ProcessInfo struct {
	PID     int
	Name    string
	Path    string
	CWD     string
	Command []string
}

// GetProcessByPID gets process info by PID
func GetProcessByPID(pid int) (*ProcessInfo, error) {
	info := &ProcessInfo{PID: pid}

	switch runtime.GOOS {
	case "linux":
		return getLinuxProcessInfo(info)
	case "darwin":
		return getDarwinProcessInfo(info)
	case "windows":
		return getWindowsProcessInfo(info)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func getLinuxProcessInfo(info *ProcessInfo) (*ProcessInfo, error) {
	// Read /proc/<pid>/comm for process name
	commPath := fmt.Sprintf("/proc/%d/comm", info.PID)
	if data, err := os.ReadFile(commPath); err == nil {
		info.Name = strings.TrimSpace(string(data))
	}

	// Read /proc/<pid>/cmdline for command
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", info.PID)
	if data, err := os.ReadFile(cmdlinePath); err == nil {
		info.Command = strings.Split(strings.TrimSpace(string(data)), "\x00")
		if len(info.Command) > 0 {
			info.Path = info.Command[0]
		}
	}

	// Read /proc/<pid>/exe for executable path
	exePath := fmt.Sprintf("/proc/%d/exe", info.PID)
	if path, err := os.Readlink(exePath); err == nil {
		info.Path = path
	}

	// Read /proc/<pid>/cwd for working directory
	cwdPath := fmt.Sprintf("/proc/%d/cwd", info.PID)
	if cwd, err := os.Readlink(cwdPath); err == nil {
		info.CWD = cwd
	}

	return info, nil
}

func getDarwinProcessInfo(info *ProcessInfo) (*ProcessInfo, error) {
	// On macOS, we need to use sysctl or libproc
	// This is a simplified implementation
	info.Name = fmt.Sprintf("process-%d", info.PID)
	info.Path = ""
	return info, nil
}

func getWindowsProcessInfo(info *ProcessInfo) (*ProcessInfo, error) {
	// On Windows, use Windows API
	info.Name = fmt.Sprintf("process-%d", info.PID)
	info.Path = ""
	return info, nil
}

// FindProcessByName finds process by name
func FindProcessByName(name string) ([]*ProcessInfo, error) {
	var processes []*ProcessInfo

	switch runtime.GOOS {
	case "linux":
		procs, err := filepath.Glob("/proc/*/comm")
		if err != nil {
			return nil, err
		}

		for _, commPath := range procs {
			// Extract PID from path
			dir := filepath.Dir(commPath)
			pidStr := filepath.Base(dir)
			var pid int
			if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil {
				continue
			}

			// Read process name
			if data, err := os.ReadFile(commPath); err == nil {
				procName := strings.TrimSpace(string(data))
				if strings.EqualFold(procName, name) {
					info, _ := GetProcessByPID(pid)
					if info != nil {
						processes = append(processes, info)
					}
				}
			}
		}
	}

	return processes, nil
}

// GetProcessForConnection gets process info for a connection
// This is OS-specific and requires elevated privileges
func GetProcessForConnection(network string, laddr, raddr string) (*ProcessInfo, error) {
	// This is a stub - actual implementation requires OS-specific APIs
	// On Linux: use /proc/net/tcp, /proc/net/udp and inode lookup
	// On macOS: use netstat and lsof
	// On Windows: use netstat and handle lookup

	return nil, fmt.Errorf("GetProcessForConnection not implemented for %s", runtime.GOOS)
}

// ProcessCache caches process information
type ProcessCache struct {
	cache  map[int]*ProcessInfo
	mu     sync.RWMutex
	maxAge int64 // seconds
}

// NewProcessCache creates a new process cache
func NewProcessCache(maxAge int64) *ProcessCache {
	return &ProcessCache{
		cache:  make(map[int]*ProcessInfo),
		maxAge: maxAge,
	}
}

// Get retrieves process info from cache or fetches it
func (c *ProcessCache) Get(pid int) (*ProcessInfo, error) {
	c.mu.RLock()
	info, ok := c.cache[pid]
	if ok {
		c.mu.RUnlock()
		return info, nil
	}
	c.mu.RUnlock()

	// Fetch process info
	info, err := GetProcessByPID(pid)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[pid] = info
	c.mu.Unlock()

	return info, nil
}

// Invalidate removes a PID from cache
func (c *ProcessCache) Invalidate(pid int) {
	c.mu.Lock()
	delete(c.cache, pid)
	c.mu.Unlock()
}

// Clear clears the entire cache
func (c *ProcessCache) Clear() {
	c.mu.Lock()
	c.cache = make(map[int]*ProcessInfo)
	c.mu.Unlock()
}

// ProcessRuleMatcher matches rules based on process information
type ProcessRuleMatcher struct {
	matcher *ProcessMatcher
	rules   map[string]string // process -> outbound
	mu      sync.RWMutex
}

// NewProcessRuleMatcher creates a new process rule matcher
func NewProcessRuleMatcher() *ProcessRuleMatcher {
	return &ProcessRuleMatcher{
		matcher: NewProcessMatcher(),
		rules:   make(map[string]string),
	}
}

// AddRule adds a PROCESS rule
func (m *ProcessRuleMatcher) AddRule(processName, outbound string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.matcher.AddName(processName)
	m.rules[processName] = outbound
}

// AddPathRule adds a PROCESS-PATH rule
func (m *ProcessRuleMatcher) AddPathRule(pattern, outbound string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.matcher.AddPath(pattern); err != nil {
		return err
	}
	m.rules[pattern] = outbound
	return nil
}

// Match matches a process and returns the outbound
func (m *ProcessRuleMatcher) Match(name, path string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.matcher.Match(name, path) {
		return "", false
	}

	// Find matching rule
	for pattern, outbound := range m.rules {
		if strings.EqualFold(pattern, name) {
			return outbound, true
		}
		// Check path patterns
		if m.pathMatches(pattern, path) {
			return outbound, true
		}
	}

	return "", false
}

func (m *ProcessRuleMatcher) pathMatches(pattern, path string) bool {
	rePattern := globToRegex(pattern)
	re, err := regexp.Compile(rePattern)
	if err != nil {
		return false
	}
	return re.MatchString(path)
}
