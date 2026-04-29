package constant

import "runtime"

// Build variables (set via ldflags)
// These are the canonical version variables used by mihomo
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// GetGoVersion returns the Go version used for building
func GetGoVersion() string {
	return runtime.Version()
}
