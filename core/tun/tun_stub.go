//go:build !linux

package tun

import (
	"fmt"
)

// setIFF is a stub for non-Linux platforms
func setIFF(name string, fd int) error {
	return fmt.Errorf("TUN not supported on this platform")
}

// setIFFlags is a stub for non-Linux platforms
func setIFFlags(fd int, flags int) error {
	return fmt.Errorf("TUN not supported on this platform")
}

// getDevName is a stub for non-Linux platforms
func getDevName(fd int) (string, error) {
	return "", fmt.Errorf("TUN not supported on this platform")
}

// setMTU is a stub for non-Linux platforms
func setMTU(fd int, mtu int) error {
	return fmt.Errorf("TUN not supported on this platform")
}

// SetupTUN is a stub for non-Linux platforms
func SetupTUN(fd int, config *Config) error {
	return fmt.Errorf("TUN not supported on this platform without root")
}

// getMTU is a stub for non-Linux platforms
func getMTU(fd int, name string) (int, error) {
	return 0, fmt.Errorf("TUN not supported on this platform")
}

// setTUNMTU is a stub for non-Linux platforms
func setTUNMTU(fd int, name string, mtu int) error {
	return fmt.Errorf("TUN not supported on this platform")
}
